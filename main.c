#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <process.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "Header/hashtable.h"
#include "Header/persistence.h"

#ifdef _MSC_VER
#pragma comment(lib, "Ws2_32.lib")
#endif

#define DEFAULT_PORT "6379"
#define DEFAULT_DATA_FILE "kvstore.aof"
#define MAX_LINE 4096
#define RECV_TIMEOUT_MS 30000
#define SWEEP_INTERVAL_MS 1000

#define MAX_ARGS 8            /* Longest command (EXPIRE key seconds) needs 3 */
#define MAX_ARG_LEN 4096
#define READ_BUF_SIZE 8192

/* Guards all access to the shared HashTable and the AOF data file, since
   multiple client threads (plus the background sweep thread) may touch them
   concurrently. */
static CRITICAL_SECTION g_storeLock;

typedef struct
{
    SOCKET client;
    HashTable* store;
    const char* dataFile;
    const char* authPassword;
} ClientContext;

/* A small buffered reader over a socket. RESP parsing needs to read a mix of
   CRLF-terminated lines and fixed-length byte blocks, so we keep a chunk of
   already-received bytes around instead of issuing a recv() per byte. */
typedef struct
{
    SOCKET sock;
    char buf[READ_BUF_SIZE];
    int len;   /* valid bytes currently in buf */
    int pos;   /* next unread byte in buf */
} BufReader;

typedef struct
{
    char argv[MAX_ARGS][MAX_ARG_LEN];
    int argc;
} Command;

static void br_init(BufReader* r, SOCKET sock)
{
    r->sock = sock;
    r->len = 0;
    r->pos = 0;
}

/* Ensures at least one unread byte is available, blocking on recv() if the
   local buffer is empty. Returns 0 on EOF/error/timeout. */
static int br_fill(BufReader* r)
{
    if (r->pos < r->len)
        return 1;
    r->len = recv(r->sock, r->buf, sizeof(r->buf), 0);
    r->pos = 0;
    return r->len > 0;
}

static int br_read_byte(BufReader* r, char* out)
{
    if (!br_fill(r))
        return 0;
    *out = r->buf[r->pos++];
    return 1;
}

/* Reads a CRLF-terminated line into out (without the CRLF). Also tolerates a
   bare '\n', since some simple clients/tools don't send '\r'. */
static int br_read_line(BufReader* r, char* out, size_t outSize)
{
    size_t i = 0;

    while (i + 1 < outSize)
    {
        char c;
        if (!br_read_byte(r, &c))
            return 0;
        if (c == '\n')
        {
            if (i > 0 && out[i - 1] == '\r')
                --i;
            out[i] = '\0';
            return 1;
        }
        out[i++] = c;
    }
    return 0; /* line too long */
}

static int br_read_n(BufReader* r, char* out, size_t n)
{
    size_t got = 0;

    while (got < n)
    {
        size_t avail, take;
        if (!br_fill(r))
            return 0;
        avail = (size_t)(r->len - r->pos);
        take = avail < (n - got) ? avail : (n - got);
        memcpy(out + got, r->buf + r->pos, take);
        r->pos += (int)take;
        got += take;
    }
    return 1;
}

static int send_raw(SOCKET client, const char* data, size_t length)
{
    size_t remaining = length;
    const char* cursor = data;

    while (remaining > 0)
    {
        int sent = send(client, cursor, (int)remaining, 0);
        if (sent == SOCKET_ERROR || sent == 0)
            return 0;
        cursor += sent;
        remaining -= (size_t)sent;
    }
    return 1;
}

/* ---- RESP reply helpers -------------------------------------------------
   See https://redis.io/docs/latest/develop/reference/protocol-spec/ for the
   wire format. We only need simple strings, errors, bulk strings, and
   integers. */

static int resp_send_simple(SOCKET client, const char* text)
{
    char line[MAX_LINE + 8];
    int n = snprintf(line, sizeof(line), "+%s\r\n", text);
    return n > 0 && (size_t)n < sizeof(line) && send_raw(client, line, (size_t)n);
}

static int resp_send_error(SOCKET client, const char* text)
{
    char line[MAX_LINE + 8];
    int n = snprintf(line, sizeof(line), "-%s\r\n", text);
    return n > 0 && (size_t)n < sizeof(line) && send_raw(client, line, (size_t)n);
}

static int resp_send_bulk(SOCKET client, const char* data)
{
    char header[32];
    size_t length = strlen(data);
    int n = snprintf(header, sizeof(header), "$%zu\r\n", length);

    if (n <= 0 || (size_t)n >= sizeof(header))
        return 0;
    return send_raw(client, header, (size_t)n) &&
           send_raw(client, data, length) &&
           send_raw(client, "\r\n", 2);
}

static int resp_send_nil(SOCKET client)
{
    return send_raw(client, "$-1\r\n", 5);
}

static int resp_send_integer(SOCKET client, long long value)
{
    char line[32];
    int n = snprintf(line, sizeof(line), ":%lld\r\n", value);

    if (n <= 0 || (size_t)n >= sizeof(line))
        return 0;
    return send_raw(client, line, (size_t)n);
}

/* ---- RESP / inline command parsing -------------------------------------- */

/* Reads one command from the connection into cmd. Supports:
   - RESP arrays of bulk strings: *2\r\n$3\r\nGET\r\n$3\r\nfoo\r\n
     (this is what redis-cli and every real client library sends)
   - Inline commands: plain text lines like "PING\r\n" or "SET a b\r\n"
     (this is what telnet/nc and real Redis's inline protocol use)
   Returns 0 on disconnect, timeout, protocol error, or too many/long args. */
static int read_command(BufReader* r, Command* cmd)
{
    char line[MAX_LINE];

    if (!br_read_line(r, line, sizeof(line)))
        return 0;

    if (line[0] == '*')
    {
        int count = atoi(line + 1);
        int i;

        if (count <= 0 || count > MAX_ARGS)
            return 0;
        cmd->argc = count;

        for (i = 0; i < count; ++i)
        {
            char lenLine[32];
            int argLen;
            char crlf[2];

            if (!br_read_line(r, lenLine, sizeof(lenLine)) || lenLine[0] != '$')
                return 0;
            argLen = atoi(lenLine + 1);
            if (argLen < 0 || argLen >= MAX_ARG_LEN)
                return 0;
            if (!br_read_n(r, cmd->argv[i], (size_t)argLen))
                return 0;
            cmd->argv[i][argLen] = '\0';
            if (!br_read_n(r, crlf, 2)) /* trailing CRLF after each bulk string */
                return 0;
        }
        return 1;
    }

    /* Inline commands use whitespace to separate the command and key, but
       preserve the remainder of the line as one value. This lets
       "SET greeting hello world" store "hello world". Commands other than
       SET still reject an unexpected third argument in handle_command(). */
    {
        char* cursor = line;
        int i;

        cmd->argc = 0;

        while (*cursor == ' ' || *cursor == '\t')
            ++cursor;
        if (*cursor == '\0')
            return 0;

        /* Command and key are individual whitespace-delimited tokens. */
        for (i = 0; i < 2; ++i)
        {
            char* start = cursor;

            while (*cursor != '\0' && *cursor != ' ' && *cursor != '\t')
                ++cursor;

            strncpy(cmd->argv[cmd->argc], start, (size_t)(cursor - start));
            cmd->argv[cmd->argc][cursor - start] = '\0';
            cmd->argv[cmd->argc][MAX_ARG_LEN - 1] = '\0';
            ++cmd->argc;

            if (*cursor == '\0')
                return 1;

            *cursor++ = '\0';
            while (*cursor == ' ' || *cursor == '\t')
                ++cursor;
            if (*cursor == '\0')
                return 1;
        }

        /* The rest of the inline line is the value, including internal and
           trailing spaces. */
        strncpy(cmd->argv[cmd->argc], cursor, MAX_ARG_LEN - 1);
        cmd->argv[cmd->argc][MAX_ARG_LEN - 1] = '\0';
        ++cmd->argc;
        return 1;
    }
}

static int valid_key(const char* key)
{
    return key != NULL && *key != '\0';
}

/* Uppercases in place so commands are case-insensitive, matching real Redis
   ("get", "Get", and "GET" are all the same command). */
static void uppercase(char* s)
{
    for (; *s != '\0'; ++s)
        *s = (char)toupper((unsigned char)*s);
}

/* Parses a non-negative integer (used for EXPIRE's seconds argument).
   Returns 1 and sets *out on success; returns 0 if text isn't a clean
   non-negative integer. */
static int parse_non_negative(const char* text, long* out)
{
    char* endptr;
    long value = strtol(text, &endptr, 10);

    if (text[0] == '\0' || *endptr != '\0' || value < 0)
        return 0;

    *out = value;
    return 1;
}

static void handle_command(SOCKET client, HashTable* store, const char* dataFile,
                           const char* authPassword, int* authenticated, Command* cmd)
{
    const char* command = cmd->argv[0];
    const char* key = cmd->argc > 1 ? cmd->argv[1] : NULL;
    const char* value = cmd->argc > 2 ? cmd->argv[2] : NULL;

    uppercase(cmd->argv[0]);

    if (strcmp(command, "AUTH") == 0 && cmd->argc == 2)
    {
        if (authPassword == NULL)
            resp_send_error(client, "ERR AUTH called without a password configured");
        else if (strcmp(key, authPassword) != 0)
            resp_send_error(client, "ERR invalid password");
        else
        {
            *authenticated = 1;
            resp_send_simple(client, "OK");
        }
    }
    else if (!*authenticated && !(strcmp(command, "QUIT") == 0 && cmd->argc == 1))
    {
        resp_send_error(client, "NOAUTH Authentication required.");
    }
    else if (strcmp(command, "PING") == 0 && cmd->argc == 1)
    {
        resp_send_simple(client, "PONG");
    }
    else if (strcmp(command, "GET") == 0 && cmd->argc == 2 && valid_key(key))
    {
        char found[MAX_ARG_LEN];
        int found_flag;

        EnterCriticalSection(&g_storeLock);
        {
            char* result = ht_search(store, key);
            found_flag = result != NULL;
            if (found_flag)
            {
                strncpy(found, result, sizeof(found) - 1);
                found[sizeof(found) - 1] = '\0';
            }
        }
        LeaveCriticalSection(&g_storeLock);

        if (found_flag)
            resp_send_bulk(client, found);
        else
            resp_send_nil(client);
    }
    else if (strcmp(command, "SET") == 0 && cmd->argc == 3 && valid_key(key) && *value != '\0')
    {
        const char* okReply = NULL;
        const char* errReply = NULL;

        EnterCriticalSection(&g_storeLock);
        /* Log before mutating, not after: if the AOF write fails, we must not
           have already changed the in-memory value, or a client could be
           told SET failed while GET quietly returns the new value anyway --
           and a crash before the next successful write on this key would
           then lose it permanently. The only remaining gap is if ht_insert
           itself fails after a successful log write (essentially only via
           OOM); that self-heals on the next restart, since replay will
           reconstruct the value from the log entry that's already durable. */
        if (!aof_append(dataFile, "SET", key, value))
            errReply = "ERR could not persist value";
        else if (!ht_insert(store, key, value))
            errReply = "ERR out of memory";
        else
            okReply = "OK";
        LeaveCriticalSection(&g_storeLock);

        if (errReply != NULL)
            resp_send_error(client, errReply);
        else
            resp_send_simple(client, okReply);
    }
    else if (strcmp(command, "DEL") == 0 && cmd->argc == 2 && valid_key(key))
    {
        int deleted = 0;
        const char* errReply = NULL;

        EnterCriticalSection(&g_storeLock);
        if (ht_search(store, key) != NULL)
        {
            if (!aof_append(dataFile, "DEL", key, NULL))
                errReply = "ERR could not persist deletion";
            else
            {
                ht_remove(store, key);
                deleted = 1;
            }
        }
        LeaveCriticalSection(&g_storeLock);

        if (errReply != NULL)
            resp_send_error(client, errReply);
        else
            /* Real Redis replies to DEL with the count of keys removed;
               we only ever delete at most one, so it's 0 or 1. */
            resp_send_integer(client, deleted ? 1 : 0);
    }
    else if (strcmp(command, "EXPIRE") == 0 && cmd->argc == 3 && valid_key(key))
    {
        long seconds;

        if (!parse_non_negative(value, &seconds))
        {
            resp_send_error(client, "ERR value is not an integer or out of range");
        }
        else
        {
            long long expireAtMs = ht_current_time_ms() + (long long)seconds * 1000;
            int exists;
            const char* errReply = NULL;

            EnterCriticalSection(&g_storeLock);
            {
                long long unusedExpiry;
                /* Existence peek only -- doesn't set anything yet. This also
                   still lazily expires the key if it's already past due,
                   which is correct: an expired key has no timeout to set. */
                exists = ht_get_expiry(store, key, &unusedExpiry);
                if (exists)
                {
                    /* Log before mutating: if this fails, leave the key's
                       existing TTL (or lack of one) untouched rather than
                       silently applying a timeout the client was told failed. */
                    if (!aof_log_expire(dataFile, key, expireAtMs))
                        errReply = "ERR could not persist expiry";
                    else
                        /* Still holding the lock since the peek above, so
                           nothing else could have removed the key -- this
                           cannot fail. */
                        ht_set_expiry(store, key, expireAtMs);
                }
            }
            LeaveCriticalSection(&g_storeLock);

            if (errReply != NULL)
                resp_send_error(client, errReply);
            else
                /* Matches real Redis: 1 if the timeout was set, 0 if the key
                   doesn't exist (or had already expired). */
                resp_send_integer(client, exists ? 1 : 0);
        }
    }
    else if (strcmp(command, "TTL") == 0 && cmd->argc == 2 && valid_key(key))
    {
        long long expireAtMs = 0;
        int exists;
        long long remainingSeconds;

        EnterCriticalSection(&g_storeLock);
        exists = ht_get_expiry(store, key, &expireAtMs);
        LeaveCriticalSection(&g_storeLock);

        if (!exists)
            remainingSeconds = -2; /* key doesn't exist (or just expired) */
        else if (expireAtMs == 0)
            remainingSeconds = -1; /* key exists but has no TTL */
        else
        {
            long long remainingMs = expireAtMs - ht_current_time_ms();
            /* Round up so a key with e.g. 400ms left reports 1s, not 0
               (0 would misleadingly suggest it's already gone). */
            remainingSeconds = remainingMs > 0 ? (remainingMs + 999) / 1000 : 0;
        }

        resp_send_integer(client, remainingSeconds);
    }
    else if (strcmp(command, "PERSIST") == 0 && cmd->argc == 2 && valid_key(key))
    {
        int changed = 0;
        const char* errReply = NULL;

        EnterCriticalSection(&g_storeLock);
        {
            long long expireAtMs;
            /* Existence + "does it even have a TTL" peek, without mutating. */
            int exists = ht_get_expiry(store, key, &expireAtMs);

            if (exists && expireAtMs != 0)
            {
                /* Log before mutating, same reasoning as SET/EXPIRE. */
                if (!aof_append(dataFile, "PERSIST", key, NULL))
                    errReply = "ERR could not persist change";
                else
                {
                    ht_persist(store, key); /* cannot fail: still holding the lock */
                    changed = 1;
                }
            }
            /* If the key doesn't exist, or exists but already has no TTL,
               there's nothing to change and nothing to log -- matches real
               Redis's PERSIST, which returns 0 in both of those cases. */
        }
        LeaveCriticalSection(&g_storeLock);

        if (errReply != NULL)
            resp_send_error(client, errReply);
        else
            /* 1 if a TTL was removed, 0 if the key had none (or doesn't exist). */
            resp_send_integer(client, changed ? 1 : 0);
    }
    else if (strcmp(command, "QUIT") == 0 && cmd->argc == 1)
    {
        resp_send_simple(client, "OK");
    }
    else
    {
        resp_send_error(client, "ERR unknown command or wrong number of arguments. "
                                 "Try: AUTH <password>, PING, GET <key>, SET <key> <value>, DEL <key>, "
                                 "EXPIRE <key> <seconds>, TTL <key>, PERSIST <key>, QUIT");
    }
}

static void serve_client(SOCKET client, HashTable* store, const char* dataFile, const char* authPassword)
{
    BufReader reader;
    Command cmd;
    int authenticated = authPassword == NULL;

    br_init(&reader, client);
    for (;;)
    {
        int quitRequested;

        if (!read_command(&reader, &cmd))
            break;

        quitRequested = strcmp(cmd.argv[0], "QUIT") == 0 || strcmp(cmd.argv[0], "quit") == 0;
        handle_command(client, store, dataFile, authPassword, &authenticated, &cmd);
        if (quitRequested)
            break;
    }
}

/* Thread entry point: one of these runs per connected client, so the accept()
   loop in main() never blocks waiting on a slow or idle client. */
static unsigned __stdcall client_thread(void* arg)
{
    ClientContext* ctx = (ClientContext*)arg;
    DWORD timeout = RECV_TIMEOUT_MS;

    /* Prevents one silent/hung client from tying up its thread forever. */
    setsockopt(ctx->client, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));

    serve_client(ctx->client, ctx->store, ctx->dataFile, ctx->authPassword);

    closesocket(ctx->client);
    free(ctx);
    return 0;
}

/* Runs for the lifetime of the process, periodically clearing out keys whose
   TTL has lapsed. Without this, a key that's set with EXPIRE and never
   looked up again (so ht_search's lazy expiry never triggers) would sit in
   memory forever. Sweep-driven removals are deliberately NOT logged to the
   AOF: since EXPIRE always logs an *absolute* timestamp, replaying the log
   after a restart reconstructs the key with that same already-past
   timestamp, so it's cleaned up again almost immediately anyway. */
static unsigned __stdcall expiry_sweep_thread(void* arg)
{
    HashTable* store = (HashTable*)arg;

    for (;;)
    {
        Sleep(SWEEP_INTERVAL_MS);
        EnterCriticalSection(&g_storeLock);
        ht_sweep_expired(store);
        LeaveCriticalSection(&g_storeLock);
    }
    return 0; /* unreachable */
}

int main(int argc, char* argv[])
{
    const char* port = argc > 1 ? argv[1] : DEFAULT_PORT;
    const char* dataFile = argc > 2 ? argv[2] : DEFAULT_DATA_FILE;
    const char* authPassword = argc > 3 && argv[3][0] != '\0' ? argv[3] : NULL;
    WSADATA wsa;
    struct addrinfo hints = { 0 };
    struct addrinfo* address = NULL;
    SOCKET listener = INVALID_SOCKET;
    HashTable* store = ht_create();
    HANDLE sweepThread;

    if (store == NULL || !aof_load(store, dataFile))
    {
        fprintf(stderr, "Could not initialize store.\n");
        ht_destroy(store);
        return 1;
    }

    InitializeCriticalSection(&g_storeLock);

    /* Compact once at startup: the log has just been fully replayed into
       memory, so this is a cheap opportunity to collapse whatever redundant
       or expired history built up before the previous shutdown, keeping the
       next startup's replay fast too. No other thread exists yet, so this
       runs without lock contention -- EnterCriticalSection here is just
       future-proofing in case that ever changes. */
    EnterCriticalSection(&g_storeLock);
    if (!aof_compact(store, dataFile))
        fprintf(stderr, "Warning: startup AOF compaction failed; continuing with existing log.\n");
    LeaveCriticalSection(&g_storeLock);

    sweepThread = (HANDLE)_beginthreadex(NULL, 0, expiry_sweep_thread, store, 0, NULL);
    if (sweepThread == NULL)
    {
        fprintf(stderr, "Could not start expiry sweep thread.\n");
        ht_destroy(store);
        return 1;
    }
    CloseHandle(sweepThread); /* runs forever; nothing needs to join it */

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
    {
        fprintf(stderr, "WSAStartup failed.\n");
        ht_destroy(store);
        return 1;
    }

    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;
    if (getaddrinfo(NULL, port, &hints, &address) != 0 ||
        (listener = socket(address->ai_family, address->ai_socktype, address->ai_protocol)) == INVALID_SOCKET ||
        bind(listener, address->ai_addr, (int)address->ai_addrlen) == SOCKET_ERROR ||
        listen(listener, SOMAXCONN) == SOCKET_ERROR)
    {
        fprintf(stderr, "Could not listen on port %s.\n", port);
        if (address != NULL) freeaddrinfo(address);
        if (listener != INVALID_SOCKET) closesocket(listener);
        WSACleanup();
        ht_destroy(store);
        return 1;
    }
    freeaddrinfo(address);

    printf("kvstore listening on port %s (RESP/TCP); data file: %s; authentication: %s\n",
           port, dataFile, authPassword != NULL ? "enabled" : "disabled");
    for (;;)
    {
        SOCKET client = accept(listener, NULL, NULL);
        ClientContext* ctx;
        HANDLE threadHandle;

        if (client == INVALID_SOCKET)
            continue;

        ctx = malloc(sizeof(ClientContext));
        if (ctx == NULL)
        {
            /* Out of memory: reject this connection but keep serving others. */
            closesocket(client);
            continue;
        }
        ctx->client = client;
        ctx->store = store;
        ctx->dataFile = dataFile;
        ctx->authPassword = authPassword;

        threadHandle = (HANDLE)_beginthreadex(NULL, 0, client_thread, ctx, 0, NULL);
        if (threadHandle == NULL)
        {
            closesocket(client);
            free(ctx);
            continue;
        }
        /* Detach: client_thread cleans up its own socket/context, and main()
           never blocks on it, so we don't need to keep the handle around. */
        CloseHandle(threadHandle);
    }
}
