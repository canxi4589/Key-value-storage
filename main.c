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

#define MAX_ARGS 8
#define MAX_ARG_LEN 4096
#define READ_BUF_SIZE 8192

static CRITICAL_SECTION g_storeLock;

typedef struct
{
    SOCKET client;
    HashTable* store;
    const char* dataFile;
    const char* authPassword;
} ClientContext;

typedef struct
{
    SOCKET sock;
    char buf[READ_BUF_SIZE];
    int len;
    int pos;
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
    return 0;
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
            if (!br_read_n(r, crlf, 2))
                return 0;
        }
        return 1;
    }

    /* Preserve the remaining inline text as a value. */
    {
        char* cursor = line;
        int i;

        cmd->argc = 0;

        while (*cursor == ' ' || *cursor == '\t')
            ++cursor;
        if (*cursor == '\0')
            return 0;

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

static void uppercase(char* s)
{
    for (; *s != '\0'; ++s)
        *s = (char)toupper((unsigned char)*s);
}

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
                exists = ht_get_expiry(store, key, &unusedExpiry);
                if (exists)
                {
                    if (!aof_log_expire(dataFile, key, expireAtMs))
                        errReply = "ERR could not persist expiry";
                    else
                        ht_set_expiry(store, key, expireAtMs);
                }
            }
            LeaveCriticalSection(&g_storeLock);

            if (errReply != NULL)
                resp_send_error(client, errReply);
            else
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
            remainingSeconds = -2;
        else if (expireAtMs == 0)
            remainingSeconds = -1;
        else
        {
            long long remainingMs = expireAtMs - ht_current_time_ms();
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
            int exists = ht_get_expiry(store, key, &expireAtMs);

            if (exists && expireAtMs != 0)
            {
                if (!aof_append(dataFile, "PERSIST", key, NULL))
                    errReply = "ERR could not persist change";
                else
                {
                    ht_persist(store, key);
                    changed = 1;
                }
            }
        }
        LeaveCriticalSection(&g_storeLock);

        if (errReply != NULL)
            resp_send_error(client, errReply);
        else
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

static unsigned __stdcall client_thread(void* arg)
{
    ClientContext* ctx = (ClientContext*)arg;
    DWORD timeout = RECV_TIMEOUT_MS;

    setsockopt(ctx->client, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));

    serve_client(ctx->client, ctx->store, ctx->dataFile, ctx->authPassword);

    closesocket(ctx->client);
    free(ctx);
    return 0;
}

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
    return 0;
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
    CloseHandle(sweepThread);

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
        CloseHandle(threadHandle);
    }
}
