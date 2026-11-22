#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <process.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "Header/hashtable.h"
#include "Header/persistence.h"

#ifdef _MSC_VER
#pragma comment(lib, "Ws2_32.lib")
#endif

#define DEFAULT_BIND "127.0.0.1"
#define DEFAULT_PORT "6379"
#define DEFAULT_DATA_FILE "kvstore.aof"
#define DEFAULT_MAX_CLIENTS 256u
#define DEFAULT_MAX_MEMORY_MB 256u
#define DEFAULT_MAX_AOF_MB 512u
#define DEFAULT_COMPACT_MIN_MB 64u

#define MAX_LINE 4096u
#define MAX_ARGS 8
#define MAX_ARG_LEN 4096u
#define READ_BUF_SIZE 8192u
#define WRITE_BUF_SIZE 8192u

#define RECV_TIMEOUT_MS 30000
#define AUTH_IDLE_TIMEOUT_MS 10000
#define SEND_TIMEOUT_MS 10000
#define POLL_SLICE_MS 250
#define SWEEP_INTERVAL_MS 1000
#define SWEEP_BUCKETS_PER_TICK 1024u

#define MAX_AUTH_FAILURES 5
#define GLOBAL_AUTH_WINDOW_MS 10000
#define GLOBAL_AUTH_MAX_FAILURES 30

static SRWLOCK g_storeLock = SRWLOCK_INIT;
static volatile LONG g_running = 1;
static HANDLE g_stopEvent = NULL;

static CRITICAL_SECTION g_listenerLock;
static SOCKET g_listener = INVALID_SOCKET;

typedef struct
{
    CRITICAL_SECTION lock;
    CONDITION_VARIABLE emptyCv;
    SOCKET* sockets;
    size_t capacity;
    size_t activeCount;
} ClientRegistry;

typedef struct
{
    CRITICAL_SECTION lock;
    long long windowStartMs;
    int failures;
} AuthRateLimiter;

static ClientRegistry g_clients;
static AuthRateLimiter g_authLimiter;

typedef struct
{
    const char* bindAddr;
    const char* port;
    const char* dataFile;
    char* authPassword;
    size_t authPasswordLen;
    AofFsyncMode fsyncMode;
    size_t maxClients;
    size_t maxMemoryBytes;
    size_t maxAofBytes;
} ServerConfig;

typedef struct
{
    SOCKET client;
    size_t slotIdx;
    HashTable* store;
    const ServerConfig* config;
} ClientContext;

typedef struct
{
    HashTable* store;
    const char* dataFile;
} MaintenanceContext;

typedef struct
{
    SOCKET sock;
    char buf[READ_BUF_SIZE];
    int len;
    int pos;
} BufReader;

typedef struct
{
    SOCKET sock;
    char buf[WRITE_BUF_SIZE];
    size_t len;
} BufWriter;

typedef struct
{
    char* argv[MAX_ARGS];
    size_t cap[MAX_ARGS];
    size_t len[MAX_ARGS];
    int argc;
} Command;

typedef struct
{
    BufReader reader;
    BufWriter writer;
    Command cmd;
    char* scratch;
    size_t scratchCap;
} ClientSession;

static int is_running(void)
{
    return InterlockedCompareExchange(&g_running, 0, 0) != 0;
}

static int client_registry_init(ClientRegistry* reg, size_t maxClients)
{
    size_t i;

    reg->sockets = (SOCKET*)malloc(maxClients * sizeof(SOCKET));
    if (reg->sockets == NULL)
        return 0;

    for (i = 0; i < maxClients; i++)
        reg->sockets[i] = INVALID_SOCKET;

    reg->capacity = maxClients;
    reg->activeCount = 0;
    InitializeCriticalSection(&reg->lock);
    InitializeConditionVariable(&reg->emptyCv);
    return 1;
}

static void client_registry_destroy(ClientRegistry* reg)
{
    DeleteCriticalSection(&reg->lock);
    free(reg->sockets);
    reg->sockets = NULL;
    reg->capacity = 0;
    reg->activeCount = 0;
}

static int client_registry_acquire(ClientRegistry* reg, SOCKET sock, size_t* outSlot)
{
    size_t i;
    int acquired = 0;

    EnterCriticalSection(&reg->lock);
    if (is_running() && reg->activeCount < reg->capacity)
    {
        for (i = 0; i < reg->capacity; i++)
        {
            if (reg->sockets[i] == INVALID_SOCKET)
            {
                reg->sockets[i] = sock;
                reg->activeCount++;
                *outSlot = i;
                acquired = 1;
                break;
            }
        }
    }
    LeaveCriticalSection(&reg->lock);
    return acquired;
}

static void client_registry_release(ClientRegistry* reg, size_t slotIdx)
{
    EnterCriticalSection(&reg->lock);
    if (slotIdx < reg->capacity && reg->sockets[slotIdx] != INVALID_SOCKET)
    {
        reg->sockets[slotIdx] = INVALID_SOCKET;
        if (reg->activeCount > 0)
            reg->activeCount--;
        if (reg->activeCount == 0)
            WakeAllConditionVariable(&reg->emptyCv);
    }
    LeaveCriticalSection(&reg->lock);
}

static void client_registry_shutdown_and_wait(ClientRegistry* reg)
{
    size_t i;

    EnterCriticalSection(&reg->lock);
    for (i = 0; i < reg->capacity; i++)
    {
        if (reg->sockets[i] != INVALID_SOCKET)
            shutdown(reg->sockets[i], SD_BOTH);
    }
    while (reg->activeCount > 0)
        SleepConditionVariableCS(&reg->emptyCv, &reg->lock, INFINITE);
    LeaveCriticalSection(&reg->lock);
}

static void auth_limiter_init(AuthRateLimiter* lim)
{
    InitializeCriticalSection(&lim->lock);
    lim->windowStartMs = 0;
    lim->failures = 0;
}

static void auth_limiter_destroy(AuthRateLimiter* lim)
{
    DeleteCriticalSection(&lim->lock);
}

static DWORD auth_limiter_record_failure(AuthRateLimiter* lim, int connFailures)
{
    long long now = ht_current_time_ms();
    DWORD delayMs = (DWORD)(connFailures * 100);
    int globalExcess = 0;

    EnterCriticalSection(&lim->lock);
    if (lim->windowStartMs == 0 || now - lim->windowStartMs >= GLOBAL_AUTH_WINDOW_MS)
    {
        lim->windowStartMs = now;
        lim->failures = 1;
    }
    else
    {
        lim->failures++;
    }
    if (lim->failures > GLOBAL_AUTH_MAX_FAILURES)
        globalExcess = 1;
    LeaveCriticalSection(&lim->lock);

    if (globalExcess && delayMs < 500)
        delayMs = 500;
    return delayMs;
}

static int cmd_reserve_arg(Command* cmd, int idx, size_t neededLen)
{
    size_t required = neededLen + 1;

    if (idx < 0 || idx >= MAX_ARGS)
        return 0;
    if (cmd->cap[idx] >= required)
        return 1;

    {
        size_t newCap = cmd->cap[idx] == 0 ? 64u : cmd->cap[idx] * 2u;
        char* grown;
        if (newCap < required)
            newCap = required;
        if (newCap > MAX_ARG_LEN)
            newCap = MAX_ARG_LEN;
        if (newCap < required)
            return 0;

        grown = (char*)realloc(cmd->argv[idx], newCap);
        if (grown == NULL)
            return 0;
        cmd->argv[idx] = grown;
        cmd->cap[idx] = newCap;
    }
    return 1;
}

static void cmd_destroy(Command* cmd)
{
    int i;
    for (i = 0; i < MAX_ARGS; i++)
    {
        free(cmd->argv[i]);
        cmd->argv[i] = NULL;
        cmd->cap[i] = 0;
        cmd->len[i] = 0;
    }
    cmd->argc = 0;
}

static int session_reserve_scratch(ClientSession* s, size_t needed)
{
    char* grown;

    if (s->scratchCap >= needed)
        return 1;
    grown = (char*)realloc(s->scratch, needed);
    if (grown == NULL)
        return 0;
    s->scratch = grown;
    s->scratchCap = needed;
    return 1;
}

static void br_init(BufReader* r, SOCKET sock)
{
    r->sock = sock;
    r->len = 0;
    r->pos = 0;
}

static int br_has_buffered(const BufReader* r)
{
    return r->pos < r->len;
}

static int br_fill(BufReader* r, long long deadlineMs)
{
    if (r->pos < r->len)
        return 1;

    while (is_running())
    {
        long long now = ht_current_time_ms();
        long long remaining = deadlineMs - now;
        long long sliceMs;
        fd_set rfds;
        struct timeval tv;
        int ready;

        if (remaining <= 0)
            return 0;

        sliceMs = remaining < POLL_SLICE_MS ? remaining : POLL_SLICE_MS;
        FD_ZERO(&rfds);
        FD_SET(r->sock, &rfds);
        tv.tv_sec = (long)(sliceMs / 1000);
        tv.tv_usec = (long)((sliceMs % 1000) * 1000);

        ready = select(0, &rfds, NULL, NULL, &tv);
        if (ready < 0)
            return 0;
        if (ready == 0)
            continue;

        r->len = recv(r->sock, r->buf, (int)sizeof(r->buf), 0);
        r->pos = 0;
        return r->len > 0;
    }

    return 0;
}

static int br_read_line(BufReader* r, char* out, size_t outSize, long long deadlineMs)
{
    size_t i = 0;

    while (i + 1 < outSize)
    {
        size_t avail;
        const char* start;
        const char* nl;
        size_t chunk;

        if (!br_fill(r, deadlineMs))
            return 0;

        avail = (size_t)(r->len - r->pos);
        start = r->buf + r->pos;
        nl = (const char*)memchr(start, '\n', avail);

        if (nl != NULL)
        {
            chunk = (size_t)(nl - start);
            if (i + chunk >= outSize)
                return 0;
            if (chunk > 0)
            {
                if (memchr(start, '\0', chunk) != NULL)
                    return 0;
                memcpy(out + i, start, chunk);
                i += chunk;
            }
            r->pos += (int)(chunk + 1);
            if (i > 0 && out[i - 1] == '\r')
                --i;
            out[i] = '\0';
            return 1;
        }

        if (i + avail >= outSize)
            return 0;
        if (memchr(start, '\0', avail) != NULL)
            return 0;

        memcpy(out + i, start, avail);
        i += avail;
        r->pos = r->len;
    }

    return 0;
}

static int br_read_n(BufReader* r, char* out, size_t n, long long deadlineMs)
{
    size_t got = 0;

    while (got < n)
    {
        size_t avail, take;

        if (!br_fill(r, deadlineMs))
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
        int toSend = remaining > (size_t)INT_MAX ? INT_MAX : (int)remaining;
        int sent = send(client, cursor, toSend, 0);
        if (sent == SOCKET_ERROR || sent <= 0)
            return 0;
        cursor += sent;
        remaining -= (size_t)sent;
    }

    return 1;
}

static void bw_init(BufWriter* w, SOCKET sock)
{
    w->sock = sock;
    w->len = 0;
}

static int bw_flush(BufWriter* w)
{
    if (w->len == 0)
        return 1;
    if (!send_raw(w->sock, w->buf, w->len))
    {
        w->len = 0;
        return 0;
    }
    w->len = 0;
    return 1;
}

static int bw_write(BufWriter* w, const char* data, size_t len)
{
    if (len == 0)
        return 1;
    if (w->len + len <= sizeof(w->buf))
    {
        memcpy(w->buf + w->len, data, len);
        w->len += len;
        return 1;
    }
    if (!bw_flush(w))
        return 0;
    if (len < sizeof(w->buf))
    {
        memcpy(w->buf, data, len);
        w->len = len;
        return 1;
    }
    return send_raw(w->sock, data, len);
}

static int resp_send_simple(BufWriter* w, const char* text)
{
    size_t len = strlen(text);
    return bw_write(w, "+", 1) && bw_write(w, text, len) && bw_write(w, "\r\n", 2);
}

static int resp_send_error(BufWriter* w, const char* text)
{
    size_t len = strlen(text);
    return bw_write(w, "-", 1) && bw_write(w, text, len) && bw_write(w, "\r\n", 2);
}

static int resp_send_bulk(BufWriter* w, const char* data, size_t length)
{
    char header[32];
    int n = snprintf(header, sizeof(header), "$%zu\r\n", length);

    if (n <= 0 || (size_t)n >= sizeof(header))
        return 0;
    return bw_write(w, header, (size_t)n) &&
           bw_write(w, data, length) &&
           bw_write(w, "\r\n", 2);
}

static int resp_send_nil(BufWriter* w)
{
    return bw_write(w, "$-1\r\n", 5);
}

static int resp_send_integer(BufWriter* w, long long value)
{
    char line[32];
    int n = snprintf(line, sizeof(line), ":%lld\r\n", value);

    if (n <= 0 || (size_t)n >= sizeof(line))
        return 0;
    return bw_write(w, line, (size_t)n);
}

static int resp_send_empty_array(BufWriter* w)
{
    return bw_write(w, "*0\r\n", 4);
}

static int parse_integer(const char* text, long long* out)
{
    char* endptr = NULL;
    long long value;

    if (text == NULL || text[0] == '\0')
        return 0;
    if (text[0] == ' ' || text[0] == '\t' || text[0] == '+')
        return 0;
    if (text[0] == '-' && !isdigit((unsigned char)text[1]))
        return 0;
    if (text[0] != '-' && !isdigit((unsigned char)text[0]))
        return 0;

    errno = 0;
    value = strtoll(text, &endptr, 10);
    if (errno == ERANGE || endptr == text || *endptr != '\0')
        return 0;

    *out = value;
    return 1;
}

static int parse_non_negative(const char* text, long long* out)
{
    long long value;
    if (!parse_integer(text, &value) || value < 0)
        return 0;
    *out = value;
    return 1;
}

static int compute_expire_at_ms(long long nowMs, long long seconds, long long* outExpireAtMs)
{
    if (seconds < 0)
        return 0;
    if (seconds > (LLONG_MAX - nowMs) / 1000)
        return 0;
    *outExpireAtMs = nowMs + seconds * 1000;
    return 1;
}

static int consttime_equal(const char* a, size_t aLen, const char* b, size_t bLen)
{
    size_t maxLen = aLen > bLen ? aLen : bLen;
    volatile unsigned char diff = (aLen != bLen) ? 1u : 0u;
    size_t i;

    for (i = 0; i < maxLen; i++)
    {
        unsigned char ca = i < aLen ? (unsigned char)a[i] : 0u;
        unsigned char cb = i < bLen ? (unsigned char)b[i] : 0u;
        diff |= (unsigned char)(ca ^ cb);
    }

    return diff == 0u;
}

static int str_ieq(const char* a, const char* b)
{
    while (*a != '\0' && *b != '\0')
    {
        if (toupper((unsigned char)*a) != toupper((unsigned char)*b))
            return 0;
        a++;
        b++;
    }
    return *a == *b;
}

static int read_command(BufReader* r, Command* cmd, int authenticated)
{
    char line[MAX_LINE];
    long long deadlineMs = ht_current_time_ms() +
                           (authenticated ? RECV_TIMEOUT_MS : AUTH_IDLE_TIMEOUT_MS);

    cmd->argc = 0;
    if (!br_read_line(r, line, sizeof(line), deadlineMs))
        return 0;

    if (line[0] == '*')
    {
        long long countVal;
        int count;
        int i;

        if (!parse_integer(line + 1, &countVal) || countVal <= 0 || countVal > MAX_ARGS)
            return 0;
        count = (int)countVal;

        for (i = 0; i < count; ++i)
        {
            char lenLine[32];
            long long argLenVal;
            size_t argLen;
            char crlf[2];

            if (!br_read_line(r, lenLine, sizeof(lenLine), deadlineMs) || lenLine[0] != '$')
                return 0;
            if (!parse_non_negative(lenLine + 1, &argLenVal) ||
                (unsigned long long)argLenVal >= MAX_ARG_LEN)
                return 0;

            argLen = (size_t)argLenVal;
            if (!cmd_reserve_arg(cmd, i, argLen))
                return 0;
            if (argLen > 0 && !br_read_n(r, cmd->argv[i], argLen, deadlineMs))
                return 0;
            cmd->argv[i][argLen] = '\0';
            cmd->len[i] = argLen;

            /* Reject embedded NUL bytes to prevent silent C-string truncation. */
            if (argLen > 0 && memchr(cmd->argv[i], '\0', argLen) != NULL)
                return 0;

            /* Strictly require RESP CRLF terminator. */
            if (!br_read_n(r, crlf, 2, deadlineMs) || crlf[0] != '\r' || crlf[1] != '\n')
                return 0;
        }

        cmd->argc = count;
        return 1;
    }

    /* Inline command fallback: preserve trailing spaces in value. */
    {
        char* cursor = line;
        int splitLimit = 2;
        int i;

        while (*cursor == ' ' || *cursor == '\t')
            ++cursor;
        if (*cursor == '\0')
            return 0;

        for (i = 0; i < splitLimit; ++i)
        {
            char* start = cursor;
            size_t tokenLen;

            while (*cursor != '\0' && *cursor != ' ' && *cursor != '\t')
                ++cursor;

            tokenLen = (size_t)(cursor - start);
            if (tokenLen >= MAX_ARG_LEN)
                return 0;
            if (!cmd_reserve_arg(cmd, cmd->argc, tokenLen))
                return 0;

            memcpy(cmd->argv[cmd->argc], start, tokenLen);
            cmd->argv[cmd->argc][tokenLen] = '\0';
            cmd->len[cmd->argc] = tokenLen;
            ++cmd->argc;

            if (i == 0 && str_ieq(cmd->argv[0], "SETEX"))
                splitLimit = 3;

            if (*cursor == '\0')
                return 1;

            *cursor++ = '\0';
            while (*cursor == ' ' || *cursor == '\t')
                ++cursor;
            if (*cursor == '\0')
                return 1;
        }

        {
            size_t valLen = strlen(cursor);
            if (valLen >= MAX_ARG_LEN)
                return 0;
            if (!cmd_reserve_arg(cmd, cmd->argc, valLen))
                return 0;

            memcpy(cmd->argv[cmd->argc], cursor, valLen);
            cmd->argv[cmd->argc][valLen] = '\0';
            cmd->len[cmd->argc] = valLen;
            ++cmd->argc;
            return 1;
        }
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

/* Returns 1 if the connection should be closed after flushing the reply. */
static int handle_command(ClientSession* session, HashTable* store, const ServerConfig* config,
                          int* authenticated, int* authFailures)
{
    BufWriter* w = &session->writer;
    Command* cmd = &session->cmd;
    const char* dataFile = config->dataFile;
    const char* command = cmd->argv[0];
    const char* key = cmd->argc > 1 ? cmd->argv[1] : NULL;
    const char* value = cmd->argc > 2 ? cmd->argv[2] : NULL;

    uppercase(cmd->argv[0]);

    if (strcmp(command, "AUTH") == 0 && cmd->argc == 2)
    {
        if (config->authPassword == NULL)
        {
            resp_send_error(w, "ERR AUTH called without a password configured");
        }
        else if (!consttime_equal(key, cmd->len[1], config->authPassword, config->authPasswordLen))
        {
            DWORD delayMs;
            (*authFailures)++;
            delayMs = auth_limiter_record_failure(&g_authLimiter, *authFailures);

            if (*authFailures >= MAX_AUTH_FAILURES)
            {
                resp_send_error(w, "ERR too many failed authentication attempts");
                return 1;
            }

            if (g_stopEvent != NULL)
                WaitForSingleObject(g_stopEvent, delayMs);
            else
                Sleep(delayMs);

            resp_send_error(w, "ERR invalid password");
        }
        else
        {
            *authenticated = 1;
            *authFailures = 0;
            resp_send_simple(w, "OK");
        }
        return 0;
    }

    if (!*authenticated && !(strcmp(command, "QUIT") == 0 && cmd->argc == 1))
    {
        resp_send_error(w, "NOAUTH Authentication required.");
        return 0;
    }

    if (strcmp(command, "QUIT") == 0 && cmd->argc == 1)
    {
        resp_send_simple(w, "OK");
        return 1;
    }
    else if (strcmp(command, "PING") == 0 && cmd->argc == 1)
    {
        resp_send_simple(w, "PONG");
    }
    else if (strcmp(command, "COMMAND") == 0)
    {
        resp_send_empty_array(w);
    }
    else if (strcmp(command, "CLIENT") == 0)
    {
        resp_send_simple(w, "OK");
    }
    else if (strcmp(command, "EXISTS") == 0 && cmd->argc == 2 && valid_key(key))
    {
        int exists;
        int expired = 0;

        AcquireSRWLockShared(&g_storeLock);
        exists = ht_exists_ro(store, key, &expired);
        ReleaseSRWLockShared(&g_storeLock);

        if (expired)
        {
            AcquireSRWLockExclusive(&g_storeLock);
            ht_purge_if_expired(store, key);
            ReleaseSRWLockExclusive(&g_storeLock);
        }

        resp_send_integer(w, exists ? 1 : 0);
    }
    else if (strcmp(command, "DBSIZE") == 0 && cmd->argc == 1)
    {
        size_t count;

        AcquireSRWLockShared(&g_storeLock);
        count = ht_count(store);
        ReleaseSRWLockShared(&g_storeLock);

        resp_send_integer(w, (long long)count);
    }
    else if ((strcmp(command, "FLUSHDB") == 0 || strcmp(command, "FLUSHALL") == 0) && cmd->argc == 1)
    {
        const char* errReply = NULL;

        AcquireSRWLockExclusive(&g_storeLock);
        if (!aof_truncate(dataFile))
            errReply = "ERR could not reset persistence log";
        else
            ht_clear(store);
        ReleaseSRWLockExclusive(&g_storeLock);

        if (errReply != NULL)
            resp_send_error(w, errReply);
        else
            resp_send_simple(w, "OK");
    }
    else if (strcmp(command, "GET") == 0 && cmd->argc == 2 && valid_key(key))
    {
        int foundFlag = 0;
        int expired = 0;
        int oomFlag = 0;
        size_t valLen = 0;

        AcquireSRWLockShared(&g_storeLock);
        {
            const char* result = ht_search_ro(store, key, &expired);
            if (result != NULL)
            {
                valLen = strlen(result);
                if (session_reserve_scratch(session, valLen + 1))
                {
                    memcpy(session->scratch, result, valLen + 1);
                    foundFlag = 1;
                }
                else
                {
                    oomFlag = 1;
                }
            }
        }
        ReleaseSRWLockShared(&g_storeLock);

        if (expired)
        {
            AcquireSRWLockExclusive(&g_storeLock);
            ht_purge_if_expired(store, key);
            ReleaseSRWLockExclusive(&g_storeLock);
        }

        if (oomFlag)
            resp_send_error(w, "ERR out of memory");
        else if (foundFlag)
            resp_send_bulk(w, session->scratch, valLen);
        else
            resp_send_nil(w);
    }
    else if (strcmp(command, "SETEX") == 0 && cmd->argc == 4 && valid_key(key))
    {
        long long seconds;
        long long expireAtMs;
        const char* val = cmd->argv[3];

        if (!parse_non_negative(value, &seconds) ||
            !compute_expire_at_ms(ht_current_time_ms(), seconds, &expireAtMs))
        {
            resp_send_error(w, "ERR value is not an integer or out of range");
        }
        else
        {
            const char* errReply = NULL;

            AcquireSRWLockExclusive(&g_storeLock);
            if (!ht_can_fit(store, key, val))
                errReply = "ERR OOM command not allowed when used memory > 'maxmemory'";
            else if (!aof_append_set_expire(dataFile, key, val, expireAtMs))
                errReply = "ERR could not persist value";
            else if (!ht_insert_ex(store, key, val, expireAtMs))
                errReply = "ERR out of memory";
            ReleaseSRWLockExclusive(&g_storeLock);

            if (errReply != NULL)
                resp_send_error(w, errReply);
            else
                resp_send_simple(w, "OK");
        }
    }
    else if (strcmp(command, "SET") == 0 && valid_key(key) &&
             (cmd->argc == 3 ||
              (cmd->argc == 5 && str_ieq(cmd->argv[3], "EX"))))
    {
        if (cmd->argc == 5)
        {
            long long seconds;
            long long expireAtMs;

            if (!parse_non_negative(cmd->argv[4], &seconds) ||
                !compute_expire_at_ms(ht_current_time_ms(), seconds, &expireAtMs))
            {
                resp_send_error(w, "ERR value is not an integer or out of range");
            }
            else
            {
                const char* errReply = NULL;

                AcquireSRWLockExclusive(&g_storeLock);
                if (!ht_can_fit(store, key, value))
                    errReply = "ERR OOM command not allowed when used memory > 'maxmemory'";
                else if (!aof_append_set_expire(dataFile, key, value, expireAtMs))
                    errReply = "ERR could not persist value";
                else if (!ht_insert_ex(store, key, value, expireAtMs))
                    errReply = "ERR out of memory";
                ReleaseSRWLockExclusive(&g_storeLock);

                if (errReply != NULL)
                    resp_send_error(w, errReply);
                else
                    resp_send_simple(w, "OK");
            }
        }
        else
        {
            const char* errReply = NULL;

            AcquireSRWLockExclusive(&g_storeLock);
            if (!ht_can_fit(store, key, value))
                errReply = "ERR OOM command not allowed when used memory > 'maxmemory'";
            else if (!aof_append(dataFile, "SET", key, value))
                errReply = "ERR could not persist value";
            else if (!ht_insert_ex(store, key, value, 0))
                errReply = "ERR out of memory";
            ReleaseSRWLockExclusive(&g_storeLock);

            if (errReply != NULL)
                resp_send_error(w, errReply);
            else
                resp_send_simple(w, "OK");
        }
    }
    else if ((strcmp(command, "INCR") == 0 || strcmp(command, "DECR") == 0 ||
              strcmp(command, "INCRBY") == 0) && valid_key(key))
    {
        long long delta = 1;
        int valid = 1;

        if (strcmp(command, "DECR") == 0)
        {
            if (cmd->argc != 2) valid = 0;
            delta = -1;
        }
        else if (strcmp(command, "INCR") == 0)
        {
            if (cmd->argc != 2) valid = 0;
            delta = 1;
        }
        else
        {
            if (cmd->argc != 3 || !parse_integer(value, &delta)) valid = 0;
        }

        if (!valid)
        {
            resp_send_error(w, "ERR wrong number of arguments or invalid delta");
        }
        else
        {
            long long currentVal = 0;
            char newValBuf[32];
            const char* errReply = NULL;

            AcquireSRWLockExclusive(&g_storeLock);
            {
                long long now = ht_current_time_ms();
                HashNode* node = ht_find_live(store, key, now);
                long long existingExpire = 0;

                if (node != NULL)
                {
                    if (!parse_integer(node->value, &currentVal))
                        errReply = "ERR value is not an integer or out of range";
                    else
                        existingExpire = node->expireAtMs;
                }

                if (errReply == NULL)
                {
                    if ((delta > 0 && currentVal > LLONG_MAX - delta) ||
                        (delta < 0 && currentVal < LLONG_MIN - delta))
                    {
                        errReply = "ERR increment or decrement would overflow";
                    }
                    else
                    {
                        currentVal += delta;
                        snprintf(newValBuf, sizeof(newValBuf), "%lld", currentVal);

                        if (!ht_can_fit(store, key, newValBuf))
                        {
                            errReply = "ERR OOM command not allowed when used memory > 'maxmemory'";
                        }
                        else
                        {
                            int persisted = existingExpire != 0
                                ? aof_append_set_expire(dataFile, key, newValBuf, existingExpire)
                                : aof_append(dataFile, "SET", key, newValBuf);

                            if (!persisted)
                                errReply = "ERR could not persist value";
                            else if (node != NULL)
                            {
                                if (!ht_update_node_value(store, node, newValBuf))
                                    errReply = "ERR out of memory";
                            }
                            else if (!ht_insert_ex(store, key, newValBuf, 0))
                            {
                                errReply = "ERR out of memory";
                            }
                        }
                    }
                }
            }
            ReleaseSRWLockExclusive(&g_storeLock);

            if (errReply != NULL)
                resp_send_error(w, errReply);
            else
                resp_send_integer(w, currentVal);
        }
    }
    else if (strcmp(command, "DEL") == 0 && cmd->argc == 2 && valid_key(key))
    {
        int deleted = 0;
        const char* errReply = NULL;

        AcquireSRWLockExclusive(&g_storeLock);
        {
            HashNode* node = ht_find_live(store, key, ht_current_time_ms());
            if (node != NULL)
            {
                if (!aof_append(dataFile, "DEL", key, NULL))
                    errReply = "ERR could not persist deletion";
                else
                {
                    ht_delete_node(store, node);
                    deleted = 1;
                }
            }
        }
        ReleaseSRWLockExclusive(&g_storeLock);

        if (errReply != NULL)
            resp_send_error(w, errReply);
        else
            resp_send_integer(w, deleted ? 1 : 0);
    }
    else if (strcmp(command, "EXPIRE") == 0 && cmd->argc == 3 && valid_key(key))
    {
        long long seconds;
        long long now = ht_current_time_ms();
        long long expireAtMs;

        if (!parse_non_negative(value, &seconds) || !compute_expire_at_ms(now, seconds, &expireAtMs))
        {
            resp_send_error(w, "ERR value is not an integer or out of range");
        }
        else
        {
            int exists = 0;
            const char* errReply = NULL;

            AcquireSRWLockExclusive(&g_storeLock);
            {
                HashNode* node = ht_find_live(store, key, now);
                if (node != NULL)
                {
                    exists = 1;
                    if (!aof_log_expire(dataFile, key, expireAtMs))
                        errReply = "ERR could not persist expiry";
                    else
                        ht_set_node_expiry(store, node, expireAtMs);
                }
            }
            ReleaseSRWLockExclusive(&g_storeLock);

            if (errReply != NULL)
                resp_send_error(w, errReply);
            else
                resp_send_integer(w, exists ? 1 : 0);
        }
    }
    else if (strcmp(command, "TTL") == 0 && cmd->argc == 2 && valid_key(key))
    {
        long long expireAtMs = 0;
        int exists;
        int expired = 0;
        long long remainingSeconds;

        AcquireSRWLockShared(&g_storeLock);
        exists = ht_get_expiry_ro(store, key, &expireAtMs, &expired);
        ReleaseSRWLockShared(&g_storeLock);

        if (expired)
        {
            AcquireSRWLockExclusive(&g_storeLock);
            ht_purge_if_expired(store, key);
            ReleaseSRWLockExclusive(&g_storeLock);
        }

        if (!exists)
            remainingSeconds = -2;
        else if (expireAtMs == 0)
            remainingSeconds = -1;
        else
        {
            long long remainingMs = expireAtMs - ht_current_time_ms();
            remainingSeconds = remainingMs > 0 ? (remainingMs + 999) / 1000 : 0;
        }

        resp_send_integer(w, remainingSeconds);
    }
    else if (strcmp(command, "PERSIST") == 0 && cmd->argc == 2 && valid_key(key))
    {
        int changed = 0;
        const char* errReply = NULL;

        AcquireSRWLockExclusive(&g_storeLock);
        {
            HashNode* node = ht_find_live(store, key, ht_current_time_ms());
            if (node != NULL && node->expireAtMs != 0)
            {
                if (!aof_append(dataFile, "PERSIST", key, NULL))
                    errReply = "ERR could not persist change";
                else
                {
                    ht_set_node_expiry(store, node, 0);
                    changed = 1;
                }
            }
        }
        ReleaseSRWLockExclusive(&g_storeLock);

        if (errReply != NULL)
            resp_send_error(w, errReply);
        else
            resp_send_integer(w, changed ? 1 : 0);
    }
    else
    {
        resp_send_error(w, "ERR unknown command or wrong number of arguments. "
                           "Try: AUTH <password>, PING, GET <key>, SET <key> <value> [EX <seconds>], "
                           "SETEX <key> <seconds> <value>, DEL <key>, EXISTS <key>, INCR <key>, "
                           "DECR <key>, INCRBY <key> <delta>, EXPIRE <key> <seconds>, TTL <key>, "
                           "PERSIST <key>, DBSIZE, FLUSHDB, QUIT");
    }

    return 0;
}

static void serve_client(SOCKET client, HashTable* store, const ServerConfig* config)
{
    ClientSession* session = (ClientSession*)calloc(1, sizeof(ClientSession));
    int authenticated = config->authPassword == NULL;
    int authFailures = 0;

    if (session == NULL)
        return;

    br_init(&session->reader, client);
    bw_init(&session->writer, client);

    for (;;)
    {
        int closeRequested;

        if (!read_command(&session->reader, &session->cmd, authenticated))
            break;

        closeRequested = handle_command(session, store, config, &authenticated, &authFailures);

        /* Flush buffered replies once pipelined input drains or before closing. */
        if (closeRequested || !br_has_buffered(&session->reader))
        {
            if (!bw_flush(&session->writer))
                break;
        }

        if (closeRequested)
            break;
    }

    (void)bw_flush(&session->writer);
    cmd_destroy(&session->cmd);
    free(session->scratch);
    free(session);
}

static unsigned __stdcall client_thread(void* arg)
{
    ClientContext* ctx = (ClientContext*)arg;
    DWORD rcvTimeout = RECV_TIMEOUT_MS;
    DWORD sndTimeout = SEND_TIMEOUT_MS;
    int nodelay = 1;

    setsockopt(ctx->client, SOL_SOCKET, SO_RCVTIMEO, (const char*)&rcvTimeout, sizeof(rcvTimeout));
    setsockopt(ctx->client, SOL_SOCKET, SO_SNDTIMEO, (const char*)&sndTimeout, sizeof(sndTimeout));
    setsockopt(ctx->client, IPPROTO_TCP, TCP_NODELAY, (const char*)&nodelay, sizeof(nodelay));

    serve_client(ctx->client, ctx->store, ctx->config);

    closesocket(ctx->client);
    client_registry_release(&g_clients, ctx->slotIdx);
    free(ctx);
    return 0;
}

static unsigned __stdcall maintenance_thread(void* arg)
{
    MaintenanceContext* mctx = (MaintenanceContext*)arg;

    while (is_running())
    {
        DWORD waitRes = WaitForSingleObject(g_stopEvent, SWEEP_INTERVAL_MS);
        if (waitRes == WAIT_OBJECT_0 || !is_running())
            break;

        AcquireSRWLockExclusive(&g_storeLock);
        ht_sweep_step(mctx->store, SWEEP_BUCKETS_PER_TICK);
        ReleaseSRWLockExclusive(&g_storeLock);

        /* Sync dirty AOF writes outside g_storeLock so readers never stall. */
        aof_sync_if_dirty();

        if (is_running() && aof_needs_compact())
        {
            AcquireSRWLockExclusive(&g_storeLock);
            if (!aof_compact(mctx->store, mctx->dataFile))
                fprintf(stderr, "Warning: automatic AOF compaction failed.\n");
            ReleaseSRWLockExclusive(&g_storeLock);
        }
    }

    return 0;
}

static void close_listener_safe(void)
{
    SOCKET s = INVALID_SOCKET;

    EnterCriticalSection(&g_listenerLock);
    if (g_listener != INVALID_SOCKET)
    {
        s = g_listener;
        g_listener = INVALID_SOCKET;
    }
    LeaveCriticalSection(&g_listenerLock);

    if (s != INVALID_SOCKET)
        closesocket(s);
}

static BOOL WINAPI ConsoleCtrlHandler(DWORD dwCtrlType)
{
    (void)dwCtrlType;
    InterlockedExchange(&g_running, 0);
    if (g_stopEvent != NULL)
        SetEvent(g_stopEvent);
    close_listener_safe();
    return TRUE;
}

static char* dup_string(const char* s)
{
    size_t len = strlen(s) + 1;
    char* copy = (char*)malloc(len);
    if (copy != NULL)
        memcpy(copy, s, len);
    return copy;
}

static char* load_password_file(const char* path)
{
    FILE* f = fopen(path, "rb");
    char buf[MAX_ARG_LEN];
    size_t len;

    if (f == NULL)
        return NULL;

    if (fgets(buf, (int)sizeof(buf), f) == NULL)
    {
        fclose(f);
        return NULL;
    }
    fclose(f);

    len = strcspn(buf, "\r\n");
    buf[len] = '\0';
    if (len == 0)
        return NULL;

    {
        char* out = dup_string(buf);
        SecureZeroMemory(buf, sizeof(buf));
        return out;
    }
}

static int parse_fsync_mode(const char* text, AofFsyncMode* out)
{
    if (str_ieq(text, "always"))
    {
        *out = AOF_FSYNC_ALWAYS;
        return 1;
    }
    if (str_ieq(text, "everysec"))
    {
        *out = AOF_FSYNC_EVERYSEC;
        return 1;
    }
    if (str_ieq(text, "no"))
    {
        *out = AOF_FSYNC_NO;
        return 1;
    }
    return 0;
}

static const char* fsync_mode_name(AofFsyncMode mode)
{
    switch (mode)
    {
        case AOF_FSYNC_ALWAYS:   return "always";
        case AOF_FSYNC_EVERYSEC: return "everysec";
        case AOF_FSYNC_NO:       return "no";
        default:                 return "unknown";
    }
}

static void print_usage(const char* prog)
{
    printf("Usage: %s [port] [dataFile] [authPassword] [options]\n"
           "Options:\n"
           "  --bind <host>           Bind address (default: 127.0.0.1, env: KVSTORE_BIND)\n"
           "  --port <port>           TCP port (default: 6379)\n"
           "  --data <file>           AOF path (default: kvstore.aof)\n"
           "  --password-file <file>  Read AUTH password from file (or env: KVSTORE_PASSWORD)\n"
           "  --fsync <mode>          always | everysec | no (default: everysec, env: KVSTORE_FSYNC)\n"
           "  --max-clients <n>       Max concurrent clients (default: 256)\n"
           "  --max-memory <mb>       Max tracked heap memory in MB, 0=unlimited (default: 256)\n"
           "  --max-aof-mb <mb>       Max AOF size in MB, 0=unlimited (default: 512)\n"
           "  -h, --help              Show this help\n",
           prog);
}

static int parse_args(int argc, char* argv[], ServerConfig* cfg)
{
    const char* envVal;
    const char* passwordFile = NULL;
    int positional = 0;
    int i;

    cfg->bindAddr = DEFAULT_BIND;
    cfg->port = DEFAULT_PORT;
    cfg->dataFile = DEFAULT_DATA_FILE;
    cfg->authPassword = NULL;
    cfg->authPasswordLen = 0;
    cfg->fsyncMode = AOF_FSYNC_EVERYSEC;
    cfg->maxClients = DEFAULT_MAX_CLIENTS;
    cfg->maxMemoryBytes = (size_t)DEFAULT_MAX_MEMORY_MB * 1024u * 1024u;
    cfg->maxAofBytes = (size_t)DEFAULT_MAX_AOF_MB * 1024u * 1024u;

    envVal = getenv("KVSTORE_BIND");
    if (envVal != NULL && envVal[0] != '\0')
        cfg->bindAddr = envVal;

    envVal = getenv("KVSTORE_FSYNC");
    if (envVal != NULL && envVal[0] != '\0')
    {
        if (!parse_fsync_mode(envVal, &cfg->fsyncMode))
        {
            fprintf(stderr, "Invalid KVSTORE_FSYNC value: %s\n", envVal);
            return -1;
        }
    }

    envVal = getenv("KVSTORE_PASSWORD");
    if (envVal != NULL && envVal[0] != '\0')
        cfg->authPassword = dup_string(envVal);

    for (i = 1; i < argc; i++)
    {
        const char* arg = argv[i];

        if (strcmp(arg, "-h") == 0 || strcmp(arg, "--help") == 0)
        {
            print_usage(argv[0]);
            return 0;
        }
        else if (strcmp(arg, "--bind") == 0 && i + 1 < argc)
        {
            cfg->bindAddr = argv[++i];
        }
        else if (strcmp(arg, "--port") == 0 && i + 1 < argc)
        {
            cfg->port = argv[++i];
        }
        else if (strcmp(arg, "--data") == 0 && i + 1 < argc)
        {
            cfg->dataFile = argv[++i];
        }
        else if (strcmp(arg, "--password-file") == 0 && i + 1 < argc)
        {
            passwordFile = argv[++i];
        }
        else if (strcmp(arg, "--fsync") == 0 && i + 1 < argc)
        {
            if (!parse_fsync_mode(argv[++i], &cfg->fsyncMode))
            {
                fprintf(stderr, "Invalid --fsync mode (expected always, everysec, or no).\n");
                return -1;
            }
        }
        else if (strcmp(arg, "--max-clients") == 0 && i + 1 < argc)
        {
            long long n;
            if (!parse_non_negative(argv[++i], &n) || n <= 0 || n > 10000)
            {
                fprintf(stderr, "Invalid --max-clients value (1..10000).\n");
                return -1;
            }
            cfg->maxClients = (size_t)n;
        }
        else if (strcmp(arg, "--max-memory") == 0 && i + 1 < argc)
        {
            long long mb;
            if (!parse_non_negative(argv[++i], &mb) ||
                (unsigned long long)mb > (unsigned long long)(SIZE_MAX / (1024u * 1024u)))
            {
                fprintf(stderr, "Invalid --max-memory value.\n");
                return -1;
            }
            cfg->maxMemoryBytes = (size_t)mb * 1024u * 1024u;
        }
        else if (strcmp(arg, "--max-aof-mb") == 0 && i + 1 < argc)
        {
            long long mb;
            if (!parse_non_negative(argv[++i], &mb) ||
                (unsigned long long)mb > (unsigned long long)(SIZE_MAX / (1024u * 1024u)))
            {
                fprintf(stderr, "Invalid --max-aof-mb value.\n");
                return -1;
            }
            cfg->maxAofBytes = (size_t)mb * 1024u * 1024u;
        }
        else if (arg[0] == '-')
        {
            fprintf(stderr, "Unknown or incomplete option: %s\n", arg);
            return -1;
        }
        else
        {
            positional++;
            if (positional == 1)
                cfg->port = arg;
            else if (positional == 2)
                cfg->dataFile = arg;
            else if (positional == 3 && arg[0] != '\0')
            {
                fprintf(stderr, "Warning: passing the password on the command line exposes it in "
                                "process lists; prefer KVSTORE_PASSWORD or --password-file.\n");
                if (cfg->authPassword != NULL)
                {
                    SecureZeroMemory(cfg->authPassword, strlen(cfg->authPassword));
                    free(cfg->authPassword);
                }
                cfg->authPassword = dup_string(arg);
            }
        }
    }

    if (passwordFile != NULL)
    {
        char* loaded = load_password_file(passwordFile);
        if (loaded == NULL)
        {
            fprintf(stderr, "Could not load password from file: %s\n", passwordFile);
            return -1;
        }
        if (cfg->authPassword != NULL)
        {
            SecureZeroMemory(cfg->authPassword, strlen(cfg->authPassword));
            free(cfg->authPassword);
        }
        cfg->authPassword = loaded;
    }

    if (cfg->authPassword != NULL)
        cfg->authPasswordLen = strlen(cfg->authPassword);

    return 1;
}

static void config_destroy(ServerConfig* cfg)
{
    if (cfg->authPassword != NULL)
    {
        SecureZeroMemory(cfg->authPassword, cfg->authPasswordLen);
        free(cfg->authPassword);
        cfg->authPassword = NULL;
        cfg->authPasswordLen = 0;
    }
}

int main(int argc, char* argv[])
{
    ServerConfig config;
    int parseResult;
    WSADATA wsa;
    struct addrinfo hints;
    struct addrinfo* address = NULL;
    SOCKET listener = INVALID_SOCKET;
    HashTable* store = NULL;
    HANDLE maintThread = NULL;
    MaintenanceContext maintCtx;
    int shouldCompact = 0;
    int wsaInitialized = 0;
    int registryInitialized = 0;
    int exitCode = 1;

    parseResult = parse_args(argc, argv, &config);
    if (parseResult <= 0)
    {
        config_destroy(&config);
        return parseResult == 0 ? 0 : 1;
    }

    InitializeCriticalSection(&g_listenerLock);
    auth_limiter_init(&g_authLimiter);

    g_stopEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (g_stopEvent == NULL)
    {
        fprintf(stderr, "Could not create shutdown event.\n");
        goto cleanup;
    }

    if (!client_registry_init(&g_clients, config.maxClients))
    {
        fprintf(stderr, "Could not allocate client registry.\n");
        goto cleanup;
    }
    registryInitialized = 1;

    store = ht_create();
    if (store == NULL)
    {
        fprintf(stderr, "Could not allocate hash table.\n");
        goto cleanup;
    }

    ht_set_max_memory(store, config.maxMemoryBytes);
    aof_set_fsync_mode(config.fsyncMode);
    aof_set_max_size(config.maxAofBytes);
    aof_set_compact_threshold((size_t)DEFAULT_COMPACT_MIN_MB * 1024u * 1024u);

    if (!aof_load_ex(store, config.dataFile, &shouldCompact))
    {
        fprintf(stderr, "Could not load persistence file '%s' (corrupt, unreadable, or exceeds memory limit).\n",
                config.dataFile);
        goto cleanup;
    }

    if (shouldCompact)
    {
        AcquireSRWLockExclusive(&g_storeLock);
        if (!aof_compact(store, config.dataFile))
            fprintf(stderr, "Warning: startup AOF compaction failed; continuing with existing log.\n");
        ReleaseSRWLockExclusive(&g_storeLock);
    }

    if (!aof_open(config.dataFile))
        fprintf(stderr, "Warning: could not open AOF append handle; falling back to per-write open.\n");

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
    {
        fprintf(stderr, "WSAStartup failed.\n");
        goto cleanup;
    }
    wsaInitialized = 1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    if (getaddrinfo(config.bindAddr, config.port, &hints, &address) != 0)
    {
        fprintf(stderr, "Could not resolve bind address %s:%s.\n", config.bindAddr, config.port);
        goto cleanup;
    }

    listener = socket(address->ai_family, address->ai_socktype, address->ai_protocol);
    if (listener == INVALID_SOCKET)
    {
        fprintf(stderr, "Could not create listening socket.\n");
        freeaddrinfo(address);
        goto cleanup;
    }

    {
        int exclusive = 1;
        if (setsockopt(listener, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
                       (const char*)&exclusive, sizeof(exclusive)) == SOCKET_ERROR)
        {
            fprintf(stderr, "Warning: could not enable SO_EXCLUSIVEADDRUSE.\n");
        }
    }

    if (bind(listener, address->ai_addr, (int)address->ai_addrlen) == SOCKET_ERROR ||
        listen(listener, SOMAXCONN) == SOCKET_ERROR)
    {
        fprintf(stderr, "Could not listen on %s:%s.\n", config.bindAddr, config.port);
        freeaddrinfo(address);
        closesocket(listener);
        listener = INVALID_SOCKET;
        goto cleanup;
    }
    freeaddrinfo(address);

    EnterCriticalSection(&g_listenerLock);
    g_listener = listener;
    LeaveCriticalSection(&g_listenerLock);

    maintCtx.store = store;
    maintCtx.dataFile = config.dataFile;
    maintThread = (HANDLE)_beginthreadex(NULL, 0, maintenance_thread, &maintCtx, 0, NULL);
    if (maintThread == NULL)
    {
        fprintf(stderr, "Could not start background maintenance thread.\n");
        goto cleanup;
    }

    SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);

    printf("kvstore listening on %s:%s (RESP/TCP); data file: %s; fsync: %s; auth: %s; max-clients: %zu\n",
           config.bindAddr, config.port, config.dataFile, fsync_mode_name(config.fsyncMode),
           config.authPassword != NULL ? "enabled" : "disabled", config.maxClients);
    fflush(stdout);

    while (is_running())
    {
        SOCKET client = accept(listener, NULL, NULL);
        ClientContext* ctx;
        HANDLE threadHandle;
        size_t slotIdx = 0;

        if (client == INVALID_SOCKET)
        {
            if (!is_running())
                break;
            Sleep(10);
            continue;
        }

        if (!client_registry_acquire(&g_clients, client, &slotIdx))
        {
            static const char kBusy[] = "-ERR max number of clients reached\r\n";
            DWORD briefTimeout = 1000;
            setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, (const char*)&briefTimeout, sizeof(briefTimeout));
            if (is_running())
                (void)send_raw(client, kBusy, sizeof(kBusy) - 1);
            closesocket(client);
            continue;
        }

        ctx = (ClientContext*)malloc(sizeof(ClientContext));
        if (ctx == NULL)
        {
            client_registry_release(&g_clients, slotIdx);
            closesocket(client);
            continue;
        }
        ctx->client = client;
        ctx->slotIdx = slotIdx;
        ctx->store = store;
        ctx->config = &config;

        threadHandle = (HANDLE)_beginthreadex(NULL, 0, client_thread, ctx, 0, NULL);
        if (threadHandle == NULL)
        {
            client_registry_release(&g_clients, slotIdx);
            closesocket(client);
            free(ctx);
            continue;
        }
        CloseHandle(threadHandle);
    }

    printf("\nShutting down kvstore cleanly...\n");
    exitCode = 0;

cleanup:
    InterlockedExchange(&g_running, 0);
    if (g_stopEvent != NULL)
        SetEvent(g_stopEvent);
    close_listener_safe();

    /* Wait for all client and background threads before destroying shared state. */
    if (registryInitialized)
        client_registry_shutdown_and_wait(&g_clients);

    if (maintThread != NULL)
    {
        WaitForSingleObject(maintThread, INFINITE);
        CloseHandle(maintThread);
    }

    aof_close();
    ht_destroy(store);

    if (registryInitialized)
        client_registry_destroy(&g_clients);

    if (wsaInitialized)
        WSACleanup();

    if (g_stopEvent != NULL)
        CloseHandle(g_stopEvent);

    auth_limiter_destroy(&g_authLimiter);
    DeleteCriticalSection(&g_listenerLock);
    config_destroy(&config);

    return exitCode;
}
