#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <errno.h>
#include <io.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "Header/persistence.h"

#define AOF_MAX_ARG_LEN (16u * 1024u * 1024u)
#define AOF_DEFAULT_COMPACT_MIN_BYTES (64u * 1024u * 1024u)
#define AOF_STACK_BUF_SIZE 1024
#define AOF_COMPACT_BUF_SIZE 65536u

static INIT_ONCE g_aofInitOnce = INIT_ONCE_STATIC_INIT;
static CRITICAL_SECTION g_aofLock;
static FILE* g_aofFile = NULL;
static char* g_aofPath = NULL;
static AofFsyncMode g_fsyncMode = AOF_FSYNC_EVERYSEC;
static size_t g_maxAofBytes = 0;
static size_t g_compactMinBytes = AOF_DEFAULT_COMPACT_MIN_BYTES;
static size_t g_aofCurrentBytes = 0;
static size_t g_aofBaseBytes = 0;
static int g_aofDirty = 0;

static BOOL CALLBACK init_aof_lock_once(PINIT_ONCE initOnce, PVOID param, PVOID* ctx)
{
    (void)initOnce;
    (void)param;
    (void)ctx;
    InitializeCriticalSection(&g_aofLock);
    return TRUE;
}

static void aof_lock(void)
{
    InitOnceExecuteOnce(&g_aofInitOnce, init_aof_lock_once, NULL, NULL);
    EnterCriticalSection(&g_aofLock);
}

static void aof_unlock(void)
{
    LeaveCriticalSection(&g_aofLock);
}

static char* dup_str(const char* s)
{
    size_t len = strlen(s) + 1;
    char* copy = (char*)malloc(len);
    if (copy != NULL)
        memcpy(copy, s, len);
    return copy;
}

static size_t get_path_size_bytes(const char* path)
{
    WIN32_FILE_ATTRIBUTE_DATA fad;
    ULARGE_INTEGER uli;

    if (!GetFileAttributesExA(path, GetFileExInfoStandard, &fad))
        return 0;

    uli.LowPart = fad.nFileSizeLow;
    uli.HighPart = fad.nFileSizeHigh;
    return (size_t)uli.QuadPart;
}

static int parse_strict_i64(const char* text, long long* out)
{
    char* endptr = NULL;
    long long val;

    if (text == NULL || text[0] == '\0')
        return 0;
    if (text[0] == ' ' || text[0] == '\t')
        return 0;

    errno = 0;
    val = strtoll(text, &endptr, 10);
    if (errno == ERANGE || endptr == text || *endptr != '\0')
        return 0;

    *out = val;
    return 1;
}

/* Calculates exact byte length of a RESP bulk string "$<len>\r\n<bytes>\r\n". */
static size_t resp_bulk_size(size_t dataLen)
{
    char hdr[32];
    int n = snprintf(hdr, sizeof(hdr), "$%zu\r\n", dataLen);
    if (n <= 0 || (size_t)n >= sizeof(hdr))
        return 0;
    return (size_t)n + dataLen + 2;
}

static char* write_resp_bulk(char* dst, const char* data, size_t dataLen)
{
    int n = sprintf(dst, "$%zu\r\n", dataLen);
    dst += n;
    if (dataLen > 0)
    {
        memcpy(dst, data, dataLen);
        dst += dataLen;
    }
    dst[0] = '\r';
    dst[1] = '\n';
    return dst + 2;
}

static int format_resp_cmd(char* stackBuf, size_t stackSize, char** outBuf, size_t* outLen,
                           const char* cmd, const char* key, const char* value)
{
    size_t cmdLen = strlen(cmd);
    size_t keyLen = strlen(key);
    size_t valLen = value != NULL ? strlen(value) : 0;
    size_t argc = value != NULL ? 3u : 2u;
    size_t total;
    char* buf;
    char* p;
    char arrHdr[32];
    int arrHdrLen;

    arrHdrLen = snprintf(arrHdr, sizeof(arrHdr), "*%zu\r\n", argc);
    if (arrHdrLen <= 0 || (size_t)arrHdrLen >= sizeof(arrHdr))
        return 0;

    total = (size_t)arrHdrLen + resp_bulk_size(cmdLen) + resp_bulk_size(keyLen);
    if (value != NULL)
        total += resp_bulk_size(valLen);

    if (total <= stackSize)
        buf = stackBuf;
    else
    {
        buf = (char*)malloc(total);
        if (buf == NULL)
            return 0;
    }

    p = buf;
    memcpy(p, arrHdr, (size_t)arrHdrLen);
    p += arrHdrLen;
    p = write_resp_bulk(p, cmd, cmdLen);
    p = write_resp_bulk(p, key, keyLen);
    if (value != NULL)
        p = write_resp_bulk(p, value, valLen);

    *outBuf = buf;
    *outLen = (size_t)(p - buf);
    return 1;
}

static int write_raw_record_locked(const char* dataFile, const char* buf, size_t len)
{
    FILE* file = NULL;
    int needClose = 0;
    int ok = 1;

    if (g_maxAofBytes != 0 &&
        (len > g_maxAofBytes || g_aofCurrentBytes > g_maxAofBytes - len))
    {
        return 0;
    }

    if (g_aofFile != NULL && g_aofPath != NULL && strcmp(g_aofPath, dataFile) == 0)
    {
        file = g_aofFile;
    }
    else
    {
        file = fopen(dataFile, "ab");
        if (file == NULL)
            return 0;
        needClose = 1;
    }

    if (fwrite(buf, 1, len, file) != len)
        ok = 0;

    if (ok && fflush(file) != 0)
        ok = 0;

    if (ok)
    {
        if (g_fsyncMode == AOF_FSYNC_ALWAYS || needClose)
        {
            if (_commit(_fileno(file)) != 0)
                ok = 0;
            else if (!needClose)
                g_aofDirty = 0;
        }
        else if (g_fsyncMode == AOF_FSYNC_EVERYSEC)
        {
            g_aofDirty = 1;
        }
    }

    if (ok)
        g_aofCurrentBytes += len;

    if (needClose)
        fclose(file);

    return ok;
}

static void aof_close_locked(void)
{
    if (g_aofFile != NULL)
    {
        fflush(g_aofFile);
        _commit(_fileno(g_aofFile));
        fclose(g_aofFile);
        g_aofFile = NULL;
        g_aofDirty = 0;
    }
    free(g_aofPath);
    g_aofPath = NULL;
}

static int aof_open_locked(const char* dataFile)
{
    char* pathCopy;
    FILE* f;

    aof_close_locked();

    pathCopy = dup_str(dataFile);
    if (pathCopy == NULL)
        return 0;

    f = fopen(dataFile, "ab");
    if (f == NULL)
    {
        free(pathCopy);
        return 0;
    }

    g_aofFile = f;
    g_aofPath = pathCopy;
    g_aofCurrentBytes = get_path_size_bytes(dataFile);
    g_aofDirty = 0;
    return 1;
}

void aof_set_fsync_mode(AofFsyncMode mode)
{
    aof_lock();
    g_fsyncMode = mode;
    aof_unlock();
}

void aof_set_max_size(size_t maxBytes)
{
    aof_lock();
    g_maxAofBytes = maxBytes;
    aof_unlock();
}

void aof_set_compact_threshold(size_t minBytes)
{
    aof_lock();
    g_compactMinBytes = minBytes;
    aof_unlock();
}

int aof_needs_compact(void)
{
    int needed = 0;

    aof_lock();
    if (g_compactMinBytes != 0 && g_aofCurrentBytes >= g_compactMinBytes)
    {
        size_t target = g_aofBaseBytes > 0 ? g_aofBaseBytes * 2 : g_compactMinBytes;
        if (target < g_compactMinBytes)
            target = g_compactMinBytes;
        if (g_aofCurrentBytes >= target)
            needed = 1;
    }
    aof_unlock();

    return needed;
}

void aof_sync_if_dirty(void)
{
    aof_lock();
    if (g_aofFile != NULL && g_aofDirty && g_fsyncMode == AOF_FSYNC_EVERYSEC)
    {
        if (fflush(g_aofFile) == 0 && _commit(_fileno(g_aofFile)) == 0)
            g_aofDirty = 0;
    }
    aof_unlock();
}

int aof_open(const char* dataFile)
{
    int ok;

    if (dataFile == NULL)
        return 0;

    aof_lock();
    ok = aof_open_locked(dataFile);
    aof_unlock();
    return ok;
}

void aof_close(void)
{
    aof_lock();
    aof_close_locked();
    aof_unlock();
}

int aof_append(const char* dataFile, const char* command, const char* key, const char* value)
{
    char stackBuf[AOF_STACK_BUF_SIZE];
    char* buf = NULL;
    size_t len = 0;
    int ok;

    if (dataFile == NULL || command == NULL || key == NULL)
        return 0;

    if (!format_resp_cmd(stackBuf, sizeof(stackBuf), &buf, &len, command, key, value))
        return 0;

    aof_lock();
    ok = write_raw_record_locked(dataFile, buf, len);
    aof_unlock();

    if (buf != stackBuf)
        free(buf);

    return ok;
}

int aof_append_set_expire(const char* dataFile, const char* key, const char* value, long long expireAtMs)
{
    char tsBuf[32];
    char stackBuf[AOF_STACK_BUF_SIZE];
    size_t keyLen;
    size_t valLen;
    size_t tsLen;
    size_t total;
    char* buf;
    char* p;
    int n;
    int ok;

    if (dataFile == NULL || key == NULL || value == NULL)
        return 0;

    n = snprintf(tsBuf, sizeof(tsBuf), "%lld", expireAtMs);
    if (n <= 0 || (size_t)n >= sizeof(tsBuf))
        return 0;

    keyLen = strlen(key);
    valLen = strlen(value);
    tsLen = (size_t)n;

    /* "*3\r\n$3\r\nSET\r\n" (13) + bulk(key) + bulk(val)
       + "*3\r\n$6\r\nEXPIRE\r\n" (16) + bulk(key) + bulk(ts) */
    total = 4u + resp_bulk_size(3) + resp_bulk_size(keyLen) + resp_bulk_size(valLen) +
            4u + resp_bulk_size(6) + resp_bulk_size(keyLen) + resp_bulk_size(tsLen);

    if (total <= sizeof(stackBuf))
        buf = stackBuf;
    else
    {
        buf = (char*)malloc(total);
        if (buf == NULL)
            return 0;
    }

    p = buf;
    memcpy(p, "*3\r\n", 4); p += 4;
    p = write_resp_bulk(p, "SET", 3);
    p = write_resp_bulk(p, key, keyLen);
    p = write_resp_bulk(p, value, valLen);

    memcpy(p, "*3\r\n", 4); p += 4;
    p = write_resp_bulk(p, "EXPIRE", 6);
    p = write_resp_bulk(p, key, keyLen);
    p = write_resp_bulk(p, tsBuf, tsLen);

    aof_lock();
    ok = write_raw_record_locked(dataFile, buf, (size_t)(p - buf));
    aof_unlock();

    if (buf != stackBuf)
        free(buf);

    return ok;
}

int aof_log_expire(const char* dataFile, const char* key, long long expireAtMs)
{
    char value[32];
    int n = snprintf(value, sizeof(value), "%lld", expireAtMs);

    if (n <= 0 || (size_t)n >= sizeof(value))
        return 0;

    return aof_append(dataFile, "EXPIRE", key, value);
}

/* Reads a full line dynamically into *buf (stripped of trailing \r\n).
 * Returns 1 on success, 0 on EOF, -1 on error / line too long. */
static int read_dynamic_line(FILE* file, char** buf, size_t* cap, size_t maxLen, size_t* outLen)
{
    size_t len = 0;
    int ch;

    for (;;)
    {
        ch = fgetc(file);
        if (ch == EOF)
        {
            if (ferror(file))
                return -1;
            if (len == 0)
                return 0;
            break;
        }
        if (ch == '\n')
            break;
        if (len >= maxLen)
            return -1;
        if (len + 2 > *cap)
        {
            size_t newCap = *cap == 0 ? 256u : (*cap * 2u);
            char* grown;
            if (newCap > maxLen + 2)
                newCap = maxLen + 2;
            grown = (char*)realloc(*buf, newCap);
            if (grown == NULL)
                return -1;
            *buf = grown;
            *cap = newCap;
        }
        (*buf)[len++] = (char)ch;
    }

    if (len > 0 && (*buf)[len - 1] == '\r')
        len--;

    if (*cap == 0)
    {
        *buf = (char*)malloc(1);
        if (*buf == NULL)
            return -1;
        *cap = 1;
    }
    (*buf)[len] = '\0';
    if (outLen != NULL)
        *outLen = len;
    return 1;
}

static int apply_command_args(HashTable* store, int argc, char* const* argv)
{
    if (argc < 2 || argv[0] == NULL || argv[1] == NULL || argv[1][0] == '\0')
        return 1;

    if (strcmp(argv[0], "SET") == 0 && argc == 3 && argv[2] != NULL)
    {
        return ht_insert(store, argv[1], argv[2]);
    }
    else if (strcmp(argv[0], "DEL") == 0 && argc == 2)
    {
        ht_remove(store, argv[1]);
        return 1;
    }
    else if (strcmp(argv[0], "EXPIRE") == 0 && argc == 3 && argv[2] != NULL)
    {
        long long ts;
        if (parse_strict_i64(argv[2], &ts) && ts >= 0)
            ht_set_expiry(store, argv[1], ts);
        return 1;
    }
    else if (strcmp(argv[0], "PERSIST") == 0 && argc == 2)
    {
        ht_persist(store, argv[1]);
        return 1;
    }

    return 1;
}

static int apply_legacy_line(HashTable* store, char* line)
{
    char* p = line;
    char* cmd;
    char* key;
    char* value = NULL;
    char* argv[3];
    int argc = 0;

    while (*p == ' ' || *p == '\t')
        p++;
    if (*p == '\0')
        return 1;

    cmd = p;
    while (*p != '\0' && *p != ' ' && *p != '\t')
        p++;
    if (*p == '\0')
        return 1;
    *p++ = '\0';

    while (*p == ' ' || *p == '\t')
        p++;
    if (*p == '\0')
        return 1;

    key = p;
    while (*p != '\0' && *p != ' ' && *p != '\t')
        p++;
    if (*p != '\0')
    {
        *p++ = '\0';
        if (*p != '\0')
            value = p;
    }

    argv[argc++] = cmd;
    argv[argc++] = key;
    if (value != NULL)
        argv[argc++] = value;

    return apply_command_args(store, argc, argv);
}

static int read_resp_record(FILE* file, HashTable* store, const char* firstLine)
{
    long long countVal;
    int argc;
    int i;
    char* args[3] = { NULL, NULL, NULL };
    char* lenLine = NULL;
    size_t lenCap = 0;
    int ok = 1;

    if (!parse_strict_i64(firstLine + 1, &countVal) || countVal < 2 || countVal > 3)
        return 0;

    argc = (int)countVal;
    for (i = 0; i < argc; i++)
    {
        long long argLenVal;
        size_t argLen;
        char crlf[2];

        if (read_dynamic_line(file, &lenLine, &lenCap, 64, NULL) != 1 || lenLine[0] != '$')
        {
            ok = 0;
            break;
        }
        if (!parse_strict_i64(lenLine + 1, &argLenVal) || argLenVal < 0 ||
            (unsigned long long)argLenVal > AOF_MAX_ARG_LEN)
        {
            ok = 0;
            break;
        }

        argLen = (size_t)argLenVal;
        args[i] = (char*)malloc(argLen + 1);
        if (args[i] == NULL)
        {
            ok = 0;
            break;
        }

        if (argLen > 0 && fread(args[i], 1, argLen, file) != argLen)
        {
            ok = 0;
            break;
        }
        args[i][argLen] = '\0';

        if (argLen > 0 && memchr(args[i], '\0', argLen) != NULL)
        {
            ok = 0;
            break;
        }

        if (fread(crlf, 1, 2, file) != 2 || crlf[0] != '\r' || crlf[1] != '\n')
        {
            ok = 0;
            break;
        }
    }

    if (ok)
        ok = apply_command_args(store, argc, args);

    free(lenLine);
    for (i = 0; i < 3; i++)
        free(args[i]);

    return ok;
}

int aof_load_ex(HashTable* store, const char* dataFile, int* outShouldCompact)
{
    FILE* file;
    char* line = NULL;
    size_t lineCap = 0;
    size_t records = 0;
    int sawLegacy = 0;
    int ok = 1;
    size_t fileBytes = 0;

    if (outShouldCompact != NULL)
        *outShouldCompact = 0;

    if (store == NULL || dataFile == NULL)
        return 0;

    errno = 0;
    file = fopen(dataFile, "rb");
    if (file == NULL)
    {
        /* Only a missing file is valid; permission/IO errors must fail startup. */
        return errno == ENOENT ? 1 : 0;
    }

    for (;;)
    {
        int r = read_dynamic_line(file, &line, &lineCap, AOF_MAX_ARG_LEN * 2 + 64, NULL);
        if (r == 0)
            break;
        if (r < 0)
        {
            ok = 0;
            break;
        }
        if (line[0] == '\0')
            continue;

        if (line[0] == '*')
        {
            if (!read_resp_record(file, store, line))
            {
                ok = 0;
                break;
            }
        }
        else
        {
            sawLegacy = 1;
            if (!apply_legacy_line(store, line))
            {
                ok = 0;
                break;
            }
        }
        records++;
    }

    if (ferror(file))
        ok = 0;

    fileBytes = get_path_size_bytes(dataFile);
    free(line);
    fclose(file);

    if (ok)
    {
        aof_lock();
        g_aofCurrentBytes = fileBytes;
        g_aofBaseBytes = fileBytes;
        aof_unlock();

        if (outShouldCompact != NULL && (sawLegacy || records > 0))
            *outShouldCompact = 1;
    }

    return ok;
}

int aof_load(HashTable* store, const char* dataFile)
{
    return aof_load_ex(store, dataFile, NULL);
}

typedef struct
{
    HANDLE handle;
    char* buf;
    size_t bufLen;
    size_t bufCap;
    size_t bytesWritten;
    int ok;
} CompactContext;

static int write_all_handle(HANDLE h, const char* data, size_t len)
{
    size_t offset = 0;

    while (offset < len)
    {
        size_t remaining = len - offset;
        DWORD chunk = remaining > 0x40000000u ? 0x40000000u : (DWORD)remaining;
        DWORD written = 0;

        if (!WriteFile(h, data + offset, chunk, &written, NULL) || written == 0)
            return 0;
        offset += (size_t)written;
    }

    return 1;
}

static int compact_flush(CompactContext* ctx)
{
    if (ctx->bufLen == 0)
        return 1;
    if (!write_all_handle(ctx->handle, ctx->buf, ctx->bufLen))
    {
        ctx->ok = 0;
        return 0;
    }
    ctx->bufLen = 0;
    return 1;
}

static void compact_write(CompactContext* ctx, const char* data, size_t len)
{
    if (!ctx->ok || len == 0)
        return;

    if (ctx->bufLen + len <= ctx->bufCap)
    {
        memcpy(ctx->buf + ctx->bufLen, data, len);
        ctx->bufLen += len;
        ctx->bytesWritten += len;
        return;
    }

    if (!compact_flush(ctx))
        return;

    if (len < ctx->bufCap)
    {
        memcpy(ctx->buf, data, len);
        ctx->bufLen = len;
        ctx->bytesWritten += len;
    }
    else if (write_all_handle(ctx->handle, data, len))
    {
        ctx->bytesWritten += len;
    }
    else
    {
        ctx->ok = 0;
    }
}

static void write_compact_record(CompactContext* ctx, const char* cmd, const char* key, const char* value)
{
    char stackBuf[AOF_STACK_BUF_SIZE];
    char* buf = NULL;
    size_t len = 0;

    if (!ctx->ok)
        return;

    if (!format_resp_cmd(stackBuf, sizeof(stackBuf), &buf, &len, cmd, key, value))
    {
        ctx->ok = 0;
        return;
    }

    compact_write(ctx, buf, len);

    if (buf != stackBuf)
        free(buf);
}

static void write_entry(const char* key, const char* value, long long expireAtMs, void* userData)
{
    CompactContext* ctx = (CompactContext*)userData;

    if (!ctx->ok)
        return;

    write_compact_record(ctx, "SET", key, value);
    if (!ctx->ok)
        return;

    if (expireAtMs != 0)
    {
        char tsBuf[32];
        int n = snprintf(tsBuf, sizeof(tsBuf), "%lld", expireAtMs);
        if (n <= 0 || (size_t)n >= sizeof(tsBuf))
        {
            ctx->ok = 0;
            return;
        }
        write_compact_record(ctx, "EXPIRE", key, tsBuf);
    }
}

/* Creates an exclusive temporary file next to dataFile to prevent symlink/name clashes. */
static HANDLE create_unique_temp_file(const char* dataFile, char** outTempPath)
{
    static volatile LONG s_counter = 0;
    DWORD pid = GetCurrentProcessId();
    size_t baseLen = strlen(dataFile);
    size_t pathCap = baseLen + 64;
    char* path = (char*)malloc(pathCap);
    int attempt;

    if (path == NULL)
        return INVALID_HANDLE_VALUE;

    for (attempt = 0; attempt < 32; attempt++)
    {
        LONG seq = InterlockedIncrement(&s_counter);
        ULONGLONG tick = GetTickCount64();
        HANDLE hFile;

        snprintf(path, pathCap, "%s.%lu.%lx.%llx.tmp",
                 dataFile, (unsigned long)pid, (unsigned long)seq, (unsigned long long)tick);

        hFile = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE)
        {
            if (GetLastError() == ERROR_FILE_EXISTS)
                continue;
            free(path);
            return INVALID_HANDLE_VALUE;
        }

        *outTempPath = path;
        return hFile;
    }

    free(path);
    return INVALID_HANDLE_VALUE;
}

int aof_compact(const HashTable* store, const char* dataFile)
{
    char* tempFile = NULL;
    CompactContext ctx;
    int reOpen;
    int ok = 1;

    if (store == NULL || dataFile == NULL)
        return 0;

    aof_lock();

    reOpen = (g_aofFile != NULL);
    aof_close_locked();

    ctx.buf = (char*)malloc(AOF_COMPACT_BUF_SIZE);
    if (ctx.buf == NULL)
    {
        if (reOpen)
            (void)aof_open_locked(dataFile);
        aof_unlock();
        return 0;
    }

    ctx.handle = create_unique_temp_file(dataFile, &tempFile);
    if (ctx.handle == INVALID_HANDLE_VALUE)
    {
        free(ctx.buf);
        if (reOpen)
            (void)aof_open_locked(dataFile);
        aof_unlock();
        return 0;
    }

    ctx.bufLen = 0;
    ctx.bufCap = AOF_COMPACT_BUF_SIZE;
    ctx.bytesWritten = 0;
    ctx.ok = 1;

    ht_for_each(store, write_entry, &ctx);

    if (ctx.ok)
        (void)compact_flush(&ctx);
    if (ctx.ok && !FlushFileBuffers(ctx.handle))
        ctx.ok = 0;

    CloseHandle(ctx.handle);
    free(ctx.buf);

    if (!ctx.ok)
    {
        DeleteFileA(tempFile);
        free(tempFile);
        if (reOpen)
            (void)aof_open_locked(dataFile);
        aof_unlock();
        return 0;
    }

    if (!MoveFileExA(tempFile, dataFile, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
    {
        DeleteFileA(tempFile);
        free(tempFile);
        if (reOpen)
            (void)aof_open_locked(dataFile);
        aof_unlock();
        return 0;
    }

    free(tempFile);
    g_aofCurrentBytes = ctx.bytesWritten;
    g_aofBaseBytes = ctx.bytesWritten;
    g_aofDirty = 0;

    if (reOpen && !aof_open_locked(dataFile))
        ok = 0;

    aof_unlock();
    return ok;
}

int aof_truncate(const char* dataFile)
{
    FILE* file;
    int reOpen;
    int ok = 1;

    if (dataFile == NULL)
        return 0;

    aof_lock();
    reOpen = (g_aofFile != NULL);
    aof_close_locked();

    file = fopen(dataFile, "wb");
    if (file == NULL)
    {
        if (reOpen)
            (void)aof_open_locked(dataFile);
        aof_unlock();
        return 0;
    }

    if (fflush(file) != 0 || _commit(_fileno(file)) != 0)
        ok = 0;
    fclose(file);

    if (ok)
    {
        g_aofCurrentBytes = 0;
        g_aofBaseBytes = 0;
        g_aofDirty = 0;
    }

    if (reOpen && !aof_open_locked(dataFile))
        ok = 0;

    aof_unlock();
    return ok;
}
