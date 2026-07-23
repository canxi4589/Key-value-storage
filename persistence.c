#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <io.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "Header/persistence.h"

#define MAX_LINE 4096
#define COMPACT_TEMP_SUFFIX ".tmp"

int aof_append(const char* dataFile, const char* command, const char* key, const char* value)
{
    FILE* file = fopen(dataFile, "a");
    int ok;

    if (file == NULL)
        return 0;

    ok = value == NULL
        ? fprintf(file, "%s %s\n", command, key) > 0
        : fprintf(file, "%s %s %s\n", command, key, value) > 0;

    if (ok && fflush(file) != 0)
        ok = 0;
    if (ok && _commit(_fileno(file)) != 0)
        ok = 0;

    fclose(file);
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

static void apply_line(HashTable* store, char* line)
{
    char* command = strtok(line, " \t");
    char* key = strtok(NULL, " \t");
    char* value = strtok(NULL, "");

    if (command == NULL || key == NULL)
        return;

    if (strcmp(command, "SET") == 0 && value != NULL)
        ht_insert(store, key, value);
    else if (strcmp(command, "DEL") == 0 && value == NULL)
        ht_remove(store, key);
    else if (strcmp(command, "EXPIRE") == 0 && value != NULL)
        ht_set_expiry(store, key, atoll(value));
    else if (strcmp(command, "PERSIST") == 0 && value == NULL)
        ht_persist(store, key);
}

int aof_load(HashTable* store, const char* dataFile)
{
    FILE* file = fopen(dataFile, "r");
    char line[MAX_LINE];

    if (file == NULL)
        return 1;

    while (fgets(line, sizeof(line), file) != NULL)
    {
        line[strcspn(line, "\r\n")] = '\0';
        apply_line(store, line);
    }

    fclose(file);
    return 1;
}

typedef struct
{
    FILE* file;
    int ok;
} CompactContext;

static void write_entry(const char* key, const char* value, long long expireAtMs, void* userData)
{
    CompactContext* ctx = (CompactContext*)userData;

    if (!ctx->ok)
        return;

    if (fprintf(ctx->file, "SET %s %s\n", key, value) <= 0)
    {
        ctx->ok = 0;
        return;
    }

    if (expireAtMs != 0 && fprintf(ctx->file, "EXPIRE %s %lld\n", key, expireAtMs) <= 0)
        ctx->ok = 0;
}

int aof_compact(HashTable* store, const char* dataFile)
{
    char tempFile[MAX_PATH];
    CompactContext ctx;
    int n = snprintf(tempFile, sizeof(tempFile), "%s%s", dataFile, COMPACT_TEMP_SUFFIX);

    if (n <= 0 || (size_t)n >= sizeof(tempFile))
        return 0;

    ctx.file = fopen(tempFile, "w");
    if (ctx.file == NULL)
        return 0;
    ctx.ok = 1;

    ht_for_each(store, write_entry, &ctx);

    if (ctx.ok && fflush(ctx.file) != 0)
        ctx.ok = 0;
    if (ctx.ok && _commit(_fileno(ctx.file)) != 0)
        ctx.ok = 0;

    fclose(ctx.file);

    if (!ctx.ok)
    {
        remove(tempFile);
        return 0;
    }

    if (!MoveFileExA(tempFile, dataFile, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
    {
        remove(tempFile);
        return 0;
    }

    return 1;
}
