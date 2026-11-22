#ifndef PERSISTENCE_H
#define PERSISTENCE_H

#include <stddef.h>
#include "hashtable.h"

typedef enum
{
    AOF_FSYNC_ALWAYS = 0,
    AOF_FSYNC_EVERYSEC = 1,
    AOF_FSYNC_NO = 2
} AofFsyncMode;

/* Configures how aggressively writes are flushed to physical disk. */
void aof_set_fsync_mode(AofFsyncMode mode);

/* Configures maximum AOF size in bytes (0 = unlimited). */
void aof_set_max_size(size_t maxBytes);

/* Configures minimum AOF size before automatic runtime compaction triggers. */
void aof_set_compact_threshold(size_t minBytes);

/* Returns 1 if the AOF has grown enough to warrant compaction. */
int aof_needs_compact(void);

/* Syncs buffered AOF writes to disk if dirty (used by background thread). */
void aof_sync_if_dirty(void);

/* Opens the AOF file in binary append mode. */
int aof_open(const char* dataFile);

/* Flushes, commits, and closes the open AOF file handle if open. */
void aof_close(void);

/* Appends one RESP-framed command. `value` may be NULL. */
int aof_append(const char* dataFile, const char* command, const char* key, const char* value);

/* Atomically appends SET + EXPIRE in a single buffered write and sync. */
int aof_append_set_expire(const char* dataFile, const char* key, const char* value, long long expireAtMs);

/* Logs an absolute expiry timestamp. */
int aof_log_expire(const char* dataFile, const char* key, long long expireAtMs);

/* Replays dataFile (RESP or legacy text); missing file (ENOENT) is valid. */
int aof_load(HashTable* store, const char* dataFile);

/* Same as aof_load, also reporting whether startup compaction is recommended. */
int aof_load_ex(HashTable* store, const char* dataFile, int* outShouldCompact);

/* Atomically rewrites the AOF with live entries in RESP format. */
int aof_compact(const HashTable* store, const char* dataFile);

/* Truncates the AOF file (used by FLUSHDB). */
int aof_truncate(const char* dataFile);

#endif
