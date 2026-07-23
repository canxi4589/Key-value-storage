#ifndef PERSISTENCE_H
#define PERSISTENCE_H

#include "hashtable.h"

/* Appends one command line to dataFile and fsyncs it (fflush + _commit)
   before returning, so a successful call means the write is durable on
   disk, not just buffered. `value` may be NULL (used by DEL, which only
   logs a key). Returns 0 on any failure. */
int aof_append(const char* dataFile, const char* command, const char* key, const char* value);

/* Convenience wrapper around aof_append that logs "EXPIRE key <expireAtMs>",
   formatting the absolute expiry timestamp itself. */
int aof_log_expire(const char* dataFile, const char* key, long long expireAtMs);

/* Replays dataFile into store to rebuild in-memory state on startup. A
   missing file is treated as a normal first run, not an error -- this
   always returns 1 (kept as int for symmetry with the rest of the API and
   room for future failure modes, e.g. a corrupt file). */
int aof_load(HashTable* store, const char* dataFile);

/* Rewrites dataFile so it contains only the minimal SET/EXPIRE commands
   needed to reconstruct the table's *current*, non-expired contents --
   collapsing however much redundant history previously accumulated. On
   success, dataFile is atomically replaced with the compacted version; on
   any failure the original dataFile is left completely untouched.

   The caller must hold whatever lock protects concurrent access to `store`
   for the entire duration of this call, since it walks the live table. */
int aof_compact(HashTable* store, const char* dataFile);

#endif
