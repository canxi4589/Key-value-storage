#ifndef PERSISTENCE_H
#define PERSISTENCE_H

#include "hashtable.h"

/* Appends and flushes one command. `value` may be NULL. */
int aof_append(const char* dataFile, const char* command, const char* key, const char* value);

/* Logs an absolute expiry timestamp. */
int aof_log_expire(const char* dataFile, const char* key, long long expireAtMs);

/* Replays dataFile; a missing file is valid. */
int aof_load(HashTable* store, const char* dataFile);

/* Atomically rewrites the AOF with live entries. Caller holds the store lock. */
int aof_compact(HashTable* store, const char* dataFile);

#endif
