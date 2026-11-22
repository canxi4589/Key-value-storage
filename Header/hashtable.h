#ifndef HASHTABLE_H
#define HASHTABLE_H

#include <stddef.h>
#include <stdint.h>

typedef struct
{
    char* key;            /* NULL means empty slot */
    char* value;
    uint64_t hash;        /* Cached SipHash of key */
    long long expireAtMs; /* 0 means no expiry */
} HashNode;

typedef struct
{
    HashNode* table;
    size_t capacity;
    size_t size;
    size_t ttlCount;       /* Count of live slots with expireAtMs != 0 */
    size_t memoryBytes;    /* Tracked heap bytes (table + keys + values) */
    size_t maxMemoryBytes; /* 0 means unlimited */
    size_t sweepCursor;    /* Cursor for incremental expiry sweeping */
    uint64_t seed0;
    uint64_t seed1;
} HashTable;

HashTable* ht_create(void);
void ht_destroy(HashTable* ht);

/* Sets a hard cap on tracked heap memory in bytes (0 = unlimited). */
void ht_set_max_memory(HashTable* ht, size_t maxBytes);

/* Returns current tracked heap usage in bytes. */
size_t ht_memory_usage(const HashTable* ht);

/* Returns 1 if inserting/updating key -> value fits within maxMemoryBytes. */
int ht_can_fit(const HashTable* ht, const char* key, const char* value);

/* Returns 0 on allocation failure or memory limit exceeded. Clears any existing TTL. */
int ht_insert(HashTable* ht, const char* key, const char* value);

/* Inserts or updates with an explicit absolute expiry (0 = no expiry). */
int ht_insert_ex(HashTable* ht, const char* key, const char* value, long long expireAtMs);

/* Inserts while preserving an existing non-expired TTL. */
int ht_insert_keep_ttl(HashTable* ht, const char* key, const char* value);

/* Returns NULL for missing or expired keys (lazily removes expired keys). */
char* ht_search(HashTable* ht, const char* key);

/* Read-only lookup safe under a shared reader lock; sets *outExpired=1 if expired. */
const char* ht_search_ro(const HashTable* ht, const char* key, int* outExpired);

/* Read-only expiry lookup safe under a shared reader lock. */
int ht_get_expiry_ro(const HashTable* ht, const char* key, long long* outExpireAtMs, int* outExpired);

/* Read-only existence check safe under a shared reader lock. */
int ht_exists_ro(const HashTable* ht, const char* key, int* outExpired);

/* Removes key only if it exists and is expired. Returns 1 if removed. */
int ht_purge_if_expired(HashTable* ht, const char* key);

/* Single-lookup live node helpers (caller must hold exclusive lock). */
HashNode* ht_find_live(HashTable* ht, const char* key, long long nowMs);
void ht_delete_node(HashTable* ht, HashNode* node);
int ht_update_node_value(HashTable* ht, HashNode* node, const char* value);
void ht_set_node_expiry(HashTable* ht, HashNode* node, long long expireAtMs);

/* Returns 1 when a live key was removed. */
int ht_remove(HashTable* ht, const char* key);

/* Sets an absolute expiry time; 0 clears it. */
int ht_set_expiry(HashTable* ht, const char* key, long long expireAtMs);

/* Returns 1 only when a live key's TTL was removed. */
int ht_persist(HashTable* ht, const char* key);

/* Returns the expiry time for a live key (0 means no TTL). */
int ht_get_expiry(HashTable* ht, const char* key, long long* outExpireAtMs);

long long ht_current_time_ms(void);

/* Removes all expired keys and returns the count. */
size_t ht_sweep_expired(HashTable* ht);

/* Incrementally inspects up to maxBuckets slots for expiry. */
size_t ht_sweep_step(HashTable* ht, size_t maxBuckets);

/* Returns 1 if key exists and is not expired, 0 otherwise. */
int ht_exists(HashTable* ht, const char* key);

/* Returns the number of active, non-expired keys. O(1) when ttlCount == 0. */
size_t ht_count(const HashTable* ht);

/* Removes all keys from the table and resets capacity to initial size. */
void ht_clear(HashTable* ht);

typedef void (*HtVisitor)(const char* key, const char* value, long long expireAtMs, void* userData);

/* Visits each non-expired entry without mutating the table. */
void ht_for_each(const HashTable* ht, HtVisitor callback, void* userData);

void ht_print(const HashTable* ht);

#endif
