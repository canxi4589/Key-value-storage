#ifndef HASHTABLE_H
#define HASHTABLE_H

#include <stddef.h>

typedef struct
{
    char* key;
    char* value;
    long long expireAtMs;  /* 0 = no expiry; otherwise absolute epoch ms when this key expires */
    int occupied;
} HashNode;

typedef struct
{
    HashNode* table;
    size_t capacity;
    size_t size;
} HashTable;

HashTable* ht_create(void);
void ht_destroy(HashTable* ht);

/* Sets key to value. Clears any existing TTL on the key, matching Redis's
   plain SET semantics. Returns 0 on allocation failure. */
int ht_insert(HashTable* ht, const char* key, const char* value);

/* Same as ht_insert, but preserves any TTL the key already had (matching
   Redis's SET ... KEEPTTL). If the key is new, it has no TTL either way. */
int ht_insert_keep_ttl(HashTable* ht, const char* key, const char* value);

/* Returns the value for key, or NULL if the key is absent or has expired.
   A key found to be expired during lookup is deleted on the spot (lazy /
   passive expiration), so callers never need to check expiry separately. */
char* ht_search(HashTable* ht, const char* key);

/* Removes key. Returns 1 if it was present and not already expired,
   0 otherwise (including the case where it was present but expired). */
int ht_remove(HashTable* ht, const char* key);

/* Sets an absolute expiration time (milliseconds since the Unix epoch) on an
   existing key. Pass 0 to clear the TTL. Returns 1 if the key exists and is
   not already expired, 0 otherwise. */
int ht_set_expiry(HashTable* ht, const char* key, long long expireAtMs);

/* Clears any TTL on key, making it persist indefinitely. Returns 1 if the
   key exists (and was not already expired), 0 otherwise. */
int ht_persist(HashTable* ht, const char* key);

/* Looks up key's expiration without otherwise affecting it. Returns 0 if the
   key doesn't exist or has expired; returns 1 and sets *outExpireAtMs
   otherwise (0 meaning "no TTL", or the absolute expiry in ms). */
int ht_get_expiry(HashTable* ht, const char* key, long long* outExpireAtMs);

/* Current wall-clock time in milliseconds since the Unix epoch. Exposed so
   callers (command handlers, AOF replay) can compute absolute expiry times
   consistently with what the hash table uses internally. */
long long ht_current_time_ms(void);

/* Scans the whole table and deletes every key that has expired. Returns the
   number of keys removed. Intended to be called periodically by a
   background sweep thread, so that keys which are never looked up again
   still eventually get freed. */
size_t ht_sweep_expired(HashTable* ht);

/* Callback used by ht_for_each. expireAtMs is 0 if the key has no TTL. */
typedef void (*HtVisitor)(const char* key, const char* value, long long expireAtMs, void* userData);

/* Calls callback once for every currently non-expired key in the table.
   Does not mutate the table (does not lazily delete anything it skips over)
   so it's safe to use for read-only snapshots such as AOF compaction. */
void ht_for_each(HashTable* ht, HtVisitor callback, void* userData);

void ht_print(HashTable* ht);

#endif