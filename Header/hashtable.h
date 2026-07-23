#ifndef HASHTABLE_H
#define HASHTABLE_H

#include <stddef.h>

typedef struct
{
    char* key;
    char* value;
    long long expireAtMs;  /* 0 means no expiry */
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

/* Returns 0 on allocation failure. Clears any existing TTL. */
int ht_insert(HashTable* ht, const char* key, const char* value);

/* Inserts while preserving an existing TTL. */
int ht_insert_keep_ttl(HashTable* ht, const char* key, const char* value);

/* Returns NULL for missing or expired keys. */
char* ht_search(HashTable* ht, const char* key);

/* Returns 1 when a live key was removed. */
int ht_remove(HashTable* ht, const char* key);

/* Sets an absolute expiry time; 0 clears it. */
int ht_set_expiry(HashTable* ht, const char* key, long long expireAtMs);

/* Returns 1 only when a live key's TTL was removed. */
int ht_persist(HashTable* ht, const char* key);

/* Returns the expiry time for a live key (0 means no TTL). */
int ht_get_expiry(HashTable* ht, const char* key, long long* outExpireAtMs);

long long ht_current_time_ms(void);

/* Removes expired keys and returns the count. */
size_t ht_sweep_expired(HashTable* ht);

typedef void (*HtVisitor)(const char* key, const char* value, long long expireAtMs, void* userData);

/* Visits each non-expired entry without mutating the table. */
void ht_for_each(HashTable* ht, HtVisitor callback, void* userData);

void ht_print(HashTable* ht);

#endif
