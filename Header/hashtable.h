#ifndef HASHTABLE_H
#define HASHTABLE_H

#include <stddef.h>

typedef struct
{
    char* key;
    char* value;
    int occupied;
} HashNode;

typedef struct
{
    HashNode* table;
    size_t size;
    size_t capacity;
} HashTable;

HashTable* ht_create(void);

void ht_destroy(HashTable* ht);

int ht_insert(HashTable* ht, const char* key, const char* value);

char* ht_search(HashTable* ht, const char* key);

int ht_remove(HashTable* ht, const char* key);

void ht_print(HashTable* ht);

#endif
