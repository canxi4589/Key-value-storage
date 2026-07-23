#include "Header/hashtable.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define LOAD_FACTOR 0.7

static int ht_insert_internal(HashTable* ht, const char* key, const char* value, long long expireAtMs);
static int ht_resize(HashTable* ht);

static size_t hash(const char* key, size_t capacity)
{
    unsigned long h = 5381;
    int c;

    while ((c = *key++))
        h = ((h << 5) + h) + c;

    return h % capacity;
}

static char* copy_string(const char* str)
{
    size_t len = strlen(str) + 1;
    char* copy = malloc(len);

    if (copy == NULL)
        return NULL;

    memcpy(copy, str, len);
    return copy;
}

long long ht_current_time_ms(void)
{
    return (long long)time(NULL) * 1000;
}

static int is_expired(const HashNode* node, long long nowMs)
{
    return node->expireAtMs != 0 && node->expireAtMs <= nowMs;
}

static HashNode* find_node(HashTable* ht, const char* key)
{
    size_t index = hash(key, ht->capacity);
    size_t start = index;

    while (ht->table[index].occupied)
    {
        if (strcmp(ht->table[index].key, key) == 0)
            return &ht->table[index];

        index = (index + 1) % ht->capacity;
        if (index == start)
            break;
    }

    return NULL;
}

/* Remove a slot and rebuild its following probe chain. */
static void delete_at(HashTable* ht, size_t index)
{
    size_t next;

    free(ht->table[index].key);
    free(ht->table[index].value);
    ht->table[index].key = NULL;
    ht->table[index].value = NULL;
    ht->table[index].expireAtMs = 0;
    ht->table[index].occupied = 0;
    ht->size--;

    next = (index + 1) % ht->capacity;
    while (ht->table[next].occupied)
    {
        HashNode temp = ht->table[next];

        ht->table[next].key = NULL;
        ht->table[next].value = NULL;
        ht->table[next].expireAtMs = 0;
        ht->table[next].occupied = 0;
        ht->size--;

        ht_insert_internal(ht, temp.key, temp.value, temp.expireAtMs);
        free(temp.key);
        free(temp.value);

        next = (next + 1) % ht->capacity;
    }
}

static int ht_resize(HashTable* ht)
{
    size_t oldCapacity = ht->capacity;
    HashNode* oldTable = ht->table;
    size_t newCapacity = oldCapacity * 2;
    HashNode* newTable = calloc(newCapacity, sizeof(HashNode));
    long long now = ht_current_time_ms();
    size_t i;

    if (newTable == NULL)
        return 0;

    ht->table = newTable;
    ht->capacity = newCapacity;
    ht->size = 0;

    for (i = 0; i < oldCapacity; i++)
    {
        if (!oldTable[i].occupied)
            continue;

        if (is_expired(&oldTable[i], now))
        {
            free(oldTable[i].key);
            free(oldTable[i].value);
            continue;
        }

        {
            size_t index = hash(oldTable[i].key, ht->capacity);

            while (ht->table[index].occupied)
                index = (index + 1) % ht->capacity;

            ht->table[index].key = oldTable[i].key;
            ht->table[index].value = oldTable[i].value;
            ht->table[index].expireAtMs = oldTable[i].expireAtMs;
            ht->table[index].occupied = 1;

            ht->size++;
        }
    }

    free(oldTable);

    return 1;
}

HashTable* ht_create(void)
{
    HashTable* ht = malloc(sizeof(HashTable));

    if (ht == NULL)
        return NULL;

    ht->capacity = 16;
    ht->size = 0;
    ht->table = calloc(16, sizeof(HashNode));

    if (ht->table == NULL)
    {
        free(ht);
        return NULL;
    }

    return ht;
}

void ht_destroy(HashTable* ht)
{
    size_t i;

    if (ht == NULL)
        return;

    for (i = 0; i < ht->capacity; i++)
    {
        if (ht->table[i].occupied)
        {
            free(ht->table[i].key);
            free(ht->table[i].value);
        }
    }

    free(ht->table);
    free(ht);
}

static int ht_insert_internal(HashTable* ht, const char* key, const char* value, long long expireAtMs)
{
    size_t index;
    char* keyCopy;
    char* valueCopy;

    if ((double)ht->size / ht->capacity > LOAD_FACTOR)
    {
        if (!ht_resize(ht))
            return 0;
    }

    index = hash(key, ht->capacity);

    while (ht->table[index].occupied)
    {
        if (strcmp(ht->table[index].key, key) == 0)
        {
            char* newValue = copy_string(value);

            if (newValue == NULL)
                return 0;

            free(ht->table[index].value);
            ht->table[index].value = newValue;
            ht->table[index].expireAtMs = expireAtMs;
            return 1;
        }

        index = (index + 1) % ht->capacity;
    }

    keyCopy = copy_string(key);
    valueCopy = copy_string(value);

    if (keyCopy == NULL || valueCopy == NULL)
    {
        free(keyCopy);
        free(valueCopy);
        return 0;
    }

    ht->table[index].key = keyCopy;
    ht->table[index].value = valueCopy;
    ht->table[index].expireAtMs = expireAtMs;
    ht->table[index].occupied = 1;

    ht->size++;

    return 1;
}

int ht_insert(HashTable* ht, const char* key, const char* value)
{
    return ht_insert_internal(ht, key, value, 0);
}

int ht_insert_keep_ttl(HashTable* ht, const char* key, const char* value)
{
    HashNode* existing = find_node(ht, key);
    long long expireAtMs = 0;

    if (existing != NULL && !is_expired(existing, ht_current_time_ms()))
        expireAtMs = existing->expireAtMs;

    return ht_insert_internal(ht, key, value, expireAtMs);
}

char* ht_search(HashTable* ht, const char* key)
{
    HashNode* node = find_node(ht, key);

    if (node == NULL)
        return NULL;

    if (is_expired(node, ht_current_time_ms()))
    {
        delete_at(ht, (size_t)(node - ht->table));
        return NULL;
    }

    return node->value;
}

int ht_remove(HashTable* ht, const char* key)
{
    HashNode* node = find_node(ht, key);

    if (node == NULL)
        return 0;

    if (is_expired(node, ht_current_time_ms()))
    {
        delete_at(ht, (size_t)(node - ht->table));
        return 0;
    }

    delete_at(ht, (size_t)(node - ht->table));
    return 1;
}

int ht_set_expiry(HashTable* ht, const char* key, long long expireAtMs)
{
    HashNode* node = find_node(ht, key);

    if (node == NULL)
        return 0;

    if (is_expired(node, ht_current_time_ms()))
    {
        delete_at(ht, (size_t)(node - ht->table));
        return 0;
    }

    node->expireAtMs = expireAtMs;
    return 1;
}

int ht_persist(HashTable* ht, const char* key)
{
    HashNode* node = find_node(ht, key);

    if (node == NULL)
        return 0;

    if (is_expired(node, ht_current_time_ms()))
    {
        delete_at(ht, (size_t)(node - ht->table));
        return 0;
    }

    if (node->expireAtMs == 0)
        return 0;

    node->expireAtMs = 0;
    return 1;
}

int ht_get_expiry(HashTable* ht, const char* key, long long* outExpireAtMs)
{
    HashNode* node = find_node(ht, key);

    if (node == NULL)
        return 0;

    if (is_expired(node, ht_current_time_ms()))
    {
        delete_at(ht, (size_t)(node - ht->table));
        return 0;
    }

    if (outExpireAtMs != NULL)
        *outExpireAtMs = node->expireAtMs;

    return 1;
}

size_t ht_sweep_expired(HashTable* ht)
{
    long long now = ht_current_time_ms();
    size_t removed = 0;
    size_t i = 0;

    while (i < ht->capacity)
    {
        if (ht->table[i].occupied && is_expired(&ht->table[i], now))
        {
            delete_at(ht, i);
            ++removed;
            continue;
        }
        ++i;
    }

    return removed;
}

void ht_for_each(HashTable* ht, HtVisitor callback, void* userData)
{
    long long now = ht_current_time_ms();
    size_t i;

    for (i = 0; i < ht->capacity; i++)
    {
        if (ht->table[i].occupied && !is_expired(&ht->table[i], now))
            callback(ht->table[i].key, ht->table[i].value, ht->table[i].expireAtMs, userData);
    }
}

void ht_print(HashTable* ht)
{
    size_t i;
    long long now = ht_current_time_ms();

    printf("\nHash Table\n");
    printf("-----------------------\n");

    for (i = 0; i < ht->capacity; i++)
    {
        if (!ht->table[i].occupied)
        {
            printf("[%zu] EMPTY\n", i);
            continue;
        }

        if (ht->table[i].expireAtMs == 0)
            printf("[%zu] %s -> %s\n", i, ht->table[i].key, ht->table[i].value);
        else
        {
            long long remainingMs = ht->table[i].expireAtMs - now;
            printf("[%zu] %s -> %s (expires in %lldms)\n", i, ht->table[i].key,
                   ht->table[i].value, remainingMs);
        }
    }

    printf("-----------------------\n");
}
