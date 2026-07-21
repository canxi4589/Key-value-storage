#include "Header/hashtable.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LOAD_FACTOR 0.7

//djb2 hash function
static size_t hash(const char* key, size_t capacity)
{
    unsigned long hash = 5381;
    int c;

    while ((c = *key++))
    {
        hash = ((hash << 5) + hash) + c; 
    }

    return hash % capacity;

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

static int ht_resize(HashTable* ht)
{
    size_t oldCapacity = ht->capacity; //(*ht).capacity
    HashNode* oldTable = ht->table;

    size_t newCapacity = oldCapacity * 2;

    HashNode* newTable = calloc(newCapacity, sizeof(HashNode));

    if (newTable == NULL)
        return 0;

    ht->table = newTable;
    ht->capacity = newCapacity;
    ht->size = 0;

    for (size_t i = 0; i < oldCapacity; i++)
    {
        if (oldTable[i].occupied)
        {
            size_t index = hash(oldTable[i].key, ht->capacity);

            while (ht->table[index].occupied)
            {
                index = (index + 1) % ht->capacity;
            }

            ht->table[index].key = oldTable[i].key;
            ht->table[index].value = oldTable[i].value;
            ht->table[index].occupied = 1;

            ht->size++;
        }
    }

    free(oldTable);

    return 1;
}

HashTable* ht_create()
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
    if (ht == NULL)
        return;

    for (size_t i = 0; i < ht->capacity; i++)
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

int ht_insert(HashTable* ht, const char* key, const char* value)
{
    if ((double)ht->size / ht->capacity > LOAD_FACTOR)
    {
        if (!ht_resize(ht))
            return 0;
    }

    size_t index = hash(key, ht->capacity);

    while (ht->table[index].occupied)
    {
        if (strcmp(ht->table[index].key, key) == 0)
        {
            char* newValue = copy_string(value);

            if (newValue == NULL)
                return 0;

            free(ht->table[index].value);
            ht->table[index].value = newValue;
            return 1;
        }

        index = (index + 1) % ht->capacity;
    }

    char* keyCopy = copy_string(key);
    char* valueCopy = copy_string(value);

    if (keyCopy == NULL || valueCopy == NULL)
    {
        free(keyCopy);
        free(valueCopy);
        return 0;
    }

    ht->table[index].key = keyCopy;
    ht->table[index].value = valueCopy;
    ht->table[index].occupied = 1;

    ht->size++;

    return 1;
}

char* ht_search(HashTable* ht, const char* key)
{
    size_t index = hash(key, ht->capacity);
    size_t start = index;

    while (ht->table[index].occupied)
    {
        if (strcmp(ht->table[index].key, key) == 0)
            return ht->table[index].value;

        index = (index + 1) % ht->capacity;

        if (index == start)
            break;
    }

    return NULL;
}

int ht_remove(HashTable* ht, const char* key)
{
    size_t index = hash(key, ht->capacity);
    size_t start = index;

    while (ht->table[index].occupied)
    {
        if (strcmp(ht->table[index].key, key) == 0)
        {
            free(ht->table[index].key);
            free(ht->table[index].value);

            ht->table[index].occupied = 0;
            ht->size--;

            size_t next = (index + 1) % ht->capacity;

            while (ht->table[next].occupied)
            {
                HashNode temp = ht->table[next];

                ht->table[next].occupied = 0;
                ht->size--;

                ht_insert(ht, temp.key, temp.value);
                free(temp.key);
                free(temp.value);

                next = (next + 1) % ht->capacity;
            }

            return 1;
        }

        index = (index + 1) % ht->capacity;

        if (index == start)
            break;
    }

    return 0;
}

void ht_print(HashTable* ht)
{
    printf("\nHash Table\n");
    printf("-----------------------\n");

    for (size_t i = 0; i < ht->capacity; i++)
    {
        if (ht->table[i].occupied)
            printf("[%zu] %s -> %s\n", i, ht->table[i].key,
                ht->table[i].value);
        else
            printf("[%zu] EMPTY\n", i);
    }

    printf("-----------------------\n");
}
