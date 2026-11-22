#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif

#include "Header/hashtable.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <sys/time.h>
#endif

#define HT_INITIAL_CAPACITY 16u
#define HT_LOAD_NUM 7u
#define HT_LOAD_DEN 10u
#define HT_SHRINK_FACTOR 8u

static int ht_resize_to(HashTable* ht, size_t newCapacity, size_t* outPruned);
static size_t ht_maybe_shrink(HashTable* ht);

static uint64_t rotl64(uint64_t x, int b)
{
    return (x << b) | (x >> (64 - b));
}

#define SIPROUND()                    \
    do                                \
    {                                 \
        v0 += v1;                     \
        v1 = rotl64(v1, 13);          \
        v1 ^= v0;                     \
        v0 = rotl64(v0, 32);          \
        v2 += v3;                     \
        v3 = rotl64(v3, 16);          \
        v3 ^= v2;                     \
        v0 += v3;                     \
        v3 = rotl64(v3, 21);          \
        v3 ^= v0;                     \
        v2 += v1;                     \
        v1 = rotl64(v1, 17);          \
        v1 ^= v2;                     \
        v2 = rotl64(v2, 32);          \
    } while (0)

static uint64_t read_u64_le(const unsigned char* p)
{
    return ((uint64_t)p[0]) |
           ((uint64_t)p[1] << 8) |
           ((uint64_t)p[2] << 16) |
           ((uint64_t)p[3] << 24) |
           ((uint64_t)p[4] << 32) |
           ((uint64_t)p[5] << 40) |
           ((uint64_t)p[6] << 48) |
           ((uint64_t)p[7] << 56);
}

/* SipHash-1-3 keyed with per-table 128-bit random seed. */
static uint64_t siphash13(const void* data, size_t len, uint64_t k0, uint64_t k1)
{
    const unsigned char* in = (const unsigned char*)data;
    const unsigned char* end = in + (len - (len & 7u));
    uint64_t v0 = 0x736f6d6570736575ULL ^ k0;
    uint64_t v1 = 0x646f72616e646f6dULL ^ k1;
    uint64_t v2 = 0x6c7967656e657261ULL ^ k0;
    uint64_t v3 = 0x7465646279746573ULL ^ k1;
    uint64_t b = ((uint64_t)len & 0xffULL) << 56;
    size_t left = len & 7u;

    for (; in != end; in += 8)
    {
        uint64_t m = read_u64_le(in);
        v3 ^= m;
        SIPROUND();
        v0 ^= m;
    }

    switch (left)
    {
        case 7: b |= ((uint64_t)in[6]) << 48; /* fallthrough */
        case 6: b |= ((uint64_t)in[5]) << 40; /* fallthrough */
        case 5: b |= ((uint64_t)in[4]) << 32; /* fallthrough */
        case 4: b |= ((uint64_t)in[3]) << 24; /* fallthrough */
        case 3: b |= ((uint64_t)in[2]) << 16; /* fallthrough */
        case 2: b |= ((uint64_t)in[1]) << 8;  /* fallthrough */
        case 1: b |= ((uint64_t)in[0]);       /* fallthrough */
        case 0: break;
    }

    v3 ^= b;
    SIPROUND();
    v0 ^= b;

    v2 ^= 0xffULL;
    SIPROUND();
    SIPROUND();
    SIPROUND();

    return v0 ^ v1 ^ v2 ^ v3;
}

static uint64_t hash_key(const HashTable* ht, const char* key)
{
    return siphash13(key, strlen(key), ht->seed0, ht->seed1);
}

static uint64_t splitmix64(uint64_t* state)
{
    uint64_t z = (*state += 0x9e3779b97f4a7c15ULL);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

static void generate_hash_seeds(uint64_t* out0, uint64_t* out1, const void* entropyPtr)
{
#ifdef _WIN32
    typedef LONG (WINAPI *BCryptGenRandomFn)(void*, unsigned char*, unsigned long, unsigned long);
    HMODULE mod = LoadLibraryA("bcrypt.dll");
    if (mod != NULL)
    {
        FARPROC proc = GetProcAddress(mod, "BCryptGenRandom");
        if (proc != NULL)
        {
            BCryptGenRandomFn genRandom = NULL;
            uint64_t buf[2] = { 0, 0 };
            memcpy(&genRandom, &proc, sizeof(genRandom));
            /* BCRYPT_USE_SYSTEM_PREFERRED_RNG = 0x00000002 */
            if (genRandom(NULL, (unsigned char*)buf, (unsigned long)sizeof(buf), 0x00000002UL) == 0)
            {
                FreeLibrary(mod);
                *out0 = buf[0];
                *out1 = buf[1];
                return;
            }
        }
        FreeLibrary(mod);
    }

    {
        LARGE_INTEGER qpc;
        FILETIME ft;
        uint64_t state = 0;

        QueryPerformanceCounter(&qpc);
        GetSystemTimeAsFileTime(&ft);
        state ^= (uint64_t)qpc.QuadPart;
        state ^= ((uint64_t)ft.dwHighDateTime << 32) | (uint64_t)ft.dwLowDateTime;
        state ^= ((uint64_t)GetCurrentProcessId() << 32) | (uint64_t)GetCurrentThreadId();
        state ^= (uint64_t)(uintptr_t)entropyPtr;
        *out0 = splitmix64(&state);
        *out1 = splitmix64(&state);
    }
#else
    FILE* urandom = fopen("/dev/urandom", "rb");
    if (urandom != NULL)
    {
        uint64_t buf[2];
        if (fread(buf, sizeof(buf), 1, urandom) == 1)
        {
            fclose(urandom);
            *out0 = buf[0];
            *out1 = buf[1];
            return;
        }
        fclose(urandom);
    }

    {
        uint64_t state = (uint64_t)time(NULL) ^ (uint64_t)(uintptr_t)entropyPtr;
        *out0 = splitmix64(&state);
        *out1 = splitmix64(&state);
    }
#endif
}

static char* copy_string_len(const char* str, size_t len)
{
    char* copy = (char*)malloc(len + 1);
    if (copy == NULL)
        return NULL;
    memcpy(copy, str, len + 1);
    return copy;
}

#ifdef _WIN32
typedef VOID (WINAPI *GetPreciseTimeFn)(LPFILETIME);
static INIT_ONCE g_timeInitOnce = INIT_ONCE_STATIC_INIT;
static GetPreciseTimeFn g_preciseTimeFn = NULL;

static BOOL CALLBACK init_precise_time(PINIT_ONCE initOnce, PVOID param, PVOID* ctx)
{
    HMODULE k32;
    (void)initOnce;
    (void)param;
    (void)ctx;

    k32 = GetModuleHandleA("kernel32.dll");
    if (k32 != NULL)
    {
        FARPROC proc = GetProcAddress(k32, "GetSystemTimePreciseAsFileTime");
        if (proc != NULL)
            memcpy(&g_preciseTimeFn, &proc, sizeof(g_preciseTimeFn));
    }
    return TRUE;
}
#endif

long long ht_current_time_ms(void)
{
#ifdef _WIN32
    static const unsigned long long EPOCH_DIFF = 116444736000000000ULL;
    FILETIME ft;
    ULARGE_INTEGER uli;

    InitOnceExecuteOnce(&g_timeInitOnce, init_precise_time, NULL, NULL);
    if (g_preciseTimeFn != NULL)
        g_preciseTimeFn(&ft);
    else
        GetSystemTimeAsFileTime(&ft);

    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;
    if (uli.QuadPart < EPOCH_DIFF)
        return 0;
    return (long long)((uli.QuadPart - EPOCH_DIFF) / 10000ULL);
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (long long)tv.tv_sec * 1000 + tv.tv_usec / 1000;
#endif
}

static int is_expired_at(const HashNode* node, long long nowMs)
{
    return node->expireAtMs != 0 && node->expireAtMs <= nowMs;
}

static int node_is_expired_now(const HashNode* node)
{
    return node->expireAtMs != 0 && node->expireAtMs <= ht_current_time_ms();
}

static HashNode* find_node_hashed(const HashTable* ht, const char* key, uint64_t h)
{
    size_t mask = ht->capacity - 1;
    size_t index = (size_t)(h & mask);
    size_t start = index;

    while (ht->table[index].key != NULL)
    {
        if (ht->table[index].hash == h && strcmp(ht->table[index].key, key) == 0)
            return &ht->table[index];

        index = (index + 1) & mask;
        if (index == start)
            break;
    }

    return NULL;
}

static HashNode* find_node(const HashTable* ht, const char* key)
{
    return find_node_hashed(ht, key, hash_key(ht, key));
}

/* Remove a slot and shift following cluster elements backward (backward-shift deletion). */
static void delete_at(HashTable* ht, size_t index)
{
    size_t mask = ht->capacity - 1;
    size_t i = index;
    size_t j = (index + 1) & mask;
    size_t freedBytes = strlen(ht->table[i].key) + 1 + strlen(ht->table[i].value) + 1;

    if (ht->table[i].expireAtMs != 0 && ht->ttlCount > 0)
        ht->ttlCount--;

    free(ht->table[i].key);
    free(ht->table[i].value);
    ht->table[i].key = NULL;
    ht->table[i].value = NULL;
    ht->table[i].hash = 0;
    ht->table[i].expireAtMs = 0;
    ht->size--;
    if (ht->memoryBytes >= freedBytes)
        ht->memoryBytes -= freedBytes;

    while (ht->table[j].key != NULL)
    {
        size_t k = (size_t)(ht->table[j].hash & mask);
        int can_shift = 0;

        if (j >= k)
        {
            if (i >= k && i < j)
                can_shift = 1;
        }
        else
        {
            if (i >= k || i < j)
                can_shift = 1;
        }

        if (can_shift)
        {
            ht->table[i] = ht->table[j];
            ht->table[j].key = NULL;
            ht->table[j].value = NULL;
            ht->table[j].hash = 0;
            ht->table[j].expireAtMs = 0;
            i = j;
        }

        j = (j + 1) & mask;
    }
}

static int ht_resize_to(HashTable* ht, size_t newCapacity, size_t* outPruned)
{
    size_t oldCapacity = ht->capacity;
    HashNode* oldTable = ht->table;
    HashNode* newTable;
    size_t newMask;
    long long now = 0;
    int checkExpiry = ht->ttlCount > 0;
    size_t oldTableBytes;
    size_t newTableBytes;
    size_t pruned = 0;
    size_t i;

    if (outPruned != NULL)
        *outPruned = 0;

    if (newCapacity < HT_INITIAL_CAPACITY || newCapacity > SIZE_MAX / sizeof(HashNode))
        return 0;

    oldTableBytes = oldCapacity * sizeof(HashNode);
    newTableBytes = newCapacity * sizeof(HashNode);

    if (ht->maxMemoryBytes != 0 && newTableBytes > oldTableBytes)
    {
        size_t growth = newTableBytes - oldTableBytes;
        if (growth > ht->maxMemoryBytes || ht->memoryBytes > ht->maxMemoryBytes - growth)
            return 0;
    }

    newTable = (HashNode*)calloc(newCapacity, sizeof(HashNode));
    if (newTable == NULL)
        return 0;

    if (checkExpiry)
        now = ht_current_time_ms();

    newMask = newCapacity - 1;
    ht->table = newTable;
    ht->capacity = newCapacity;
    ht->size = 0;
    ht->ttlCount = 0;
    ht->sweepCursor = 0;

    if (newTableBytes >= oldTableBytes)
        ht->memoryBytes += (newTableBytes - oldTableBytes);
    else if (ht->memoryBytes >= (oldTableBytes - newTableBytes))
        ht->memoryBytes -= (oldTableBytes - newTableBytes);

    for (i = 0; i < oldCapacity; i++)
    {
        if (oldTable[i].key == NULL)
            continue;

        if (checkExpiry && is_expired_at(&oldTable[i], now))
        {
            size_t freedBytes = strlen(oldTable[i].key) + 1 + strlen(oldTable[i].value) + 1;
            if (ht->memoryBytes >= freedBytes)
                ht->memoryBytes -= freedBytes;
            free(oldTable[i].key);
            free(oldTable[i].value);
            pruned++;
            continue;
        }

        {
            size_t index = (size_t)(oldTable[i].hash & newMask);

            while (ht->table[index].key != NULL)
                index = (index + 1) & newMask;

            ht->table[index] = oldTable[i];
            ht->size++;
            if (oldTable[i].expireAtMs != 0)
                ht->ttlCount++;
        }
    }

    free(oldTable);
    if (outPruned != NULL)
        *outPruned = pruned;
    return 1;
}

static size_t ht_maybe_shrink(HashTable* ht)
{
    size_t pruned = 0;
    if (ht->capacity > HT_INITIAL_CAPACITY && ht->size * HT_SHRINK_FACTOR < ht->capacity)
    {
        size_t target = ht->capacity / 2;
        if (target < HT_INITIAL_CAPACITY)
            target = HT_INITIAL_CAPACITY;
        (void)ht_resize_to(ht, target, &pruned);
    }
    return pruned;
}

HashTable* ht_create(void)
{
    HashTable* ht = (HashTable*)malloc(sizeof(HashTable));

    if (ht == NULL)
        return NULL;

    ht->capacity = HT_INITIAL_CAPACITY;
    ht->size = 0;
    ht->ttlCount = 0;
    ht->memoryBytes = HT_INITIAL_CAPACITY * sizeof(HashNode);
    ht->maxMemoryBytes = 0;
    ht->sweepCursor = 0;
    generate_hash_seeds(&ht->seed0, &ht->seed1, ht);

    ht->table = (HashNode*)calloc(HT_INITIAL_CAPACITY, sizeof(HashNode));
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
        if (ht->table[i].key != NULL)
        {
            free(ht->table[i].key);
            free(ht->table[i].value);
        }
    }

    free(ht->table);
    free(ht);
}

void ht_set_max_memory(HashTable* ht, size_t maxBytes)
{
    if (ht != NULL)
        ht->maxMemoryBytes = maxBytes;
}

size_t ht_memory_usage(const HashTable* ht)
{
    return ht != NULL ? ht->memoryBytes : 0;
}

int ht_can_fit(const HashTable* ht, const char* key, const char* value)
{
    size_t newValBytes;
    const HashNode* existing;

    if (ht == NULL || key == NULL || value == NULL)
        return 0;
    if (ht->maxMemoryBytes == 0)
        return 1;

    newValBytes = strlen(value) + 1;
    existing = find_node(ht, key);
    if (existing != NULL)
    {
        size_t oldValBytes = strlen(existing->value) + 1;
        if (newValBytes <= oldValBytes)
            return 1;
        return (newValBytes - oldValBytes) <= ht->maxMemoryBytes &&
               ht->memoryBytes <= ht->maxMemoryBytes - (newValBytes - oldValBytes);
    }

    {
        size_t extra = strlen(key) + 1 + newValBytes;
        if ((ht->size + 1) * HT_LOAD_DEN > ht->capacity * HT_LOAD_NUM)
        {
            if (ht->capacity > SIZE_MAX / 2 || (ht->capacity * 2) > SIZE_MAX / sizeof(HashNode))
                return 0;
            extra += ht->capacity * sizeof(HashNode);
        }
        return extra <= ht->maxMemoryBytes && ht->memoryBytes <= ht->maxMemoryBytes - extra;
    }
}

static void apply_node_expiry(HashTable* ht, HashNode* node, long long expireAtMs)
{
    int hadTtl = node->expireAtMs != 0;
    int hasTtl = expireAtMs != 0;

    if (!hadTtl && hasTtl)
        ht->ttlCount++;
    else if (hadTtl && !hasTtl && ht->ttlCount > 0)
        ht->ttlCount--;

    node->expireAtMs = expireAtMs;
}

int ht_insert_ex(HashTable* ht, const char* key, const char* value, long long expireAtMs)
{
    uint64_t h;
    HashNode* existing;
    size_t keyLen;
    size_t valLen;
    size_t mask;
    size_t index;
    char* keyCopy;
    char* valueCopy;

    if (ht == NULL || key == NULL || value == NULL)
        return 0;

    h = hash_key(ht, key);
    existing = find_node_hashed(ht, key, h);
    valLen = strlen(value);

    /* Fast path: update existing slot without triggering an unnecessary resize. */
    if (existing != NULL)
    {
        size_t oldValBytes = strlen(existing->value) + 1;
        size_t newValBytes = valLen + 1;

        if (ht->maxMemoryBytes != 0 && newValBytes > oldValBytes)
        {
            size_t growth = newValBytes - oldValBytes;
            if (growth > ht->maxMemoryBytes || ht->memoryBytes > ht->maxMemoryBytes - growth)
                return 0;
        }

        valueCopy = copy_string_len(value, valLen);
        if (valueCopy == NULL)
            return 0;

        free(existing->value);
        existing->value = valueCopy;
        if (newValBytes >= oldValBytes)
            ht->memoryBytes += (newValBytes - oldValBytes);
        else if (ht->memoryBytes >= (oldValBytes - newValBytes))
            ht->memoryBytes -= (oldValBytes - newValBytes);

        apply_node_expiry(ht, existing, expireAtMs);
        return 1;
    }

    /* New key: check load factor; sweep expired entries before deciding to grow. */
    if ((ht->size + 1) * HT_LOAD_DEN > ht->capacity * HT_LOAD_NUM)
    {
        if (ht->ttlCount > 0)
            ht_sweep_expired(ht);

        if ((ht->size + 1) * HT_LOAD_DEN > ht->capacity * HT_LOAD_NUM)
        {
            if (ht->capacity > SIZE_MAX / 2)
                return 0;
            if (!ht_resize_to(ht, ht->capacity * 2, NULL))
                return 0;
        }
    }

    keyLen = strlen(key);
    {
        size_t needed = (keyLen + 1) + (valLen + 1);
        if (ht->maxMemoryBytes != 0 &&
            (needed > ht->maxMemoryBytes || ht->memoryBytes > ht->maxMemoryBytes - needed))
            return 0;
    }

    keyCopy = copy_string_len(key, keyLen);
    valueCopy = copy_string_len(value, valLen);
    if (keyCopy == NULL || valueCopy == NULL)
    {
        free(keyCopy);
        free(valueCopy);
        return 0;
    }

    mask = ht->capacity - 1;
    index = (size_t)(h & mask);
    while (ht->table[index].key != NULL)
        index = (index + 1) & mask;

    ht->table[index].key = keyCopy;
    ht->table[index].value = valueCopy;
    ht->table[index].hash = h;
    ht->table[index].expireAtMs = expireAtMs;
    ht->size++;
    if (expireAtMs != 0)
        ht->ttlCount++;
    ht->memoryBytes += (keyLen + 1) + (valLen + 1);

    return 1;
}

int ht_insert(HashTable* ht, const char* key, const char* value)
{
    return ht_insert_ex(ht, key, value, 0);
}

int ht_insert_keep_ttl(HashTable* ht, const char* key, const char* value)
{
    HashNode* existing;
    long long expireAtMs = 0;

    if (ht == NULL || key == NULL || value == NULL)
        return 0;

    existing = find_node(ht, key);
    if (existing != NULL && !node_is_expired_now(existing))
        expireAtMs = existing->expireAtMs;

    return ht_insert_ex(ht, key, value, expireAtMs);
}

const char* ht_search_ro(const HashTable* ht, const char* key, int* outExpired)
{
    HashNode* node;

    if (outExpired != NULL)
        *outExpired = 0;

    if (ht == NULL || key == NULL)
        return NULL;

    node = find_node(ht, key);
    if (node == NULL)
        return NULL;

    if (node_is_expired_now(node))
    {
        if (outExpired != NULL)
            *outExpired = 1;
        return NULL;
    }

    return node->value;
}

int ht_get_expiry_ro(const HashTable* ht, const char* key, long long* outExpireAtMs, int* outExpired)
{
    HashNode* node;

    if (outExpired != NULL)
        *outExpired = 0;

    if (ht == NULL || key == NULL)
        return 0;

    node = find_node(ht, key);
    if (node == NULL)
        return 0;

    if (node_is_expired_now(node))
    {
        if (outExpired != NULL)
            *outExpired = 1;
        return 0;
    }

    if (outExpireAtMs != NULL)
        *outExpireAtMs = node->expireAtMs;
    return 1;
}

int ht_exists_ro(const HashTable* ht, const char* key, int* outExpired)
{
    return ht_search_ro(ht, key, outExpired) != NULL;
}

int ht_purge_if_expired(HashTable* ht, const char* key)
{
    HashNode* node;

    if (ht == NULL || key == NULL)
        return 0;

    node = find_node(ht, key);
    if (node == NULL || !node_is_expired_now(node))
        return 0;

    delete_at(ht, (size_t)(node - ht->table));
    ht_maybe_shrink(ht);
    return 1;
}

HashNode* ht_find_live(HashTable* ht, const char* key, long long nowMs)
{
    HashNode* node;

    if (ht == NULL || key == NULL)
        return NULL;

    node = find_node(ht, key);
    if (node == NULL)
        return NULL;

    if (is_expired_at(node, nowMs))
    {
        delete_at(ht, (size_t)(node - ht->table));
        ht_maybe_shrink(ht);
        return NULL;
    }

    return node;
}

void ht_delete_node(HashTable* ht, HashNode* node)
{
    if (ht == NULL || node == NULL)
        return;
    delete_at(ht, (size_t)(node - ht->table));
    ht_maybe_shrink(ht);
}

int ht_update_node_value(HashTable* ht, HashNode* node, const char* value)
{
    size_t oldValBytes;
    size_t newValLen;
    size_t newValBytes;
    char* copy;

    if (ht == NULL || node == NULL || value == NULL)
        return 0;

    oldValBytes = strlen(node->value) + 1;
    newValLen = strlen(value);
    newValBytes = newValLen + 1;

    if (ht->maxMemoryBytes != 0 && newValBytes > oldValBytes)
    {
        size_t growth = newValBytes - oldValBytes;
        if (growth > ht->maxMemoryBytes || ht->memoryBytes > ht->maxMemoryBytes - growth)
            return 0;
    }

    copy = copy_string_len(value, newValLen);
    if (copy == NULL)
        return 0;

    free(node->value);
    node->value = copy;
    if (newValBytes >= oldValBytes)
        ht->memoryBytes += (newValBytes - oldValBytes);
    else if (ht->memoryBytes >= (oldValBytes - newValBytes))
        ht->memoryBytes -= (oldValBytes - newValBytes);

    return 1;
}

void ht_set_node_expiry(HashTable* ht, HashNode* node, long long expireAtMs)
{
    if (ht == NULL || node == NULL)
        return;
    apply_node_expiry(ht, node, expireAtMs);
}

char* ht_search(HashTable* ht, const char* key)
{
    HashNode* node;

    if (ht == NULL || key == NULL)
        return NULL;

    node = find_node(ht, key);
    if (node == NULL)
        return NULL;

    if (node_is_expired_now(node))
    {
        delete_at(ht, (size_t)(node - ht->table));
        ht_maybe_shrink(ht);
        return NULL;
    }

    return node->value;
}

int ht_remove(HashTable* ht, const char* key)
{
    HashNode* node;

    if (ht == NULL || key == NULL)
        return 0;

    node = find_node(ht, key);
    if (node == NULL)
        return 0;

    if (node_is_expired_now(node))
    {
        delete_at(ht, (size_t)(node - ht->table));
        ht_maybe_shrink(ht);
        return 0;
    }

    delete_at(ht, (size_t)(node - ht->table));
    ht_maybe_shrink(ht);
    return 1;
}

int ht_set_expiry(HashTable* ht, const char* key, long long expireAtMs)
{
    HashNode* node;

    if (ht == NULL || key == NULL)
        return 0;

    node = find_node(ht, key);
    if (node == NULL)
        return 0;

    if (node_is_expired_now(node))
    {
        delete_at(ht, (size_t)(node - ht->table));
        ht_maybe_shrink(ht);
        return 0;
    }

    apply_node_expiry(ht, node, expireAtMs);
    return 1;
}

int ht_persist(HashTable* ht, const char* key)
{
    HashNode* node;

    if (ht == NULL || key == NULL)
        return 0;

    node = find_node(ht, key);
    if (node == NULL)
        return 0;

    if (node_is_expired_now(node))
    {
        delete_at(ht, (size_t)(node - ht->table));
        ht_maybe_shrink(ht);
        return 0;
    }

    if (node->expireAtMs == 0)
        return 0;

    apply_node_expiry(ht, node, 0);
    return 1;
}

int ht_get_expiry(HashTable* ht, const char* key, long long* outExpireAtMs)
{
    HashNode* node;

    if (ht == NULL || key == NULL)
        return 0;

    node = find_node(ht, key);
    if (node == NULL)
        return 0;

    if (node_is_expired_now(node))
    {
        delete_at(ht, (size_t)(node - ht->table));
        ht_maybe_shrink(ht);
        return 0;
    }

    if (outExpireAtMs != NULL)
        *outExpireAtMs = node->expireAtMs;

    return 1;
}

size_t ht_sweep_expired(HashTable* ht)
{
    long long now;
    size_t removed = 0;
    size_t i = 0;

    if (ht == NULL || ht->ttlCount == 0)
        return 0;

    now = ht_current_time_ms();
    while (i < ht->capacity)
    {
        if (ht->table[i].key != NULL && is_expired_at(&ht->table[i], now))
        {
            delete_at(ht, i);
            ++removed;
            if (ht->ttlCount == 0)
                break;
            continue;
        }
        ++i;
    }

    if (removed > 0)
        removed += ht_maybe_shrink(ht);

    return removed;
}

size_t ht_sweep_step(HashTable* ht, size_t maxBuckets)
{
    long long now;
    size_t removed = 0;
    size_t scanned = 0;
    size_t limit;

    if (ht == NULL || ht->ttlCount == 0 || maxBuckets == 0)
        return 0;

    limit = maxBuckets < ht->capacity ? maxBuckets : ht->capacity;
    if (ht->sweepCursor >= ht->capacity)
        ht->sweepCursor = 0;

    now = ht_current_time_ms();
    while (scanned < limit && ht->ttlCount > 0)
    {
        size_t idx = ht->sweepCursor;
        if (ht->table[idx].key != NULL && is_expired_at(&ht->table[idx], now))
        {
            delete_at(ht, idx);
            ++removed;
            ++scanned;
            continue;
        }
        ht->sweepCursor = (idx + 1) & (ht->capacity - 1);
        ++scanned;
    }

    if (removed > 0)
        removed += ht_maybe_shrink(ht);

    return removed;
}

int ht_exists(HashTable* ht, const char* key)
{
    return ht_search(ht, key) != NULL;
}

size_t ht_count(const HashTable* ht)
{
    long long now;
    size_t count = 0;
    size_t i;

    if (ht == NULL)
        return 0;

    if (ht->ttlCount == 0)
        return ht->size;

    now = ht_current_time_ms();
    for (i = 0; i < ht->capacity; i++)
    {
        if (ht->table[i].key != NULL && !is_expired_at(&ht->table[i], now))
            count++;
    }

    return count;
}

void ht_clear(HashTable* ht)
{
    size_t i;

    if (ht == NULL)
        return;

    for (i = 0; i < ht->capacity; i++)
    {
        if (ht->table[i].key != NULL)
        {
            free(ht->table[i].key);
            free(ht->table[i].value);
            ht->table[i].key = NULL;
            ht->table[i].value = NULL;
            ht->table[i].hash = 0;
            ht->table[i].expireAtMs = 0;
        }
    }

    ht->size = 0;
    ht->ttlCount = 0;
    ht->sweepCursor = 0;

    if (ht->capacity > HT_INITIAL_CAPACITY)
    {
        HashNode* smallTable = (HashNode*)calloc(HT_INITIAL_CAPACITY, sizeof(HashNode));
        if (smallTable != NULL)
        {
            free(ht->table);
            ht->table = smallTable;
            ht->capacity = HT_INITIAL_CAPACITY;
        }
    }

    ht->memoryBytes = ht->capacity * sizeof(HashNode);
}

void ht_for_each(const HashTable* ht, HtVisitor callback, void* userData)
{
    long long now = 0;
    int checkExpiry;
    size_t i;

    if (ht == NULL || callback == NULL)
        return;

    checkExpiry = ht->ttlCount > 0;
    if (checkExpiry)
        now = ht_current_time_ms();

    for (i = 0; i < ht->capacity; i++)
    {
        if (ht->table[i].key != NULL && (!checkExpiry || !is_expired_at(&ht->table[i], now)))
            callback(ht->table[i].key, ht->table[i].value, ht->table[i].expireAtMs, userData);
    }
}

void ht_print(const HashTable* ht)
{
    size_t i;
    long long now;

    if (ht == NULL)
        return;

    now = ht_current_time_ms();
    printf("\nHash Table\n");
    printf("-----------------------\n");

    for (i = 0; i < ht->capacity; i++)
    {
        if (ht->table[i].key == NULL)
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
