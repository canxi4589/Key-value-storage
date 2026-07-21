
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <io.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "Header/hashtable.h"

#ifdef _MSC_VER
#pragma comment(lib, "Ws2_32.lib")
#endif

#define DEFAULT_PORT "6379"
#define DEFAULT_DATA_FILE "kvstore.aof"
#define MAX_LINE 4096
#define MAX_HTTP_REQUEST 8192

static int send_raw(SOCKET client, const char* data, size_t length)
{
    size_t remaining = length;
    const char* cursor = data;

    while (remaining > 0)
    {
        int sent = send(client, cursor, (int)remaining, 0);
        if (sent == SOCKET_ERROR || sent == 0)
            return 0;
        cursor += sent;
        remaining -= (size_t)sent;
    }
    return 1;
}

static int recv_exact(SOCKET client, void* buffer, size_t length)
{
    char* cursor = buffer;
    size_t remaining = length;

    while (remaining > 0)
    {
        int received = recv(client, cursor, (int)remaining, 0);
        if (received <= 0)
            return 0;
        cursor += received;
        remaining -= (size_t)received;
    }
    return 1;
}

static void sha1(const unsigned char* input, size_t length, unsigned char digest[20])
{
    unsigned int h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE;
    unsigned int h3 = 0x10325476, h4 = 0xC3D2E1F0;
    unsigned char padded[128] = { 0 };
    size_t paddedLength = ((length + 9 + 63) / 64) * 64;
    unsigned long long bits = (unsigned long long)length * 8;

    /* This server only hashes the short WebSocket handshake value. */
    memcpy(padded, input, length);
    padded[length] = 0x80;
    for (int i = 0; i < 8; ++i)
        padded[paddedLength - 1 - i] = (unsigned char)(bits >> (i * 8));

    for (size_t offset = 0; offset < paddedLength; offset += 64)
    {
        unsigned int w[80];
        unsigned int a, b, c, d, e;

        for (int i = 0; i < 16; ++i)
            w[i] = ((unsigned int)padded[offset + i * 4] << 24) |
                   ((unsigned int)padded[offset + i * 4 + 1] << 16) |
                   ((unsigned int)padded[offset + i * 4 + 2] << 8) |
                   padded[offset + i * 4 + 3];
        for (int i = 16; i < 80; ++i)
        {
            unsigned int x = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
            w[i] = (x << 1) | (x >> 31);
        }
        a = h0; b = h1; c = h2; d = h3; e = h4;
        for (int i = 0; i < 80; ++i)
        {
            unsigned int f, k, temp;
            if (i < 20) { f = (b & c) | ((~b) & d); k = 0x5A827999; }
            else if (i < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1; }
            else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
            else { f = b ^ c ^ d; k = 0xCA62C1D6; }
            temp = ((a << 5) | (a >> 27)) + f + e + k + w[i];
            e = d; d = c; c = (b << 30) | (b >> 2); b = a; a = temp;
        }
        h0 += a; h1 += b; h2 += c; h3 += d; h4 += e;
    }
    digest[0] = (unsigned char)(h0 >> 24); digest[1] = (unsigned char)(h0 >> 16);
    digest[2] = (unsigned char)(h0 >> 8);  digest[3] = (unsigned char)h0;
    digest[4] = (unsigned char)(h1 >> 24); digest[5] = (unsigned char)(h1 >> 16);
    digest[6] = (unsigned char)(h1 >> 8);  digest[7] = (unsigned char)h1;
    digest[8] = (unsigned char)(h2 >> 24); digest[9] = (unsigned char)(h2 >> 16);
    digest[10] = (unsigned char)(h2 >> 8); digest[11] = (unsigned char)h2;
    digest[12] = (unsigned char)(h3 >> 24); digest[13] = (unsigned char)(h3 >> 16);
    digest[14] = (unsigned char)(h3 >> 8); digest[15] = (unsigned char)h3;
    digest[16] = (unsigned char)(h4 >> 24); digest[17] = (unsigned char)(h4 >> 16);
    digest[18] = (unsigned char)(h4 >> 8); digest[19] = (unsigned char)h4;
}

static void base64_encode(const unsigned char* input, size_t length, char* output)
{
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t in = 0, out = 0;

    while (in < length)
    {
        unsigned int value = (unsigned int)input[in++] << 16;
        int haveSecond = in < length;
        int haveThird;
        if (haveSecond) value |= (unsigned int)input[in++] << 8;
        haveThird = in < length;
        if (haveThird) value |= input[in++];
        output[out++] = alphabet[(value >> 18) & 63];
        output[out++] = alphabet[(value >> 12) & 63];
        output[out++] = haveSecond ? alphabet[(value >> 6) & 63] : '=';
        output[out++] = haveThird ? alphabet[value & 63] : '=';
    }
    output[out] = '\0';
}

static int send_websocket_frame(SOCKET client, unsigned char opcode, const char* data, size_t length)
{
    unsigned char header[4];
    size_t headerLength = 2;

    if (length > MAX_LINE || length > 65535)
        return 0;
    header[0] = 0x80 | opcode;
    if (length < 126)
        header[1] = (unsigned char)length;
    else
    {
        header[1] = 126;
        header[2] = (unsigned char)(length >> 8);
        header[3] = (unsigned char)length;
        headerLength = 4;
    }
    return send_raw(client, (const char*)header, headerLength) && send_raw(client, data, length);
}

static int send_text(SOCKET client, const char* text)
{
    return send_websocket_frame(client, 0x1, text, strlen(text));
}

static int websocket_handshake(SOCKET client)
{
    char request[MAX_HTTP_REQUEST + 1];
    size_t length = 0;
    char ch;
    char* keyStart;
    char* keyEnd;
    char source[128];
    unsigned char digest[20];
    char acceptKey[32];
    char response[256];
    const char* magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

    while (length < MAX_HTTP_REQUEST && recv(client, &ch, 1, 0) == 1)
    {
        request[length++] = ch;
        if (length >= 4 && memcmp(request + length - 4, "\r\n\r\n", 4) == 0)
            break;
    }
    request[length] = '\0';
    keyStart = strstr(request, "Sec-WebSocket-Key:");
    if (strncmp(request, "GET ", 4) != 0 || keyStart == NULL)
        return 0;
    keyStart += strlen("Sec-WebSocket-Key:");
    while (*keyStart == ' ' || *keyStart == '\t') ++keyStart;
    keyEnd = strpbrk(keyStart, "\r\n");
    if (keyEnd == NULL || (size_t)(keyEnd - keyStart) + strlen(magic) >= 120)
        return 0;
    memcpy(source, keyStart, (size_t)(keyEnd - keyStart));
    strcpy(source + (keyEnd - keyStart), magic);
    sha1((const unsigned char*)source, strlen(source), digest);
    base64_encode(digest, sizeof(digest), acceptKey);
    snprintf(response, sizeof(response),
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: %s\r\n\r\n", acceptKey);
    return send_raw(client, response, strlen(response));
}

static int receive_websocket_text(SOCKET client, char* output, size_t outputSize,
                                  unsigned char* opcode)
{
    unsigned char header[2], mask[4];
    size_t length;

    if (!recv_exact(client, header, sizeof(header)) || (header[0] & 0x80) == 0 ||
        (header[1] & 0x80) == 0)
        return 0;
    *opcode = header[0] & 0x0F;
    length = header[1] & 0x7F;
    if (length == 126)
    {
        unsigned char extended[2];
        if (!recv_exact(client, extended, sizeof(extended))) return 0;
        length = ((size_t)extended[0] << 8) | extended[1];
    }
    else if (length == 127)
        return 0; /* This small server intentionally caps messages at 4 KiB. */
    if (length >= outputSize || !recv_exact(client, mask, sizeof(mask)) ||
        !recv_exact(client, output, length))
        return 0;
    for (size_t i = 0; i < length; ++i)
        output[i] ^= mask[i % 4];
    output[length] = '\0';
    return 1;
}

static int valid_key(const char* key)
{
    return key != NULL && *key != '\0' && strpbrk(key, " \t\r\n") == NULL;
}

static int append_command(const char* dataFile, const char* command, const char* key,
                          const char* value)
{
    FILE* file = fopen(dataFile, "a");
    if (file == NULL)
        return 0;

    int ok = value == NULL
        ? fprintf(file, "%s %s\n", command, key) > 0
        : fprintf(file, "%s %s %s\n", command, key, value) > 0;

    if (ok && fflush(file) != 0)
        ok = 0;
    if (ok && _commit(_fileno(file)) != 0)
        ok = 0;

    fclose(file);
    return ok;
}

static void apply_command(HashTable* store, char* line)
{
    char* command = strtok(line, " \t");
    char* key = strtok(NULL, " \t");
    char* value = strtok(NULL, "");

    if (command == NULL || key == NULL)
        return;
    if (strcmp(command, "SET") == 0 && value != NULL)
        ht_insert(store, key, value);
    else if (strcmp(command, "DEL") == 0 && value == NULL)
        ht_remove(store, key);
}

static int load_data(HashTable* store, const char* dataFile)
{
    FILE* file = fopen(dataFile, "r");
    char line[MAX_LINE];

    if (file == NULL)
        return 1; /* No data file yet is normal. */

    while (fgets(line, sizeof(line), file) != NULL)
    {
        line[strcspn(line, "\r\n")] = '\0';
        apply_command(store, line);
    }

    fclose(file);
    return 1;
}

static void handle_line(SOCKET client, HashTable* store, const char* dataFile, char* line)
{
    char* command = strtok(line, " \t");
    char* key = strtok(NULL, " \t");
    char* value = strtok(NULL, "");

    if (command == NULL)
        return;
    if (strcmp(command, "PING") == 0 && key == NULL)
    {
        send_text(client, "PONG\n");
    }
    else if (strcmp(command, "GET") == 0 && valid_key(key) && value == NULL)
    {
        char* found = ht_search(store, key);
        if (found == NULL)
            send_text(client, "NOT_FOUND\n");
        else
        {
            char response[MAX_LINE + 16];
            snprintf(response, sizeof(response), "VALUE %s\n", found);
            send_text(client, response);
        }
    }
    else if (strcmp(command, "SET") == 0 && valid_key(key) && value != NULL && *value != '\0')
    {
        if (!ht_insert(store, key, value))
            send_text(client, "ERROR out of memory\n");
        else if (!append_command(dataFile, "SET", key, value))
            send_text(client, "ERROR could not persist value\n");
        else
            send_text(client, "OK\n");
    }
    else if (strcmp(command, "DEL") == 0 && valid_key(key) && value == NULL)
    {
        if (ht_search(store, key) == NULL)
            send_text(client, "NOT_FOUND\n");
        else if (!append_command(dataFile, "DEL", key, NULL))
            send_text(client, "ERROR could not persist deletion\n");
        else
        {
            ht_remove(store, key);
            send_text(client, "OK\n");
        }
    }
    else if (strcmp(command, "QUIT") == 0 && key == NULL)
    {
        send_text(client, "BYE\n");
    }
    else
    {
        send_text(client, "ERROR commands: PING, GET <key>, SET <key> <value>, DEL <key>, QUIT\n");
    }
}

static void serve_client(SOCKET client, HashTable* store, const char* dataFile)
{
    char line[MAX_LINE];

    if (!websocket_handshake(client))
        return;

    send_text(client, "KVSTORE ready. Commands: PING, GET, SET, DEL, QUIT");
    for (;;)
    {
        unsigned char opcode;

        if (!receive_websocket_text(client, line, sizeof(line), &opcode))
            break;
        if (opcode == 0x8) /* Close */
        {
            send_websocket_frame(client, 0x8, "", 0);
            break;
        }
        if (opcode == 0x9) /* Ping */
        {
            send_websocket_frame(client, 0xA, line, strlen(line));
            continue;
        }
        if (opcode == 0x1) /* Text */
        {
            int quitRequested = strcmp(line, "QUIT") == 0;
            handle_line(client, store, dataFile, line);
            if (quitRequested)
                break;
        }
        else
            send_text(client, "ERROR text WebSocket messages are required");
    }
}

int main(int argc, char* argv[])
{
    const char* port = argc > 1 ? argv[1] : DEFAULT_PORT;
    const char* dataFile = argc > 2 ? argv[2] : DEFAULT_DATA_FILE;
    WSADATA wsa;
    struct addrinfo hints = { 0 };
    struct addrinfo* address = NULL;
    SOCKET listener = INVALID_SOCKET;
    HashTable* store = ht_create();

    if (store == NULL || !load_data(store, dataFile))
    {
        fprintf(stderr, "Could not initialize store.\n");
        ht_destroy(store);
        return 1;
    }
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
    {
        fprintf(stderr, "WSAStartup failed.\n");
        ht_destroy(store);
        return 1;
    }

    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;
    if (getaddrinfo(NULL, port, &hints, &address) != 0 ||
        (listener = socket(address->ai_family, address->ai_socktype, address->ai_protocol)) == INVALID_SOCKET ||
        bind(listener, address->ai_addr, (int)address->ai_addrlen) == SOCKET_ERROR ||
        listen(listener, SOMAXCONN) == SOCKET_ERROR)
    {
        fprintf(stderr, "Could not listen on port %s.\n", port);
        if (address != NULL) freeaddrinfo(address);
        if (listener != INVALID_SOCKET) closesocket(listener);
        WSACleanup();
        ht_destroy(store);
        return 1;
    }
    freeaddrinfo(address);

    printf("kvstore listening on port %s; data file: %s\n", port, dataFile);
    for (;;)
    {
        SOCKET client = accept(listener, NULL, NULL);
        if (client != INVALID_SOCKET)
        {
            serve_client(client, store, dataFile);
            closesocket(client);
        }
    }
}
