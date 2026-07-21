
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

static int send_text(SOCKET client, const char* text)
{
    size_t remaining = strlen(text);
    const char* cursor = text;

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
    size_t length = 0;
    char ch;

    send_text(client, "KVSTORE ready. Commands: PING, GET, SET, DEL, QUIT\n");
    while (recv(client, &ch, 1, 0) == 1)
    {
        if (ch == '\n')
        {
            int quitRequested;

            line[length] = '\0';
            if (length > 0 && line[length - 1] == '\r')
                line[--length] = '\0';
            quitRequested = strcmp(line, "QUIT") == 0;
            handle_line(client, store, dataFile, line);
            if (quitRequested)
                break;
            length = 0;
        }
        else if (length + 1 < sizeof(line))
        {
            line[length++] = ch;
        }
        else
        {
            send_text(client, "ERROR command too long\n");
            length = 0;
        }
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
