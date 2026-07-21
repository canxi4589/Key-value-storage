# kvstore

A small, persistent key-value store server written in C for Windows.

The server stores string keys and values in an in-memory hash table. It also
writes changes to an append-only log so data is restored when the server starts
again.

## Features

- TCP server using Winsock
- One client handled at a time
- `SET`, `GET`, and `DEL` commands
- In-memory hash table with automatic resizing
- Append-only persistence log (`kvstore.aof` by default)

## Build

Build with MinGW GCC:

```powershell
gcc -std=c11 -Wall -Wextra -Werror main.c hashtable.c -o output\kvstore.exe -lws2_32
```

## Run

Start the server with its default port (`6379`) and data file (`kvstore.aof`):

```powershell
.\output\kvstore.exe
```

You may provide a port and persistence-file path:

```powershell
.\output\kvstore.exe 6380 mydata.aof
```

## Protocol

Connect with a TCP client such as `telnet`, `nc`, or your own application. Send
one command per line.

```text
PING
SET name Alice
GET name
DEL name
QUIT
```

Example responses:

```text
PONG
OK
VALUE Alice
NOT_FOUND
BYE
```

Keys cannot contain spaces. Values may contain spaces, but cannot contain a
newline.

## Persistence

Each successful `SET` or `DEL` operation is appended to the data file and
flushed to disk. On startup, the server replays this log to rebuild the hash
table.

The log grows over time. A future improvement is log compaction: write the
current contents to a smaller replacement file.

## Project files

- `main.c` — TCP server, command parsing, and persistence handling
- `hashtable.c` — hash table implementation
- `Header/hashtable.h` — hash table interface
