# kvstore

A small, persistent key-value store server written in C for Windows, speaking
a subset of the Redis wire protocol (RESP) over plain TCP.

The server stores string keys and values in an in-memory hash table. It also
writes changes to an append-only log so data is restored when the server starts
again.

## Features

- Plain TCP server using Winsock — speaks RESP, the same wire protocol Redis
  uses, so standard tools like `redis-cli` can connect directly
- Also accepts simple inline commands (plain text lines), so `telnet`/`nc`
  work too, for quick manual testing
- Thread-per-connection: each client is handled on its own thread, so
  multiple clients can be connected and issuing commands at the same time
- A mutex guards the shared hash table and the data file, so concurrent
  `SET`/`GET`/`DEL` calls from different clients don't race
- `SET`, `GET`, `DEL`, `EXPIRE`, `TTL`, and `PERSIST` commands
- Key expiration (TTL): both lazy (checked on access) and active (a
  background thread sweeps expired keys every second)
- In-memory hash table with automatic resizing
- Append-only persistence log (`kvstore.aof` by default)
- AOF compaction: the log is rewritten to its minimal form on startup, so
  redundant history and expired keys don't make every restart slower

## Build

Build with MinGW GCC:

```powershell
gcc -std=c11 -Wall -Wextra -Werror main.c hashtable.c persistence.c -o output\kvstore.exe -lws2_32
```

> Note: the server uses `_beginthreadex`, which requires linking the
> multithreaded C runtime. This is the default with MinGW GCC and with
> modern MSVC project templates — only worth double-checking if you're
> building from an older `.vcxproj`.

## Run

Start the server with its default port (`6379`) and data file (`kvstore.aof`):

```powershell
.\output\kvstore.exe
```

You may provide a port and persistence-file path:

```powershell
.\output\kvstore.exe 6380 mydata.aof
```

### Authentication

Pass a third argument to require a password for every new connection:

```powershell
.\output\kvstore.exe 6379 kvstore.aof my-secret-password
```

When a password is configured, clients must authenticate with `AUTH` before
using any data command. `QUIT` is always allowed. For example:

```powershell
redis-cli -p 6379 -a my-secret-password SET name Alice
```

The password and all traffic are sent in plain text. This is a lightweight
access gate for trusted networks, not a replacement for TLS or production
authentication controls. Omit the third argument to leave authentication off.

## Protocol

The server listens on a plain TCP socket and speaks
[RESP](https://redis.io/docs/latest/develop/reference/protocol-spec/), the
same wire protocol real Redis uses for commands and replies. This means
standard Redis client libraries and `redis-cli` can talk to it directly:

```powershell
redis-cli -p 6379 PING
redis-cli -p 6379 SET name Alice
redis-cli -p 6379 GET name
redis-cli -p 6379 DEL name
```

Only a small command set is implemented — anything outside this list returns
a RESP error:

```text
PING
AUTH <password>
GET <key>
SET <key> <value>
DEL <key>
EXPIRE <key> <seconds>
TTL <key>
PERSIST <key>
QUIT
```

Commands are case-insensitive (`get`, `Get`, and `GET` are all treated the
same way). Keys cannot contain spaces. Values may contain spaces, but not a
newline.

### Key expiration

`EXPIRE` and `TTL` work the same way they do in real Redis:

```powershell
redis-cli -p 6379 SET session abc123
redis-cli -p 6379 EXPIRE session 60
redis-cli -p 6379 TTL session
# (integer) 60
```

- `EXPIRE <key> <seconds>` sets an expiration. Returns `1` if the key
  existed and the timeout was set, `0` if the key doesn't exist.
- `TTL <key>` returns the remaining time to live in seconds: a positive
  number if a TTL is set, `-1` if the key exists but has no TTL, or `-2` if
  the key doesn't exist (or has already expired).
- `PERSIST <key>` removes any TTL from a key, making it live forever until
  explicitly deleted. Returns `1` if a TTL was removed, `0` otherwise.
- A plain `SET` on an existing key clears any TTL it had, matching Redis's
  default `SET` behavior.

Expired keys are removed two ways: lazily, the moment any command next
touches that key, and actively, by a background thread that sweeps the
whole table once a second. Either way, a key past its expiration is
treated as if it were already deleted.

### Inline commands (telnet/nc)

For quick manual testing without a Redis client, the server also accepts
plain, newline-terminated commands — this is the same "inline command"
fallback real Redis supports:

```powershell
telnet localhost 6379
```

```text
PING
SET name Alice
GET name
EXPIRE name 30
TTL name
DEL name
QUIT
```

### Replies

Replies follow standard RESP types:

| Reply             | Meaning                                            |
|--------------------|-----------------------------------------------------|
| `+OK`              | Simple success                                      |
| `+PONG`            | Reply to `PING`                                     |
| `$<len>\r\n<data>` | Bulk string, e.g. the value from a `GET`            |
| `$-1`              | Nil — key not found                                 |
| `:0` / `:1`        | Integer — e.g. keys removed by `DEL`, or whether `EXPIRE`/`PERSIST` changed something |
| `:<n>`             | Integer — remaining TTL in seconds from `TTL` (`-1` no TTL, `-2` no such key) |
| `-ERR <message>`   | Error, e.g. an unknown or malformed command         |

## Concurrency and persistence

Each connected client is served on its own thread. A single mutex protects
all access to the in-memory hash table and the append-only data file, so
commands from different clients are applied one at a time and never
interleave or corrupt shared state — but they can run concurrently rather
than queuing behind one client's entire connection.

Each successful `SET`, `DEL`, `EXPIRE`, or `PERSIST` operation is appended to
the data file and flushed to disk before the reply is sent. On startup, the
server replays this log to rebuild the hash table.

`EXPIRE` logs an absolute timestamp (milliseconds since the Unix epoch), not
a relative offset — so a TTL set before a restart still expires at the
correct real-world time afterward, no matter how long the server was down.

Keys removed by the background expiration sweep are *not* individually
logged. Since expiry timestamps are absolute, replaying the log after a
restart reconstructs the key with that same already-past timestamp, and it's
cleaned up again within a second regardless — so skipping that log write is
free.

### Compaction

The log only ever grows from appends, so it can accumulate a lot of
redundant history — repeated `SET`s to the same key, or entries for keys
that were later deleted or have since expired. On startup, right after the
log is replayed, the server rewrites it down to the minimal set of commands
needed to reconstruct the *current* state: one `SET` (plus an `EXPIRE` if
the key has a TTL) per live key, with expired or deleted keys dropped
entirely.

The rewrite is written to a temporary file first and only swapped in with an
atomic rename once it's fully flushed to disk, so a crash mid-compaction
can't corrupt or lose the existing log — it's always either the old log or
the fully-written new one, never something in between.

## Project files

- `main.c` — TCP/RESP server, connection handling, command parsing, and
  the background expiration sweep thread
- `hashtable.c` — hash table implementation, including TTL/expiry logic
- `persistence.c` — append-only log writing, replay, and compaction
- `Header/hashtable.h` — hash table interface
- `Header/persistence.h` — persistence interface
