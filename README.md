# kvstore

A small, persistent key-value store server written in C for Windows, speaking
a subset of the Redis wire protocol (RESP) over plain TCP.

The server stores string keys and values in an in-memory hash table. It also
writes changes to a binary-safe, RESP-framed append-only log so data is restored
when the server starts again.

## Features

- Plain TCP server using Winsock — speaks RESP, the same wire protocol Redis
  uses, so standard tools like `redis-cli` can connect directly
- Also accepts simple inline commands (plain text lines), so `telnet`/`nc`
  work too, for quick manual testing
- Bounded multi-threaded server with `TCP_NODELAY`, buffered response batching,
  and pipelining support
- Reader-writer lock (`SRWLOCK`) for parallel reads (`GET`, `EXISTS`, `TTL`,
  `DBSIZE`) and serialized writes
- Supported commands: `SET`, `SETEX`, `GET`, `DEL`, `EXISTS`, `INCR`, `DECR`, `INCRBY`, `EXPIRE`, `TTL`, `PERSIST`, `DBSIZE`, `FLUSHDB`, `FLUSHALL`, `PING`, `AUTH`, and `QUIT`
- Key expiration (TTL): both lazy (checked on access) and active (incremental
  background sweeps every second, skipped in O(1) when no TTLs are set)
- In-memory hash table with per-process randomly seeded SipHash-1-3 (hash-flood
  resistant), cached hashes, open addressing, backward-shift deletion,
  sub-millisecond timer resolution (`GetSystemTimePreciseAsFileTime`), automatic
  resizing & shrinking, and configurable memory limits
- Binary-safe, RESP-framed append-only persistence log (`kvstore.aof` by
  default) with configurable fsync policies (`everysec`, `always`, `no`),
  automatic runtime & startup compaction, and backward-compatible loading of
  legacy text logs
- Security hardening: binds to `127.0.0.1` by default with
  `SO_EXCLUSIVEADDRUSE`, constant-time `AUTH` comparison with brute-force
  throttling, Slowloris command-deadline timeouts, and strict input/overflow
  validation
- Graceful shutdown handling (`Ctrl+C` / console close) that drains and joins
  all worker and background threads cleanly

## Build

Build with MinGW GCC / Clang:

```powershell
gcc -std=c11 -Wall -Wextra -Werror main.c hashtable.c persistence.c -o output\kvstore.exe -lws2_32
```

Or build with MSVC (x64 Native Tools Command Prompt):

```powershell
cl /nologo /std:c11 /W4 /WX /O2 /Fe:output\kvstore.exe main.c hashtable.c persistence.c /link Ws2_32.lib
```

## Run

Start the server with its default bind address (`127.0.0.1`), port (`6379`),
and data file (`kvstore.aof`):

```powershell
.\output\kvstore.exe
```

You may pass flags or legacy positional arguments (`[port] [dataFile] [authPassword]`):

```powershell
.\output\kvstore.exe --bind 127.0.0.1 --port 6380 --data mydata.aof --fsync everysec
```

### CLI Options & Environment Variables

| Option                  | Environment Variable | Default       | Description                                               |
|-------------------------|----------------------|---------------|-----------------------------------------------------------|
| `--bind <host>`         | `KVSTORE_BIND`       | `127.0.0.1`   | Bind address (`0.0.0.0` to listen on all interfaces)      |
| `--port <port>`         | —                    | `6379`        | TCP listening port                                        |
| `--data <file>`         | —                    | `kvstore.aof` | Append-only persistence file path                         |
| `--password-file <file>`| `KVSTORE_PASSWORD`   | disabled      | Password for `AUTH` (reads first line from file)          |
| `--fsync <mode>`        | `KVSTORE_FSYNC`      | `everysec`    | Disk sync mode: `always`, `everysec`, or `no`             |
| `--max-clients <n>`     | —                    | `256`         | Maximum concurrent client connections (`1..10000`)        |
| `--max-memory <mb>`     | —                    | `256`         | Maximum tracked heap memory in MB (`0` = unlimited)       |
| `--max-aof-mb <mb>`     | —                    | `512`         | Maximum AOF file size in MB (`0` = unlimited)             |

### Authentication

Set `KVSTORE_PASSWORD` or pass `--password-file` to require a password for
every new connection (preferred over passing the password as a positional
argument, which exposes it in process lists):

```powershell
$env:KVSTORE_PASSWORD = "my-secret-password"
.\output\kvstore.exe --port 6379 --data kvstore.aof
```

When a password is configured, clients must authenticate with `AUTH` before
using any command other than `QUIT`. Failed attempts are throttled and the
connection is closed after 5 consecutive failures. Example:

```powershell
redis-cli -p 6379 -a my-secret-password SET name Alice
```

Traffic is sent in plain text over TCP; use loopback binding (`127.0.0.1`) or a
TLS tunnel/proxy on untrusted networks.

## Protocol

The server listens on a plain TCP socket and speaks
[RESP](https://redis.io/docs/latest/develop/reference/protocol-spec/), the
same wire protocol real Redis uses for commands and replies:

```powershell
redis-cli -p 6379 PING
redis-cli -p 6379 SET name Alice
redis-cli -p 6379 GET name
redis-cli -p 6379 EXISTS name
redis-cli -p 6379 DEL name
```

### Supported Commands

```text
PING
AUTH <password>
GET <key>
SET <key> <value> [EX <seconds>]
SETEX <key> <seconds> <value>
DEL <key>
EXISTS <key>
INCR <key>
DECR <key>
INCRBY <key> <delta>
EXPIRE <key> <seconds>
TTL <key>
PERSIST <key>
DBSIZE
FLUSHDB / FLUSHALL
COMMAND / COMMAND DOCS
CLIENT ...
QUIT
```

Commands are case-insensitive (`get`, `Get`, and `GET` are treated identically).
Via RESP, keys and values are length-prefixed and may safely contain spaces or
newlines (embedded NUL bytes are rejected).

### Key expiration

`EXPIRE` and `TTL` work the same way they do in Redis:

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
- A plain `SET` on an existing key clears any TTL it had; `INCR`/`DECR`/`INCRBY`
  preserve any existing TTL both in memory and in the AOF.

### Inline commands (telnet/nc)

For quick manual testing without a Redis client, the server also accepts
plain, newline-terminated inline commands:

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

| Reply              | Meaning                                                                             |
|--------------------|-------------------------------------------------------------------------------------|
| `+OK`              | Simple success                                                                      |
| `+PONG`            | Reply to `PING`                                                                     |
| `$<len>\r\n<data>` | Bulk string, e.g. the value from a `GET`                                            |
| `$-1`              | Nil — key not found                                                                 |
| `:0` / `:1`        | Integer — e.g. keys removed by `DEL`, or whether `EXPIRE`/`PERSIST` changed a key   |
| `:<n>`             | Integer — remaining TTL in seconds from `TTL` (`-1` no TTL, `-2` no such key)       |
| `-ERR <message>`   | Error, e.g. unknown command, integer overflow, memory limit, or auth failure        |

## Concurrency and persistence

Read commands (`GET`, `EXISTS`, `TTL`, `DBSIZE`) acquire a shared reader lock
(`SRWLOCK`), allowing concurrent reads in parallel. Write commands acquire the
exclusive lock and append length-prefixed RESP records to the binary AOF file.

- **`everysec` (default):** Each write flushes immediately to the OS page cache,
  and the background thread calls `_commit` (`FlushFileBuffers`) once per second
  outside the store lock whenever dirty writes exist.
- **`always`:** Each write commits synchronously to physical disk before
  replying.
- **`no`:** Writes flush to the OS page cache and commit on clean shutdown.

`EXPIRE` logs an absolute Unix timestamp in milliseconds, so TTLs remain
accurate across restarts.

### Compaction

Compaction rewrites the AOF to the minimal set of live RESP records into an
exclusively created temporary file (`CREATE_NEW`), flushes and commits it to
disk, and atomically swaps it in with `MoveFileExA(..., MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)`. Compaction runs on startup when
replaying an existing log (automatically upgrading legacy text logs to RESP
framing) and automatically at runtime once the AOF grows past 64 MB and doubles
from its last compacted size.

## Project files

- `main.c` — TCP/RESP server, connection registry, buffered I/O, command
  parsing, authentication throttling, and background maintenance thread
- `hashtable.c` — SipHash-1-3 open-addressing hash table with cached hashes,
  backward-shift deletion, incremental expiry sweeps, memory caps, and shrinking
- `persistence.c` — Binary-safe RESP-framed AOF writer, legacy-compatible
  loader, fsync policies, and atomic compaction
- `Header/hashtable.h` — Hash table interface
- `Header/persistence.h` — Persistence interface
