# shadowtls-cpp

C++ port of [shadow-tls](https://github.com/ihciah/shadow-tls) — a proxy that exposes real TLS handshake to the firewall.

**Builds with 3 dependencies:** OpenSSL, pthread, libstdc++. No Boost, no async frameworks.

## Build

```bash
cmake -B build && cmake --build build
```

### Pre-built binaries

Download from [Releases](https://github.com/MaurerAnton/shadowtls-cpp/releases):

| Target | |
|--------|---|
| `x86_64-unknown-linux-gnu` | Linux x86_64 (glibc) |
| `x86_64-unknown-linux-musl` | Linux x86_64 (static) |
| `i686-unknown-linux-musl` | Linux i686 32-bit (static) |
| `aarch64-unknown-linux-musl` | Linux ARM64 (static) |
| `arm-unknown-linux-musleabi` | Linux ARM32 (static) |
| `armv7-unknown-linux-musleabihf` | Linux ARMv7 (static) |

## Usage

### Server
```bash
shadowtls server --listen [::]:443 --server 127.0.0.1:8080 --tls cloud.tencent.com:443 --password SECRET
```

### Client
```bash
shadowtls client --listen [::1]:8080 --server SERVER_IP:443 --sni cloud.tencent.com --password SECRET
```

### Options
| Flag | Description |
|------|-------------|
| `--threads N` | Worker threads (default: CPU count) |
| `--fastopen` | TCP FASTOPEN |
| `--v3` | V3 protocol |
| `--strict` | V3 strict mode |
| `--nodelay` | TCP_NODELAY (default: on) |
| `--disable-nodelay` | Disable TCP_NODELAY |
| `--alpn h2;http/1.1` | ALPN protocols |
| `--wildcard-sni off\|authed\|all` | Server SNI routing |
| `--sni host1;host2` | Multiple SNIs (client picks random) |
| `--tls sni=ip:port;fallback:port` | Server TLS dispatch |
| `--config file.json` | JSON config file |

### SIP003 (shadowsocks plugin)
```bash
SS_REMOTE_HOST=:: SS_REMOTE_PORT=443 \
SS_LOCAL_HOST=127.0.0.1 SS_LOCAL_PORT=8080 \
SS_PLUGIN_OPTIONS="server;passwd=SECRET;tls=cloud.tencent.com:443" \
shadowtls
```

## Protocol

### V2
- Client does real TLS handshake through server (transparent proxy)
- HMAC-SHA1 of all handshake bytes sent as 8-byte auth tag in first APPLICATION_DATA frame
- Server detects match, switches to data relay
- Subsequent frames: HMAC-4 chain (KDF-based)

### V3
- Client embeds 4-byte HMAC-SHA1 in ClientHello session_id tail
- Server validates, extracts server_random from real TLS ServerHello
- During handshake: APPLICATION_DATA from TLS endpoint is XOR'd and HMAC'd (StreamWrapper)
- Client APPLICATION_DATA checked for HMAC match
- Data relay: XOR + HMAC-4 chain

## Architecture

```
src/
  types.hpp     — RAII handles, constants, Conn, Config
  engine.hpp    — EventLoop, protocol functions
  main.cpp      — 1127 lines, all implementations
  protocol.hpp  — TLS constants, HMAC wrapper
  protocol.cpp  — HMAC, KDF, address parsing
  relay.hpp     — FrameDecoder, appdata record builders
tests/
  test_basic.cpp        — 4 unit tests
  test_integration.cpp  — 7 integration tests
  test_fuzz.cpp         — 208 fuzz tests
  test_bench.cpp        — 2 benchmarks
```

## Performance

- HMAC relay: **1780 MB/s**
- SNI parsing: **0.2 µs/op**
- 219 tests, zero warnings

## License

GNU General Public License v3.0
