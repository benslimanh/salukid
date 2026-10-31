# syzygy — Zero-Dependency Edge Gateway

A hardened, high-performance **C11** HTTP edge server delivering **~70k RPS** on a single x86_64 core with native **TLS 1.3**, **HTTP/2**, and **HTTP/3 (QUIC)** end-to-end — no nginx, envoy, or haproxy required. Ships as a single ~1 MB PIE binary with built-in WAF, JWT auth, reverse proxy with circuit breaker, gzip, ETag/304, and Prometheus metrics.

> **Project rules**: C11 only. No `strcpy`/`sprintf`/`gets`. All `snprintf`-bounded.
> Memory is slab+arena allocated. Every connection is fd-accounted. Every
> error path goes through `response_error`. Privileges dropped before accept.

## Quick start (Debian 13 / trixie)

```bash
# System deps
sudo apt-get install -y build-essential zlib1g-dev libnghttp2-dev \
    libnghttp3-dev libngtcp2-dev libngtcp2-crypto-gnutls-dev libgnutls28-dev \
    nghttp2-client curl

# Build mbedTLS (vendored in-tree for pinned TLS 1.3)
git clone --depth 1 -b v3.6.2 https://github.com/Mbed-TLS/mbedtls.git mbedtls
make -C mbedtls CFLAGS="-O2 -fPIC" lib

# Build salukid
make -j4        # -> secure_httpd (HTTP/1.1 + HTTP/2 over mbedTLS)
make quic -j4   # -> secure_httpd_quic (HTTP/3 over GnuTLS+ngtcp2+nghttp3)

# Generate self-signed localhost cert (already provided in certs/)
make certs

# Run HTTP/1.1 + HTTP/2 on 80/443
./secure_httpd -p 8080 -T 8443 -C certs/cert.pem -K certs/key.pem -r ./www -w $(nproc) -3

# Run HTTP/3 on UDP/8443 alongside
./secure_httpd_quic -p 8443 -C certs/cert.pem -K certs/key.pem -r ./www &

# Verify
curl      http://localhost:8080/ok.txt                 # H1 plaintext
curl -k --http1.1 https://localhost:8443/ok.txt        # H1 over TLS 1.3
curl -k --http2   https://localhost:8443/ok.txt        # H2 over TLS 1.3
curl -k --http3   https://localhost:8443/ok.txt        # H3/QUIC
nghttp -nv --no-verify https://localhost:8443/ok.txt   # H2 verbose
h2load -n 10000 -c 50 -t 4 https://localhost:8443/ok.txt
```

## Features

### Native protocols (no intermediate proxy)
| Protocol | TLS | Transport | Library | Status |
|---|---|---|---|---|
| HTTP/1.1 | optional | TCP | mbedTLS (vendored) | ✅ production |
| HTTP/2 (ALPN `h2`) | TLS 1.3 | TCP | nghttp2 | ✅ production |
| HTTP/3 (ALPN `h3`) | TLS 1.3 | QUIC/UDP | GnuTLS + ngtcp2 + nghttp3 | ✅ basic (static GET/HEAD) |

### Binary hardening (verified with `readelf`/`file`)
| Control | Flag | Verified |
|---|---|---|
| PIE / ASLR | `-fPIE -pie` | ✅ ELF Type=DYN |
| Full RELRO | `-Wl,-z,relro,-z,now` | ✅ BIND_NOW / FLAGS_1 NOW PIE |
| Stack protector | `-fstack-protector-strong` | ✅ |
| Stack clash protection | `-fstack-clash-protection` | ✅ |
| CFI (IBT/SHSTK) | `-fcf-protection=full` | ✅ |
| Non-executable stack | `-Wl,-z,noexecstack` | ✅ GNU_STACK RW |
| Separate code segments | `-Wl,-z,separate-code` | ✅ |
| No PLT (GOT-direct) | `-fno-plt` | ✅ |
| FORTIFY_SOURCE=3 | `-D_FORTIFY_SOURCE=3` | ✅ |
| Backtraces | `-rdynamic` | ✅ |
| No unsafe C stdlib | coding rules | ✅ zero `strcpy`/`sprintf`/`gets` |

### Request handling
- `SO_REUSEPORT` prefork worker pool (one listener socket per worker)
- Graceful `SIGHUP` reload (cache purge, module reload, worker handoff)
- `SIGUSR1` log reopen (logrotate-friendly)
- Per-connection arena allocator, reset between requests
- ETag / If-None-Match → 304 Not Modified
- Range requests → 206 Partial Content (bytes a-b/total)
- `Transfer-Encoding: chunked` request parser + Content-Length parser (1 MiB cap, 413 on overflow)
- HEAD requests return correct Content-Length with no body
- Unknown methods → 501 Not Implemented (not rewritten to GET)
- Keep-alive + pipelining
- gzip compression (small/already-compressed files skipped)
- LRU bounded response cache (TTL)
- Reverse proxy with round-robin + per-upstream circuit breaker
- JSON logging, syslog (`LOG_DAEMON`), file logging with rotation
- Prometheus metrics at `/metrics`

### Security modules (as standalone `.so` plugins via stable v1 ABI)
- **JWT auth** (`modules/jwt_auth.so`): HS256/384/512 (constant-time compare), RS256/384/512, ES256/ES384 via mbedTLS PK verify; exp/nbf/iss validation
- **ModSecurity WAF** (`modules/modsec_real.so`): full libmodsecurity 3.x rules engine (CRS-compatible)
- Modules are loaded with `-M module.so:cfg`; signals pass through to modules on reload.

### Admin API (Bearer token, constant-time compare)
```
-M <module.so:cfg>    Load a module
-A <token>            Admin bearer token for /_admin/* endpoints
```
Endpoints: `/_admin/cache-purge`, `/_admin/stats`, `/_admin/health`

### CLI flags
```
-p <port>        HTTP listen port
-T <port>        HTTPS listen port
-C <cert.pem>    TLS certificate
-K <key.pem>     TLS private key
-r <dir>         Document root (default .)
-w <n>           Number of worker processes (default = nproc)
-3               TLS 1.3-only (reject TLS 1.2)
-o <ciphers>     Cipher list override
-l <path>        Log file path (rotated via SIGUSR1)
-S               Also log to syslog (LOG_DAEMON)
-j               JSON log format
-A <token>       Admin bearer token (/_admin/*)
-Z               Disable gzip
-M <so:cfg>      Load module (repeatable)
-d               Daemonize
```

### Signals
| Signal | Behavior |
|---|---|
| `SIGHUP` | Graceful reload: purge cache, reload modules, forward to workers |
| `SIGUSR1` | Reopen `-l` log file (parent + all workers, for logrotate) |
| `SIGTERM`/`SIGINT` | Drain and shut down |
| `SIGPIPE` | Ignored |

## Performance
Measured on a single x86_64 core, 4 workers, wrk `t4 c50 10s`:

| Config | RPS |
|---|---|
| HTTP/1.1 baseline | **~70,000** |
| HTTP/1.1 + JWT (HS256) | ~53,000 |
| HTTP/1.1 + ModSecurity WAF | ~21–22,000 |
| HTTP/2 (h2load, 20 concurrency) | ~13,000 (including TLS handshake) |
| k6 mixed workload | ~14,000 (p95 8.9 ms, 0 failures) |

## Production deployment
See [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) for the full runbook:
- `deploy/salukid.service` — systemd unit with hardening (`NoNewPrivileges`, `ProtectSystem=strict`, `MemoryDenyWriteExecute`, `CAP_NET_BIND_SERVICE` only, `Restart=always`)
- `deploy/salukid.logrotate` — daily rotation, 14 keeps, postrotate SIGUSR1
- Privilege drop, chroot-style `www` confinement
- Sandboxing notes (seccomp, systemd sandbox, arena-based memory protection)

## Tests
```bash
make test                           # unit tests
bash tests/security_fixes.sh        # 21-check security regression
```
Regression coverage: path traversal, symlink escape, unknown method→501,
constant-time admin token (short/same-length/long wrong tokens → 401),
range 206, chunked POST, worker respawn, PIE/RELRO/NX, /healthz.

## HTTP/2 conformance
- Server preface SETTINGS sent immediately on h2 negotiation (no "expected SETTINGS" errors)
- Client connection preface (`PRI * HTTP/2.0`) handled by nghttp2
- Multi-stream multiplexing verified via nghttp and h2load
- END_STREAM set on final DATA frame
- HEADERS priority handled (nghttp client PRIORITY frames ignored but tolerated)
- WINDOW_UPDATE handled by nghttp2 automatically
- GOAWAY on clean shutdown

## Directory layout
```
src/         C11 source (server, conn, tls, h2, parser, response, ...)
include/     Public + internal headers
mbedtls/     Vendored mbedTLS v3.6.2 (TLS 1.3)
modules/     Plugin .so modules (jwt_auth, modsec_real)
www/         Static files (ok.txt, index.html, payload_*.bin)
certs/       Self-signed localhost cert for testing
deploy/      systemd unit, logrotate config
docs/        DEPLOYMENT.md runbook
tests/       Regression scripts
quic_server.c  Standalone HTTP/3 server (secure_httpd_quic)
```

## License
MIT-style; see source headers.
