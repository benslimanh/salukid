# salukid Benchmark Report (2026-07-26)

Target: `secure_httpd` HTTP/1.1 server, **4 worker processes** (`-w 4`),
hardened build (PIE, full RELRO, `-D_FORTIFY_SOURCE=3`, SSP, CF-Protect,
Stack Clash, `-fno-plt`), port 18080, document root `./www`, localhost
loopback, Linux x86_64, Debian 13 (trixie).

Tools:
- Apache Bench (`ab`) 2.3 — classic forked benchmark
- wrk 4.1.0 — epoll-based, Lua-scriptable (best steady-state RPS)
- Grafana k6 v0.57.0 — JS-based, thresholds/scenarios

Modules tested:
- **Baseline**: no modules, static file serving only.
- **+JWT**: `-M modules/jwt_auth.so` (HS256 verify + iss check).
- **+ModSecurity (real libmodsecurity 3.0.14)**: `-M modules/modsec_real.so`
  with builtin SQLi/XSS rules 1001-1004; not the dummy stub.

Test payloads (in `www/`):
- `/ok.txt`           — 3 B "ok\n"
- `/healthz`         — 2 B "ok" (built-in endpoint)
- `/payload_1k.bin`  — 1.4 KiB random
- `/payload_16k.bin` — 21.6 KiB random
- `/_admin/*`        — JSON admin API
- `/metrics`         — Prometheus exposition

## 1. Baseline — no modules

### 1.1 wrk, 15 s, t4/c50

| Endpoint          | RPS       | Throughput | p50     | p90     | p99     |
|-------------------|-----------|------------|---------|---------|---------|
| `/ok.txt` (3 B)   | **70 520** | 27.6 MB/s  | 655 µs  | 2.38 ms | 13.1 ms |
| `/payload_1k.bin` | **70 051** | 120.0 MB/s | 674 µs  | 1.00 ms | 2.93 ms |

### 1.2 ab, 50 000 requests, c100

```
Complete requests:  50 000
Failed requests:    0
Requests/sec:        8 476 RPS  (ab reports ~8.5k because it disables
                                 keep-alive by default and its RPS
                                 accounting is pessimistic; wrk agrees
                                 that the server handles ~70 kRPS with
                                 connection reuse)
```

### 1.3 k6, 50 VUs, 20 s, mixed workload (`k6/loadtest.js`)

```
✓ status 200 ........... 100.00%  280 951 / 280 951
✓ http_req_failed ...... 0.00%
  http_req_duration ... avg=3.49ms  p(95)=8.86ms  max=38.5ms
  http_reqs ........... 280 951  (14 046 req/s)
  data_received ....... 1.5 GB   (75 MB/s)
```

Thresholds: `http_req_failed < 0.1%` and `p(95) < 50 ms` — both **pass**.

## 2. +JWT authentication (HS256 + iss claim)

Secret: hex-encoded "secret"; every request carries a valid
`Authorization: Bearer <HS256 JWT>`. Invalid/missing tokens are rejected
with HTTP 401 (verified).

wrk t4/c50, 15 s, `/ok.txt`:

| Metric | Value |
|--------|-------|
| Requests/sec | **52 061** |
| Throughput   | 20.4 MB/s |
| p50          | 860 µs |
| p90          | 1.80 ms |
| p99          | 11.5 ms |
| Overhead vs baseline | −26% RPS, still ~52 kRPS at sub-2 ms p90 |

## 3. +ModSecurity WAF (real libmodsecurity 3.0.14)

The real ModSecurity module is compiled from `modules/modsec_real.cpp`
and loads its built-in rule set (rule IDs 1001-1004: generic SQLi/XSS
probes). The dummy `modsec_stub.so` is **not** used.

wrk t4/c50, 15 s, `/ok.txt` (clean requests):

| Metric | Value |
|--------|-------|
| Requests/sec | **21 278** |
| Throughput   | 8.3 MB/s |
| p50          | 2.34 ms |
| p90          | 3.36 ms |
| p99          | 12.6 ms |

Blocked-by-WAF test (executed against same running server):

```
GET /ok.txt?q=1' OR 1=1--   → HTTP 403  (SQLi signature hit)
GET /ok.txt                 → HTTP 200  (clean)
```

No crashes, no false positives on the static asset set.

## 4. HTTP/3 (QUIC) status

`secure_httpd_quic` (48 KB PIE binary) builds cleanly against
system-installed `libngtcp2` 1.11 + `libngtcp2_crypto_gnutls` +
`nghttp3` 1.8. It binds UDP, performs the ngtcp2 server setup, and the
event loop / stream-data path is fully written. Full end-to-end
handshake + body transfer with `curl --http3` is in progress (one
remaining null-pointer during TLS-crypto-callback setup in
`libngtcp2_crypto_gnutls`); the static file serving logic uses the same
hardened `safe_resolve_path()` as the HTTP/1.1 server.

## 5. Security fixes applied this revision

The following findings from the security review are fixed:

| Sev | File | Fix |
|-----|------|-----|
| High | `src/path.c` | Directory indexes are opened via `openat(dfd, idx, O_RDONLY\|O_NOFOLLOW)` after `lstat()`-validating the parent dir, then `fstat()`'d — a symlinked `index.html` (or hardlinked file pointing outside the root) is now rejected rather than followed. Same resolver is used by QUIC. |
| High | `src/response.c` | `response_error()` and `dir_listing()` now `arena_strndup()` their body into the connection arena instead of storing a pointer to a stack-local buffer — no more dangling body slice. Both the first and second `response_add_buf()` call that were feeding the slice list from `body[]` are gone. |
| High | `src/h2.c` | `arena_alloc(drv)` is NULL-checked before dereference; OOM emits a clean empty response instead of a NULL-ptr crash. |
| High | `src/admin.c` | `/_admin/{config,health,upstreams,lb,dashboard}` now check `g_cfg.enable_proxy` before locking `g_proxy.mtx`; when the server is started without `-P`, proxy endpoints return HTTP 409 JSON instead of locking an uninitialized mutex. |
| High | `src/conn.c` | The receive-path condition for TLS no longer excludes `h2_active`, so after H2 is negotiated over TLS the server continues to use `mbedtls_ssl_read()` instead of feeding ciphertext bytes directly into the nghttp2 H2 parser. |
| High | `src/tls.c` | The ALPN protocol list passed to `mbedtls_ssl_conf_alpn_protocols()` is now a file-scope `static const char *const[]` (`g_alpn_protos`) instead of a compound literal inside `tls_init()`, so mbedTLS doesn't hold a dangling pointer to stack memory after `tls_init()` returns. The unused dead ALPN callback was removed. |
| High | `src/modapi.c` | All `calloc()`/`strdup()`/`malloc()` allocations in the shared-dict paths and in `modapi_load()` and `H_resp_set_header()` now NULL-check their results; OOM returns an error / no-ops safely instead of dereferencing NULL through module callbacks. |
| Med-High | `src/server.c` | Reload (SIGHUP) and shutdown now signal the direct worker PIDs tracked in a `children[]` array; children `setpgid(0,0)` so they never inherit the parent's process group. The prior `kill(0, SIG…)` that would blast every process in the group is removed. |
| Med-High | `src/parser.c` + `src/conn.c` | Unknown HTTP methods are no longer silently rewritten to `GET`; the parser records `HTTP_M_UNKNOWN` and the connection layer returns **HTTP 501 Not Implemented** with a proper body via the normal response path (routed through `response_init`+`response_error`+`response_finalize_headers` and `c->whead`/`wqueued`, so the body actually gets written to the socket). |
| Med | `quic_server.c` | Error responses (`srv_text()`) now heap-duplicate their body via `strdup` onto the qstream, add a `mem` field to `qstream_t`, and wire it through `write_one_stream()` so `Content-Length` matches the actual body bytes (body is freed in `sfree()`). `cb_h3_sendpkt` returns `NGTCP2_ERR_NOBUF` only on transient EAGAIN/ENOBUFS and `NGTCP2_ERR_CALLBACK_FAILURE` on real errors; `on_pkt` now calls both `flush_pkts()` and `flush_streams()` after receive. Fixed ngtcp2 connection-param flags (`original_dcid_present=1, initial_scid_present=0`) to match ngtcp2 1.11 assertion requirements; `ngtcp2_pkt_info` is now stack-allocated (not NULL) for every `read_pkt`/`write_pkt` call. |

## 6. Hardening posture of the shipped binary

```
$ file secure_httpd
secure_httpd: ELF 64-bit LSB pie executable, x86-64, ..., dynamically linked, ...
$ readelf -d secure_httpd | grep FLAGS
   FLAGS   BIND_NOW
   FLAGS_1 NOW PIE
```

- PIE + full RELRO (`-Wl,-z,relro,-z,now`), no lazy binding.
- `-fstack-protector-strong`, `-fstack-clash-protection`, `-fcf-protection=full` (CET).
- `-D_FORTIFY_SOURCE=3`, `-fno-plt`, `-rdynamic` (for backtraces), `-Wl,-z,noexecstack`, `-Wl,-z,separate-code`.
- No `strcpy`/`sprintf`/`gets` in the binary's dynamic symbol table; all
  bounded (`memcpy`/`snprintf` with explicit lengths).
- Modules loaded via the v1 stable ABI (`-M`) run in the same address
  space but behind a function-pointer table; legacy `-m` is retained for
  backward compatibility.
