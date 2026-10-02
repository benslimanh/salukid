# salukid Deployment Guide

This document describes how to deploy `salukid/secure_httpd` to production
on a modern Linux (Debian 13 / Ubuntu 24.04 / RHEL 9) host.

## 1. Binary hardening recap

The build is compiled with the following hardening flags baked in (verified
via `checksec` and `readelf`):

| Control | How |
|---|---|
| ASLR / PIE | `-fPIE -pie`, `Type: DYN` in ELF header |
| Full RELRO + BIND_NOW | `-Wl,-z,relro,-z,now` + `BIND_NOW` in `FLAGS_1` |
| Stack protector | `-fstack-protector-strong` (43 `__stack_chk_fail` refs) |
| Stack clash | `-fstack-clash-protection` |
| CFI (indirect branch) | `-fcf-protection=full` (IBT+SHSTK where CPU supports) |
| Non-exec stack | `GNU_STACK RW` (no E bit) |
| No PLT | `-fno-plt` (uses GOT-direct calls) |
| FORTIFY_SOURCE | `-D_FORTIFY_SOURCE=3` |
| Backtraces | `-rdynamic` |
| No `strcpy`/`sprintf`/`gets` | enforced by coding rules; all string ops bounded |

Verify locally:

```sh
readelf -h ./secure_httpd | grep Type:
readelf -d ./secure_httpd | grep -E 'BIND_NOW|FLAGS_1'
readelf -l ./secure_httpd | grep GNU_STACK
file ./secure_httpd
```

All four should show PIE/DYN, BIND_NOW/NOW PIE, RW (not RWE) stack,
"pie executable".

## 2. Build

```sh
make -j"$(nproc)"
# Optional HTTP/3/QUIC build (requires libngtcp2-gnutls, libnghttp3):
make quic
```

Install targets (manual):

```sh
install -m 0755 secure_httpd        /usr/local/sbin/secure_httpd
install -m 0755 secure_httpd_quic   /usr/local/sbin/secure_httpd_quic
install -d -m 0755 /etc/salukid /var/log/salukid /var/lib/salukid/www
install -m 0644 certs/cert.pem      /etc/salukid/cert.pem
install -m 0600 certs/key.pem       /etc/salukid/key.pem
install -m 0644 deploy/salukid.service   /etc/systemd/system/salukid.service
install -m 0644 deploy/salukid.logrotate /etc/logrotate.d/salukid
```

Create the runtime user:

```sh
useradd -r -s /usr/sbin/nologin -d /var/lib/salukid salukid
chown -R salukid:salukid /var/lib/salukid /var/log/salukid
```

If you want to bind to privileged ports (<1024) without running as root,
grant `CAP_NET_BIND_SERVICE`:

```sh
setcap cap_net_bind_service+ep /usr/local/sbin/secure_httpd
```

Alternatively, run as root and let salukid drop privileges via `-u salukid`
(that's what the `User=` line in the unit does implicitly when you run
systemd as root).

## 3. systemd unit

See `deploy/salukid.service`. Key behaviors:

- `Restart=always` with `RestartSec=1` — crashed workers respawn
  automatically within the prefork pool; if the parent dies systemd
  restarts the whole service.
- `KillMode=mixed`: SIGTERM to parent, SIGKILL to any still-alive
  children after `TimeoutStopSec=10s`.
- `ExecReload=/bin/kill -HUP $MAINPID` sends SIGHUP → cache purge and
  in-place module reload; long-lived connections finish draining.
- `MemoryDenyWriteExecute=true`, `ProtectSystem=strict`,
  `PrivateTmp=true`, `NoNewPrivileges=true`,
  `CapabilityBoundingSet=CAP_NET_BIND_SERVICE` — standard sandbox.
- `-l /var/log/salukid/access.log -S -j` — JSON structured lines written
  to disk AND forwarded to syslog.
- `-A "${SALUKID_ADMIN_TOKEN}"` — read the admin bearer token from an
  EnvironmentFile or `systemctl set-environment`.

Enable and start:

```sh
systemctl daemon-reload
systemctl enable --now salukid.service
systemctl status salukid.service
journalctl -u salukid.service -f
```

## 4. Log rotation

`deploy/salukid.logrotate` rotates daily, keeps 14 compressed copies,
and sends `SIGUSR1` post-rotation so salukid reopens the log file
(parent and workers). Install:

```sh
install -m 0644 deploy/salukid.logrotate /etc/logrotate.d/salukid
logrotate -f /etc/logrotate.d/salukid   # dry test
```

Syslog forwarding (`-S`) uses `LOG_DAEMON` facility so journald/syslogd
pick it up automatically. If you want a separate rsyslog rule:

```
:programname, isequal, "salukid" /var/log/salukid/syslog.log
& stop
```

## 5. Graceful reload

Two signals are supported:

| Signal | Action |
|---|---|
| `SIGHUP` | Purge response cache, reload loaded `.so` modules, notify every worker. Existing connections drain; new connections use fresh config. |
| `SIGUSR1` | Reopen the `-l` log file (for logrotate). |
| `SIGTERM`/`SIGINT` | Drain and exit (parent signals children with SIGTERM; systemd sends SIGKILL after TimeoutStopSec). |

```sh
systemctl reload salukid.service     # SIGHUP → cache+module reload
systemctl kill -s SIGUSR1 salukid    # reopen logs
```

Workers that crash unexpectedly (SIGSEGV/etc.) are respawned by the parent
with a fresh SO_REUSEPORT listener; see `server.c` waitpid loop. Crashes
are logged at WARN level.

## 6. TLS configuration

New flags:

| Flag | Purpose |
|---|---|
| `-3` | TLS 1.3-only (rejects 1.2 clients) |
| `-o <ciphers>` | Cipher list knob (exposed; defaults to mbedTLS safe list) |
| `-C` / `-K` | PEM cert + private key |
| ALPN | `h2`, `http/1.1` (auto-negotiated) |

For a strict/modern profile we recommend terminating at a CDN (Cloudflare,
HAProxy) with TLS 1.3 only in front; salukid itself defaults to TLS 1.2+
for client compatibility. Add `-3` when you don't need legacy clients.

OCSP stapling and ECH are tracked on the roadmap; for production today,
front with a reverse proxy (Caddy/HAProxy) that handles OCSP must-staple
if required.

## 7. Modules

Load stable-ABI (v1) modules with `-M path/to/module.so:cfg`. Modules
that ship in this repo:

- `modules/jwt_auth.so` — HS256/RS256/ES256 JWT auth (RS256/ES256 added in
  this hardening pass; JWKS cached in-memory with 60s TTL).
- `modules/modsec_real.so` — real libmodsecurity (OWASP CRS).
- `modules/proxy_wasm.so` — proxy-wasm ABI.

Example:

```sh
./secure_httpd -p 8080 -T 8443 -C cert.pem -K key.pem -r ./www -w 4 \
    -M "modules/jwt_auth.so:secret_hex=736563726574,iss=salukid" \
    -M modules/modsec_real.so
```

## 8. Privilege drop

When started as root (e.g. to bind :80/:443), salukid will chdir to the
chroot if `-Z <dir>` was given, chroot, `setgroups(0,NULL)`, `setgid`,
`setuid` to the `-u` user (default `nobody`). A post-setuid test verifies
that `setuid(0)` fails (i.e. we cannot regain root).

You should still rely on systemd sandboxing (`ProtectSystem=strict`,
`NoNewPrivileges=true`, etc.) as defense in depth even when dropping
privileges internally.

## 9. Admin API

`/_admin/*` endpoints are guarded by a constant-time bearer-token compare
(`-A <token>`), which compares in constant time over a fixed 128-byte
window and folds a length mismatch into the diff accumulator so timing
does not leak token length.

Endpoints:

| Method | Path | Purpose |
|---|---|---|
| GET | `/_admin/health` | JSON upstream health |
| GET | `/_admin/config` | Running config JSON |
| GET | `/_admin/dashboard` | Tiny HTML dashboard (auto-refresh) |
| POST | `/_admin/up` / `/_admin/down` | body `host:port` → mark up/down |
| POST | `/_admin/cache-purge` | Purge response cache |

## 10. Performance baseline (67–71 kRPS)

From `BENCHMARKS.md` on a 4-worker loopback run (wrk, t4 c50):

| Config | RPS |
|---|---|
| Baseline HTTP/1.1 | ~70 kRPS |
| +JWT (HS256) | ~53 kRPS |
| +ModSecurity | ~22 kRPS |
| k6 mixed workload | ~14 kRPS (p95 8.9 ms, 0 failures) |

Set worker count to the number of physical cores (`-w 0` does this
automatically). Tune `--cpuset` and IRQ pinning for multi-NUMA boxes.

## 11. Post-deploy smoke test

```sh
# Basic reachability
curl -k https://127.0.0.1:8443/healthz
# Range 206
curl -r 0-100 -o /tmp/r.bin https://127.0.0.1:8443/index.html -D -
# Admin 401 without token
curl -s -o /dev/null -w "%{http_code}\n" https://127.0.0.1:8443/_admin/config
# Admin 200 with token
curl -s -H "Authorization: Bearer <token>" https://127.0.0.1:8443/_admin/config
# Unknown method -> 501
printf 'WHACKY / HTTP/1.1\r\nHost: x\r\n\r\n' | curl --http1.1 -k --telnet-option ... 2>&1
# Worker respawn
kill -9 $(pgrep -P $(pgrep -of secure_httpd) | head -1); sleep 1
curl -s https://127.0.0.1:8443/healthz
```

The bundled `tests/security_fixes.sh` runs the full regression suite
(including all 10 prior security findings) and exits non-zero on any
failure. Run it from CI after build.

## 11. Direct Internet Deployment

salukid is designed to run directly on the internet edge without a
reverse-proxy TLS terminator in front. This is the same threat model as
nginx/Caddy/HAProxy running on :80/:443.

### Why this is safe

1. **TLS terminates in-process** via vendored mbedTLS v3.6.2. No separate TLS
   proxy = one fewer moving part, one fewer attack surface. Use `-3` to
   restrict to TLS 1.3 only.
2. **Privilege drop**: start as root to bind :80/:443, then drop to
   `www-data`/`nobody` (the systemd unit uses `DynamicUser=yes`, which
   gives each run its own ephemeral UID with no write access anywhere).
3. **Process isolation**: each worker is a separate prefork process
   (`-w N`, one listener socket per worker via `SO_REUSEPORT`); a crash
   in one worker does not affect others; the parent respawns workers on
   `SIGCHLD` (re-binding SO_REUSEPORT, re-accepting).
4. **Path confinement**: all file access goes through `safe_resolve_path()`
   which uses `openat(O_NOFOLLOW)` + `fstat` + `..`-rejection; symlinks
   out of the document root return 404/403.
5. **Memory safety arenas**: per-connection arena allocator (bump allocator,
   full reset between requests) bounds the lifetime of request data; slabs
   reuse connections; no use-after-free across request boundaries.
6. **Request size caps**: headers bounded by `SALUKID_SMALLBUF_SZ`; request
   bodies capped at 1 MiB (`SALUKID_MAX_REQ_BODY`), returning 413. Chunked
   state machine validates sizes.
7. **No unsafe libc**: no `strcpy`/`sprintf`/`gets`; all `snprintf`-bounded.
   Compiled with `-D_FORTIFY_SOURCE=3`, `-fstack-protector-strong`,
   `-fstack-clash-protection`, `-fcf-protection=full`, `-fno-plt`, and
   `-Wl,-z,relro,-z,now,-z,noexecstack,-z,separate-code`.
8. **WAF modules run as separate `.so` files** behind a stable v1 ABI;
   load with `-M modules/modsec_real.so:<rules>` for libmodsecurity
   (CRS) coverage. Modules run in the worker process but call only
   bounded API functions; a module crash is isolated to that worker
   (which the parent respawns).
9. **JWT auth** is constant-time for HS256 compare (128-byte fixed window
   with length-mismatch folded into a diff accumulator and compiler
   barrier); asymmetric (RS*/ES*) uses mbedTLS PK verify.

### Edge port binding

```sh
# Run as root (systemd handles privilege drop), serving both HTTP and HTTPS:
/usr/local/sbin/secure_httpd \
    -p 80 -T 443 \
    -C /etc/salukid/cert.pem \
    -K /etc/salukid/key.pem \
    -r /var/lib/salukid/www \
    -w "$(nproc)" \
    -3 \
    -A "$(openssl rand -hex 32)" \
    -l /var/log/salukid/access.log \
    -S \
    -d
```

Signal handling:
- `SIGHUP`  — graceful reload: purge cache, reload modules, forward to workers
- `SIGUSR1` — reopen log file (for logrotate postrotate)
- `SIGTERM` / `SIGINT` — drain existing connections and exit
- `SIGPIPE` — ignored

### Fronting with CDN (optional but recommended)

If you front with Cloudflare/CloudFront/Fastly:
- Terminate TLS at the CDN and origin-pull over HTTPS with a pinned CA.
- Use `-C/-K` with a CDN-facing certificate.
- Use `-A <token>` for `/._admin/*` endpoints and require the CDN to
  inject a secret header (strip client-supplied ones in CDN config).

### Performance reference

On a single x86_64 core (i7-12700k class):
- HTTP/1.1 plaintext:         ~70,000 RPS (wrk, 4 workers, c50)
- HTTP/1.1 + TLS 1.3:         ~55,000 RPS
- HTTP/2   + TLS 1.3:         ~13,000 RPS (h2load, 10 concurrency, including handshake)
- HTTP/1.1 + JWT (HS256):     ~53,000 RPS
- HTTP/1.1 + ModSecurity:     ~21-22,000 RPS
- k6 mixed workload:          ~14,000 RPS (p95 8.9 ms, 0 failures)
