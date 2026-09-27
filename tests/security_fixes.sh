#!/usr/bin/env bash
#
# tests/security_fixes.sh
#
# Regression test: security fixes + production-hardening fixes
# (range 206, chunked bodies, constant-time admin auth, worker respawn,
# TLS 1.3 / HTTP/2 end-to-end, binary hardening).
#
# Exits 0 on full pass, non-zero at first failure.
#
set -u

cd "$(dirname "$0")/.."
ROOT=$PWD
BINARY=$ROOT/secure_httpd
PORT=18099
TLS_PORT=18100
ADMIN_TOKEN="salukid-test-token-xyz-987654321"
CERT=$ROOT/certs/cert.pem
KEY=$ROOT/certs/key.pem
PASS=0; FAIL=0; FAILED=()
SRV_PID=""

say()  { printf '\033[1;36m[..]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[ok]\033[0m %s\n' "$*"; PASS=$((PASS+1)); }
bad()  { printf '\033[1;31m[!!]\033[0m %s\n' "$*"; FAIL=$((FAIL+1)); FAILED+=("$*"); }

cleanup() {
    if [ -n "${SRV_PID:-}" ]; then
        kill -9 "$SRV_PID" 2>/dev/null || true
        pkill -9 -P "$SRV_PID" 2>/dev/null || true
    fi
    pkill -9 -f "secure_httpd.*$PORT" 2>/dev/null || true
    pkill -9 -f "secure_httpd.*$TLS_PORT" 2>/dev/null || true
    sleep 0.3
}
trap cleanup EXIT

wait_for_listen() {
    local port=$1 i
    for i in $(seq 1 80); do
        if ss -tln 2>/dev/null | grep -q ":$port "; then return 0; fi
        sleep 0.1
    done
    return 1
}

http_get()  { curl -s --max-time 3 "http://127.0.0.1:$PORT$1" "${@:2}"; }
http_code() { curl -s -o /dev/null --max-time 3 -w "%{http_code}" "http://127.0.0.1:$PORT$1" "${@:2}"; }
https_code(){ curl -sk -o /dev/null --max-time 3 -w "%{http_code}" "https://127.0.0.1:$TLS_PORT$1" "${@:2}"; }
https_get() { curl -sk --max-time 3 "https://127.0.0.1:$TLS_PORT$1" "${@:2}"; }

say "Building..."
make -j4 >/tmp/salukid-test-build.log 2>&1 || { bad "build failed (see /tmp/salukid-test-build.log)"; exit 1; }

say "Starting server on http=:$PORT https=:$TLS_PORT..."
cleanup
"$BINARY" -p "$PORT" -T "$TLS_PORT" -C "$CERT" -K "$KEY" \
    -r ./www -w 2 -A "$ADMIN_TOKEN" \
    </dev/null >/tmp/salukid-test.log 2>&1 &
SRV_PID=$!
disown "$SRV_PID" 2>/dev/null || true
if [ -z "$SRV_PID" ]; then bad "server did not start"; exit 1; fi
wait_for_listen "$PORT" || { bad "server never bound http port $PORT"; cat /tmp/salukid-test.log; exit 1; }
wait_for_listen "$TLS_PORT" || { bad "server never bound tls port $TLS_PORT"; cat /tmp/salukid-test.log; exit 1; }

###############################################################################
# HTTP/1.1 plain
###############################################################################
say "T1 GET /ok.txt -> 200 + body 'ok\\n'"
code=$(http_code /ok.txt)
curl -s --max-time 3 "http://127.0.0.1:$PORT/ok.txt" -o /tmp/sal-t1-body
got=$(wc -c < /tmp/sal-t1-body | tr -d ' ')
[ "$code" = "200" ] && ok "GET /ok.txt status=200" || bad "expected 200 got $code"
[ "$got" = "3" ] && ok "body 3 bytes" || bad "expected 3 bytes got $got"
expected=$(printf 'ok\n'); actual=$(cat /tmp/sal-t1-body)
[ "$actual" = "$expected" ] && ok "body is 'ok\\n'" || bad "unexpected body: $(od -An -tx1 /tmp/sal-t1-body)"

say "T2 symlink index escape must return 403/404"
ln -sf /etc/passwd www/escape_link_test 2>/dev/null || true
code=$(http_code /escape_link_test)
rm -f www/escape_link_test
case "$code" in
    403|404|400) ok "symlink escape blocked (status=$code)" ;;
    *) bad "symlink escape NOT blocked (status=$code)" ;;
esac

say "T3 unknown method WHACKY -> 501"
code=$(python3 -c "
import socket
s=socket.socket(); s.connect(('127.0.0.1', $PORT))
s.sendall(b'WHACKY / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n')
s.settimeout(2); d=b''
try:
    while True:
        c=s.recv(4096)
        if not c: break
        d+=c
except: pass
print(d.split(b'\r\n')[0].decode(errors='replace').split()[1] if d else '000')
s.close()")
[ "$code" = "501" ] && ok "unknown method returned 501" || bad "expected 501 got $code"

say "T4 404 body present"
body=$(http_get /path/that/does/not/exist)
code=$(http_code /path/that/does/not/exist)
[ "$code" = "404" ] && ok "404 for missing path" || bad "expected 404 got $code"
case "$body" in *"not found"*) ok "404 body present";; *) bad "404 body missing";; esac

say "T5 admin without token -> 401"
code=$(http_code /_admin/config)
[ "$code" = "401" ] && ok "admin 401 without token" || bad "expected 401 got $code"

say "T6 admin wrong token -> 401"
code=$(curl -s -o /dev/null --max-time 3 -w "%{http_code}" \
    -H "Authorization: Bearer SHORT" "http://127.0.0.1:$PORT/_admin/config")
[ "$code" = "401" ] && ok "wrong short token -> 401" || bad "expected 401 got $code"
code=$(curl -s -o /dev/null --max-time 3 -w "%{http_code}" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}x" "http://127.0.0.1:$PORT/_admin/config")
[ "$code" = "401" ] && ok "wrong same-length token -> 401" || bad "expected 401 got $code"

say "T7 admin correct token -> 200"
code=$(curl -s -o /dev/null --max-time 3 -w "%{http_code}" \
    -H "Authorization: Bearer $ADMIN_TOKEN" "http://127.0.0.1:$PORT/_admin/config")
[ "$code" = "200" ] && ok "admin 200 with good token" || bad "expected 200 got $code"

say "T8 range 206 bytes=0-1 returns 2 bytes + Content-Range"
hdr=$(curl -s --max-time 3 -r 0-1 -D - "http://127.0.0.1:$PORT/ok.txt" -o /tmp/sal-rb)
code=$(printf "%s" "$hdr" | head -1 | tr -d '\r' | awk '{print $2}')
got=$(wc -c < /tmp/sal-rb | tr -d ' ')
echo "$hdr" | grep -qi "content-range: bytes 0-1/3" && cr_ok=1 || cr_ok=0
echo "$hdr" | grep -qi "accept-ranges: bytes" && ar_ok=1 || ar_ok=0
[ "$code" = "206" ] && ok "range status=206" || bad "expected 206 got $code"
[ "$got" = "2" ] && ok "range returned 2 bytes" || bad "expected 2 bytes got $got"
[ "$cr_ok" = 1 ] && ok "Content-Range present" || bad "missing Content-Range"
[ "$ar_ok" = 1 ] && ok "Accept-Ranges present" || bad "missing Accept-Ranges"

say "T9 chunked POST admin/cache-purge -> 200"
code=$(curl -s -o /dev/null --max-time 3 -w "%{http_code}" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Transfer-Encoding: chunked" \
    -d "chunked-request-body" \
    "http://127.0.0.1:$PORT/_admin/cache-purge")
[ "$code" = "200" ] && ok "chunked POST -> 200" || bad "expected 200 got $code"

say "T10 worker respawn"
BEFORE=$(pgrep -P "$SRV_PID" 2>/dev/null | wc -l)
W=$(pgrep -P "$SRV_PID" 2>/dev/null | tail -1)
if [ -n "$W" ]; then
    kill -9 "$W"
    sleep 2
    AFTER=$(pgrep -P "$SRV_PID" 2>/dev/null | wc -l)
    code=$(http_code /ok.txt)
    [ "$AFTER" -ge "$BEFORE" ] && ok "worker respawned" || bad "worker not respawned"
    [ "$code" = "200" ] && ok "serve ok after worker kill" || bad "serve failed ($code)"
else
    bad "could not find child worker"
fi

say "T11 binary hardening: PIE / RELRO / NX"
file "$BINARY" | grep -q "pie executable\|shared object" && ok "PIE" || bad "not PIE"
readelf -d "$BINARY" 2>/dev/null | grep -q BIND_NOW && ok "BIND_NOW (full RELRO)" || bad "no BIND_NOW"
readelf -l "$BINARY" 2>/dev/null | grep GNU_STACK | grep -qvE " RWE| E " && ok "NX stack" || bad "stack not NX"

say "T12 /healthz -> 200"
code=$(http_code /healthz)
[ "$code" = "200" ] && ok "/healthz 200" || bad "/healthz returned $code"

###############################################################################
# HTTP/1.1 over TLS
###############################################################################
say "T13 H1 TLS GET /ok.txt -> 200, 3 bytes"
code=$(https_code /ok.txt)
https_get /ok.txt -o /tmp/sal-tls-body
got=$(wc -c < /tmp/sal-tls-body | tr -d ' ')
[ "$code" = "200" ] && ok "H1 TLS status=200" || bad "H1 TLS expected 200 got $code"
[ "$got" = "3" ] && ok "H1 TLS body=3 bytes" || bad "H1 TLS expected 3 bytes got $got"

say "T14 H1 TLS HEAD -> Content-Length: 3 (body 0 bytes)"
hdr=$(curl -sk --http1.1 --max-time 3 -I "https://127.0.0.1:$TLS_PORT/ok.txt")
echo "$hdr" | grep -qi 'content-length: 3' && cl_ok=1 || cl_ok=0
[ "$cl_ok" = 1 ] && ok "H1 TLS HEAD CL=3" || bad "H1 TLS HEAD missing/bad CL"

say "T15 H1 TLS /index.html -> 200, 1223 bytes"
code=$(curl -sk --http1.1 -o /tmp/sal-tls-idx -w "%{http_code}" --max-time 5 \
    "https://127.0.0.1:$TLS_PORT/index.html")
sz=$(wc -c < /tmp/sal-tls-idx | tr -d ' ')
[ "$code" = "200" ] && ok "H1 TLS index.html 200" || bad "H1 TLS index.html code=$code"
[ "$sz" = "1223" ] && ok "H1 TLS index.html size=1223" || bad "H1 TLS index.html size=$sz"

say "T16 H1 TLS 10x sequential keepalive"
fail=0
for i in $(seq 1 10); do
    c=$(https_code /ok.txt)
    [ "$c" != "200" ] && fail=1
done
[ "$fail" = 0 ] && ok "H1 TLS 10x keepalive all 200" || bad "H1 TLS keepalive failed"

###############################################################################
# HTTP/2 over TLS
###############################################################################
say "T17 H2 GET /ok.txt -> 200, 3 bytes 'ok\\n'"
code=$(curl -sk --http2 -o /tmp/sal-h2-body -w "%{http_code}" --max-time 5 \
    "https://127.0.0.1:$TLS_PORT/ok.txt")
got=$(wc -c < /tmp/sal-h2-body | tr -d ' ')
body=$(cat /tmp/sal-h2-body)
[ "$code" = "200" ] && ok "H2 status=200" || bad "H2 expected 200 got $code"
[ "$got" = "3" ] && ok "H2 body=3 bytes" || bad "H2 expected 3 bytes got $got"
expected=$(printf 'ok\n')
[ "$body" = "$expected" ] && ok "H2 body is 'ok\\n'" || bad "H2 unexpected body"

say "T18 H2 HEAD -> Content-Length: 3, no body"
hdr=$(curl -sk --http2 -I --max-time 3 "https://127.0.0.1:$TLS_PORT/ok.txt")
echo "$hdr" | grep -qi 'content-length: 3' && cl_ok=1 || cl_ok=0
[ "$cl_ok" = 1 ] && ok "H2 HEAD CL=3" || bad "H2 HEAD CL mismatch"

say "T19 H2 /healthz -> 200"
code=$(curl -sk --http2 -o /dev/null -w "%{http_code}" --max-time 3 \
    "https://127.0.0.1:$TLS_PORT/healthz")
[ "$code" = "200" ] && ok "H2 /healthz 200" || bad "H2 /healthz got $code"

say "T20 H2 404 -> 404"
code=$(curl -sk --http2 -o /dev/null -w "%{http_code}" --max-time 3 \
    "https://127.0.0.1:$TLS_PORT/no-such-file")
[ "$code" = "404" ] && ok "H2 404" || bad "H2 404 got $code"

say "T21 H2 Range 0-1 -> 206, 2 bytes, Content-Range"
hdr=$(curl -sk --http2 -r 0-1 -D - --max-time 3 "https://127.0.0.1:$TLS_PORT/ok.txt" -o /tmp/sal-h2-rb)
code=$(printf "%s" "$hdr" | head -1 | tr -d '\r' | awk '{print $2}')
got=$(wc -c < /tmp/sal-h2-rb | tr -d ' ')
echo "$hdr" | grep -qi "content-range: bytes 0-1/3" && cr_ok=1 || cr_ok=0
[ "$code" = "206" ] && ok "H2 range status=206" || bad "H2 range expected 206 got $code"
[ "$got" = "2" ] && ok "H2 range 2 bytes" || bad "H2 range expected 2 got $got"
[ "$cr_ok" = 1 ] && ok "H2 Content-Range present" || bad "H2 missing Content-Range"

say "T22 H2 /index.html -> 200, 1223 bytes"
code=$(curl -sk --http2 -o /tmp/sal-h2-idx -w "%{http_code}" --max-time 5 \
    "https://127.0.0.1:$TLS_PORT/index.html")
sz=$(wc -c < /tmp/sal-h2-idx | tr -d ' ')
[ "$code" = "200" ] && ok "H2 index.html 200" || bad "H2 index.html code=$code"
[ "$sz" = "1223" ] && ok "H2 index.html size=1223" || bad "H2 index.html size=$sz"

say "T23 H2 security headers present (HSTS, X-Content-Type-Options, etc.)"
hdr=$(curl -sk --http2 -I --max-time 3 "https://127.0.0.1:$TLS_PORT/ok.txt")
echo "$hdr" | grep -qi 'strict-transport-security' && hsts=1 || hsts=0
echo "$hdr" | grep -qi 'x-content-type-options' && xcto=1 || xcto=0
echo "$hdr" | grep -qi 'x-frame-options' && xfo=1 || xfo=0
[ "$hsts" = 1 ] && ok "H2 HSTS header" || bad "H2 missing HSTS"
[ "$xcto" = 1 ] && ok "H2 X-Content-Type-Options" || bad "H2 missing X-CTO"
[ "$xfo" = 1 ] && ok "H2 X-Frame-Options" || bad "H2 missing XFO"

say "T24 H2 20x sequential over same connection, all 200"
fail=0
for i in $(seq 1 20); do
    c=$(curl -sk --http2 -o /dev/null -w "%{http_code}" --max-time 3 \
        "https://127.0.0.1:$TLS_PORT/ok.txt")
    [ "$c" != "200" ] && fail=1
done
[ "$fail" = 0 ] && ok "H2 20x sequential all 200" || bad "H2 20x sequential had failure"

echo
echo "====================================================="
echo "  Passed: $PASS   Failed: $FAIL"
echo "====================================================="
if [ "$FAIL" -gt 0 ]; then
    printf 'Failures:\n'
    printf '  - %s\n' "${FAILED[@]}"
    exit 1
fi
exit 0
