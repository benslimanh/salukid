/*
 * admin.c - Runtime reconfiguration API. All endpoints return JSON and
 * are protected by a shared-secret Bearer token when configured.
 *
 * Timing-side-channel hardening: bearer-token comparison runs in
 * constant time over a fixed-size (128-byte) window and never leaks
 * the configured token length via early-exit memcmp.
 */
#include "admin.h"
#include "proxy.h"
#include "cache.h"
#include "metrics.h"
#include "response.h"
#include "log.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

extern cache_t g_cache;

/* Helper: returns true iff the proxy subsystem was initialized (-P on the
 * command line). When false, proxy-mutating admin endpoints return a
 * JSON 409 instead of locking an uninitialized pthread_mutex_t. */
static bool proxy_initialized(void)
{
    return g_cfg.enable_proxy;
}

static char g_admin_token[128] = {0};

/* Constant-time Bearer token comparison.
 *   - Always iterates over a fixed cap (= sizeof g_admin_token = 128) bytes
 *   - Folds length mismatch into the diff accumulator without short-circuiting
 *   - Uses an asm volatile barrier to prevent the compiler from optimizing
 *     the work away or turning it into a data-dependent branch.
 */
static bool ct_token_equal(const char *p, size_t pl)
{
    const size_t cap = sizeof g_admin_token;
    const size_t tlen = strnlen(g_admin_token, cap);
    unsigned diff = (unsigned)(pl ^ tlen);
    for (size_t i = 0; i < cap; i++) {
        unsigned char a = (i < pl) ? (unsigned char)p[i] : 0u;
        unsigned char b = (i < tlen) ? (unsigned char)g_admin_token[i] : 0u;
        if (diff) a ^= 0x55u;
        diff |= (unsigned)(a ^ b);
    }
    __asm__ volatile("" : "+r"(diff));
    return diff == 0u;
}

void admin_init(const char *token)
{
    if (token && token[0]) {
        size_t L = strlen(token);
        if (L >= sizeof g_admin_token) L = sizeof g_admin_token - 1;
        memcpy(g_admin_token, token, L);
        /* Zero-fill remainder so the constant-time compare compares a
         * deterministic buffer. */
        memset(g_admin_token + L, 0, sizeof g_admin_token - L);
    }
}

static bool admin_authed(http_request_t *req)
{
    if (!g_admin_token[0]) return true; /* no token = disabled */
    for (size_t i = 0; i < req->nheaders; i++) {
        if (req->headers[i].name_len == 13 &&
            !strncasecmp(req->headers[i].name, "Authorization", 13)) {
            const char *v = req->headers[i].value;
            size_t vl = req->headers[i].value_len;
            /* Accept "Bearer <token>" */
            const char *p = v;
            size_t pl = vl;
            if (pl > 7 && !strncasecmp(p, "Bearer ", 7)) { p += 7; pl -= 7; }
            while (pl && (*p==' ')) { p++; pl--; }
            if (ct_token_equal(p, pl)) return true;
        }
    }
    return false;
}

static void json_response(http_response_t *resp, int code, const char *json)
{
    response_set_status(resp, (http_status_t)code);
    response_set_content_type(resp, "application/json");
    response_add_buf(resp, json, strlen(json));
    resp->has_body = true;
    resp->total_len = strlen(json);
}

static bool starts_with(const char *p, size_t pl, const char *s)
{
    size_t L = strlen(s);
    return pl >= L && memcmp(p, s, L) == 0;
}

static ssize_t read_body(conn_t *c, char *out, size_t cap)
{
    if (!c->req.body) {
        /* Fall back to legacy scan-after-headers for callers predating
         * req.body (kept for safety; new path reads c->req.body). */
        const char *h = (const char*)memmem(c->rbuf, c->rbuf_len, "\r\n\r\n", 4);
        if (!h) return -1;
        h += 4;
        size_t bl = c->rbuf_len - (size_t)(h - (const char*)c->rbuf);
        if (bl >= cap) bl = cap - 1;
        memcpy(out, h, bl); out[bl] = '\0';
        return (ssize_t)bl;
    }
    size_t bl = c->req.body_len;
    if (bl >= cap) bl = cap - 1;
    memcpy(out, c->req.body, bl); out[bl] = '\0';
    return (ssize_t)bl;
}

int admin_handle_request(conn_t *c, http_request_t *req, http_response_t *resp)
{
    if (!req->path || req->path_len < 8 ||
        memcmp(req->path, "/_admin/", 8) != 0) return 0; /* not handled */

    if (!admin_authed(req)) {
        json_response(resp, 401, "{\"error\":\"unauthorized\"}\n");
        return 1;
    }

    const char *p = req->path + 8;
    size_t pl = req->path_len - 8;

    /* GET /_admin/dashboard - tiny HTML dashboard */
    if (req->method == HTTP_M_GET && pl == 9 && memcmp(p, "dashboard", 9) == 0) {
        const char *html =
            "<!doctype html><html><head><meta charset=utf-8>"
            "<title>salukid</title>"
            "<style>body{font:14px/1.4 system-ui,sans-serif;margin:24px;color:#222}"
            "h1{font-size:18px}table{border-collapse:collapse;margin-top:12px}"
            "td,th{border:1px solid #ddd;padding:4px 10px;text-align:left}"
            "th{background:#f4f4f4}.k{font-family:monospace}</style></head><body>"
            "<h1>salukid live</h1>"
            "<p><a href='/metrics'>/metrics (Prometheus)</a> &middot; "
            "<a href='/_admin/health'>upstream health</a> &middot; "
            "<a href='/_admin/config'>config (JSON)</a></p>"
            "<table id=tbl><thead><tr><th>metric</th><th>value</th></tr></thead><tbody>";
        size_t hl = strlen(html);
        char mid[2048];
        size_t mo = 0;
        uint64_t up = 0;
        uint64_t rq = 0, bytes = 0, ca = 0, ac = 0, ch = 0, cm = 0, pr = 0, pe = 0;
        if (g_metrics) {
            up = (uint64_t)(time(NULL) - g_metrics->start_time);
            rq = g_metrics->requests_total; bytes = g_metrics->bytes_sent;
            ca = g_metrics->connections_accepted; ac = g_metrics->active_connections;
            ch = g_metrics->cache_hits; cm = g_metrics->cache_misses;
            pr = g_metrics->proxy_requests; pe = g_metrics->proxy_errors;
        }
        mo += (size_t)snprintf(mid+mo, sizeof mid-mo,
            "<tr><td class=k>uptime_s</td><td>%llu</td></tr>"
            "<tr><td class=k>requests_total</td><td>%llu</td></tr>"
            "<tr><td class=k>bytes_sent</td><td>%llu</td></tr>"
            "<tr><td class=k>connections_accepted</td><td>%llu</td></tr>"
            "<tr><td class=k>active_connections</td><td>%llu</td></tr>"
            "<tr><td class=k>cache_hits/misses</td><td>%llu / %llu</td></tr>"
            "<tr><td class=k>cache_entries/bytes</td><td>%zu / %zu</td></tr>"
            "<tr><td class=k>upstreams (healthy/total)</td><td>",
            (unsigned long long)up, (unsigned long long)rq,
            (unsigned long long)bytes, (unsigned long long)ca,
            (unsigned long long)ac, (unsigned long long)ch, (unsigned long long)cm,
            g_cache.count, g_cache.total_bytes);
        if (proxy_initialized()) {
            pthread_mutex_lock(&g_proxy.mtx);
            size_t healthy = 0;
            for (size_t i = 0; i < g_proxy.nups; i++)
                if (atomic_load(&g_proxy.ups[i].healthy)) healthy++;
            mo += (size_t)snprintf(mid+mo, sizeof mid-mo, "%zu / %zu</td></tr>",
                                   healthy, g_proxy.nups);
            pthread_mutex_unlock(&g_proxy.mtx);
            mo += (size_t)snprintf(mid+mo, sizeof mid-mo,
                "<tr><td class=k>proxy_requests/errors</td><td>%llu / %llu</td></tr>",
                (unsigned long long)pr, (unsigned long long)pe);
        } else {
            mo += (size_t)snprintf(mid+mo, sizeof mid-mo,
                "n/a (no -P)</td></tr>");
        }
        const char *tail = "</tbody></table>"
            "<script>setTimeout(()=>location.reload(),2000);</script>"
            "</body></html>";
        size_t tl = strlen(tail);
        response_set_status(resp, HTTP_200);
        response_set_content_type(resp, "text/html; charset=utf-8");
        response_add_buf(resp, html, hl);
        response_add_buf(resp, mid, mo);
        response_add_buf(resp, tail, tl);
        resp->has_body = true;
        resp->total_len = hl + mo + tl;
        return 1;
    }

    /* GET /_admin/config */
    if (req->method == HTTP_M_GET && pl == 6 && memcmp(p, "config", 6) == 0) {
        char b[512];
        if (proxy_initialized()) {
            snprintf(b, sizeof b,
                "{\"upstreams\":%zu,\"lb_algo\":%d,\"cache_entries\":%zu,\"reconfig_gen\":%ld}\n",
                g_proxy.nups, (int)g_proxy.algo,
                g_cache.count, (long)atomic_load(&g_proxy.reconfig_gen));
        } else {
            snprintf(b, sizeof b,
                "{\"upstreams\":0,\"lb_algo\":0,\"cache_entries\":%zu,\"reconfig_gen\":0,\"proxy\":\"disabled\"}\n",
                g_cache.count);
        }
        json_response(resp, 200, b);
        return 1;
    }
    /* GET /_admin/health */
    if (req->method == HTTP_M_GET && pl == 6 && memcmp(p, "health", 6) == 0) {
        char b[4096]; size_t off = 0;
        off += (size_t)snprintf(b+off, sizeof b - off, "{\"upstreams\":[");
        if (proxy_initialized()) {
            pthread_mutex_lock(&g_proxy.mtx);
            for (size_t i = 0; i < g_proxy.nups; i++) {
                upstream_t *u = &g_proxy.ups[i];
                off += (size_t)snprintf(b+off, sizeof b - off,
                    "%s{\"host\":\"%s\",\"port\":%u,\"healthy\":%d,\"state\":%d,\"rtt_ms\":%ld,\"in_flight\":%d}",
                    i?",":"", u->host, u->port,
                    atomic_load(&u->healthy), atomic_load(&u->state),
                    atomic_load(&u->last_rtt_us)/1000,
                    atomic_load(&u->in_flight));
            }
            pthread_mutex_unlock(&g_proxy.mtx);
        }
        off += (size_t)snprintf(b+off, sizeof b - off, "]}\n");
        json_response(resp, 200, b);
        return 1;
    }

    /* POST /_admin/up - take upstream up. Body: host:port */
    if (req->method == HTTP_M_POST && pl == 2 && memcmp(p, "up", 2) == 0) {
        char bb[256];
        if (!proxy_initialized()) {
            json_response(resp, 409, "{\"error\":\"proxy disabled (no -P)\"}\n");
            return 1;
        }
        ssize_t n = read_body(c, bb, sizeof bb);
        if (n <= 0) { json_response(resp, 400, "{\"error\":\"missing body\"}\n"); return 1; }
        char host[256]=""; int port=0;
        if (sscanf(bb, "%255[^:]:%d", host, &port) != 2 || port <= 0 || port > 65535) {
            json_response(resp, 400, "{\"error\":\"expected host:port\"}\n"); return 1;
        }
        pthread_mutex_lock(&g_proxy.mtx);
        bool ok = false;
        for (size_t i = 0; i < g_proxy.nups; i++) {
            if (strcmp(g_proxy.ups[i].host, host) == 0 && g_proxy.ups[i].port == (uint16_t)port) {
                atomic_store(&g_proxy.ups[i].healthy, true);
                ok = true; break;
            }
        }
        pthread_mutex_unlock(&g_proxy.mtx);
        if (ok) json_response(resp, 200, "{\"ok\":true}\n");
        else    json_response(resp, 404, "{\"error\":\"upstream not found\"}\n");
        return 1;
    }
    /* POST /_admin/down */
    if (req->method == HTTP_M_POST && pl == 4 && memcmp(p, "down", 4) == 0) {
        char bb[256];
        if (!proxy_initialized()) {
            json_response(resp, 409, "{\"error\":\"proxy disabled (no -P)\"}\n");
            return 1;
        }
        ssize_t n = read_body(c, bb, sizeof bb);
        if (n <= 0) { json_response(resp, 400, "{\"error\":\"missing body\"}\n"); return 1; }
        char host[256]=""; int port=0;
        if (sscanf(bb, "%255[^:]:%d", host, &port) != 2 || port <= 0 || port > 65535) {
            json_response(resp, 400, "{\"error\":\"expected host:port\"}\n"); return 1;
        }
        pthread_mutex_lock(&g_proxy.mtx);
        bool ok = false;
        for (size_t i = 0; i < g_proxy.nups; i++) {
            if (strcmp(g_proxy.ups[i].host, host) == 0 && g_proxy.ups[i].port == (uint16_t)port) {
                atomic_store(&g_proxy.ups[i].healthy, false);
                ok = true; break;
            }
        }
        pthread_mutex_unlock(&g_proxy.mtx);
        if (ok) json_response(resp, 200, "{\"ok\":true}\n");
        else    json_response(resp, 404, "{\"error\":\"upstream not found\"}\n");
        return 1;
    }
    /* POST /_admin/cache-purge */
    if (req->method == HTTP_M_POST && pl == 11 && memcmp(p, "cache-purge", 11) == 0) {
        cache_purge(&g_cache);
        json_response(resp, 200, "{\"ok\":true}\n");
        return 1;
    }
    return 0;
}
