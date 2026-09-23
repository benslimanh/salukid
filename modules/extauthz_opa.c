/*
 * extauthz_opa.c - Async out-of-process authorization against OPA via the
 * subrequester thread pool.
 *
 * Lifecycle:
 *   - on_req_hdr builds a subrequest_t on the heap (not arena!) and
 *     submits it; returns SALUKID_AGAIN.
 *   - Worker performs blocking HTTP POST; completion fires on the main
 *     epoll thread. On allow, we call serve_request_on_conn(c) to resume
 *     normal serving (request_headers phase is skipped via req_mod_done);
 *     on deny/error we build a response and call finalize_conn_response.
 */
#define _GNU_SOURCE
#include "../include/salukid_hooks.h"
#include "../include/subrequester.h"
#include "../include/conn.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>

#ifndef MIN
#define MIN(a,b) ((a)<(b)?(a):(b))
#endif

static const salukid_host_v1_t *H;

typedef struct {
    char     url[512];
    int      fail_open;
    int      cache_ttl;
    uint32_t timeout_ms;
} cfg_t;
static cfg_t cfg = {
    .url = "http://127.0.0.1:8181/v1/data/http/authz/allow",
    .fail_open = 0, .cache_ttl = 10, .timeout_ms = 50
};

static void on_subreq_done(conn_t *c, int status,
                           const subreq_kv_t *hdrs, size_t nhdrs,
                           const uint8_t *body, size_t blen,
                           void *mctx, void *tag);

static int on_req_hdr(void *ctx, salukid_req_t *r)
{
    (void)ctx;
    conn_t *c = (conn_t*)r;

    const char *m = H->method(r);
    const char *p; size_t pl; H->path(r, &p, &pl);
    const char *authz = H->header_get(r, "authorization");
    if (!authz) authz = "";
    char dkey[256];
    int dl = snprintf(dkey, sizeof dkey, "opa:%s|%.*s|%.*s", m,
                      (int)MIN(pl, 96), p, 48, authz);
    (void)dl;
    char cached[16];
    if (cfg.cache_ttl > 0 && H->shared_get("opa", dkey, cached, sizeof cached) == 0) {
        if (cached[0] == '1') return SALUKID_PASS;
        if (cached[0] == '0') goto deny;
    }

    const char *host = H->header_get(r, "host"); if (!host) host = "";
    char input[2048];
    int il = snprintf(input, sizeof input,
        "{\"input\":{\"method\":\"%s\",\"path\":\"%.*s\","
         "\"host\":\"%s\",\"remote_addr\":\"%s\","
         "\"headers\":{\"authorization\":\"%s\"}}}",
        m, (int)pl, p, host, H->remote_addr(r), authz);
    if (il < 0) goto fail_500;

    subrequest_t *sr = subrequest_new();
    if (!sr) goto fail_500;
    snprintf(sr->method, sizeof sr->method, "POST");
    snprintf(sr->url, sizeof sr->url, "%s", cfg.url);
    /* Copy body into heap (sr is heap allocated; we use a separate
     * malloc so the worker doesn't touch arena memory) */
    uint8_t *bcopy = malloc((size_t)il + 1);
    if (!bcopy) { subrequest_free(sr); goto fail_500; }
    memcpy(bcopy, input, (size_t)il); bcopy[il] = '\0';
    sr->body = bcopy;
    sr->body_len = (size_t)il;
    sr->heap_body = true;
    sr->timeout_ms = cfg.timeout_ms;
    sr->origin = c;
    sr->cb = on_subreq_done;
    sr->module_ctx = NULL;
    /* strdup tag for cache key */
    char *tag = strdup(dkey);
    if (!tag) { free(bcopy); subrequest_free(sr); goto fail_500; }
    sr->tag = tag;
    static const subreq_kv_t hdrs[] = { {"Content-Type","application/json"} };
    sr->headers = hdrs; sr->nheaders = 1;

    c->pending_subreq = sr;
    c->state = CONN_SUBREQ_PENDING;
    if (subrequester_submit(sr) < 0) {
        /* Queue full: 503 backpressure. Note: submit freed nothing on
         * failure because we haven't handed off, so clean up. */
        c->pending_subreq = NULL;
        c->state = CONN_READING;
        free(bcopy); free(tag); subrequest_free(sr);
        goto fail_503;
    }
    return SALUKID_AGAIN;

deny: {
    salukid_resp_t *rs = H->resp_begin(r, 403);
    H->resp_set_header(rs, "content-type", "application/json");
    H->resp_send_str(rs, "{\"error\":\"forbidden by policy\"}\n");
    return SALUKID_DENY;
}
fail_503: {
    salukid_resp_t *rs = H->resp_begin(r, 503);
    H->resp_set_header(rs, "content-type", "application/json");
    H->resp_send_str(rs, "{\"error\":\"service unavailable\"}\n");
    return SALUKID_DENY;
}
fail_500: {
    salukid_resp_t *rs = H->resp_begin(r, 500);
    H->resp_set_header(rs, "content-type", "application/json");
    H->resp_send_str(rs, "{\"error\":\"authz unavailable\"}\n");
    return SALUKID_DENY;
}
}

static void on_subreq_done(conn_t *c, int status,
                           const subreq_kv_t *hdrs,
                           size_t nhdrs,
                           const uint8_t *body, size_t blen,
                           void *mctx, void *tag)
{
    (void)hdrs; (void)nhdrs; (void)mctx;
    int allow = 0;
    const char *dkey = tag;
    /* The subrequest_t and its heap_body/heap_headers are freed by
     * subrequester_drain after this callback returns. Just clear the
     * connection's weak pointer. */
    c->pending_subreq = NULL;
    free(tag);

    if (status == 504) {
        /* Timeout */
        if (cfg.fail_open) allow = 1;
        else {
            salukid_resp_t *rs = H->resp_begin((salukid_req_t*)c, 504);
            H->resp_set_header(rs, "content-type", "application/json");
            H->resp_send_str(rs, "{\"error\":\"authz timeout\"}\n");
            goto do_finalize;
        }
    } else if (status != 200 || !body) {
        if (cfg.fail_open) allow = 1;
        else {
            salukid_resp_t *rs = H->resp_begin((salukid_req_t*)c, 503);
            H->resp_set_header(rs, "content-type", "application/json");
            H->resp_send_str(rs, "{\"error\":\"authz unavailable\"}\n");
            goto do_finalize;
        }
    } else {
        if (blen > 16) {
            const void *r = memmem(body, blen, "\"result\"", 8);
            if (r) {
                const char *p = memchr(r, ':', blen - (size_t)((const char*)r - (const char*)body));
                if (p) {
                    while (*p == ':' || *p == ' ') p++;
                    if (blen > (size_t)((const char*)p - (const char*)body) + 4 &&
                        !strncmp(p, "true", 4)) allow = 1;
                }
            }
        }
    }

    if (cfg.cache_ttl > 0 && dkey && dkey[0])
        H->shared_set("opa", dkey, allow ? "1" : "0", (uint32_t)cfg.cache_ttl);

    if (!allow) {
        salukid_resp_t *rs = H->resp_begin((salukid_req_t*)c, 403);
        H->resp_set_header(rs, "content-type", "application/json");
        H->resp_send_str(rs, "{\"error\":\"forbidden by policy\"}\n");
        goto do_finalize;
    }
    /* Allow: resume normal serving. Skip the module request_headers
     * phase (req_mod_done=true) so we don't re-submit another OPA call. */
    c->state = CONN_READING;
    c->req_mod_done = true;
    serve_request_on_conn(c);
    return;

do_finalize:
    finalize_conn_response(c);
}

static int on_init(void **ctxp, const char *cfgs, size_t cl,
                   const salukid_host_v1_t *h, uint32_t id)
{
    (void)id;
    H = h; *ctxp = &cfg;
    if (cfgs && cl) {
        char buf[1024]; size_t L = MIN(cl, sizeof buf - 1);
        memcpy(buf, cfgs, L); buf[L] = '\0';
        const char *u = strstr(buf, "url=");
        if (u) {
            u += 4; const char *e = strchrnul(u, ',');
            size_t ul = (size_t)(e - u);
            if (ul >= sizeof cfg.url) ul = sizeof cfg.url - 1;
            memcpy(cfg.url, u, ul); cfg.url[ul] = '\0';
        }
        if (strstr(buf, "fail_open=1")) cfg.fail_open = 1;
        const char *t = strstr(buf, "timeout_ms=");
        if (t) cfg.timeout_ms = (uint32_t)atoi(t+11);
        const char *ct = strstr(buf, "cache_ttl=");
        if (ct) cfg.cache_ttl = atoi(ct+10);
    }
    H->log(SALUKID_LOG_INFO,
           "extauthz_opa loaded url=%s fail_open=%d timeout=%ums cache_ttl=%ds",
           cfg.url, cfg.fail_open, cfg.timeout_ms, cfg.cache_ttl);
    return 0;
}

static void on_shutdown(void *ctx) { (void)ctx; }

static const salukid_module_v1_t module = {
    .magic              = SALUKID_MODULE_MAGIC,
    .abi_version        = SALUKID_ABI_V1,
    .name               = "extauthz_opa",
    .init               = on_init,
    .shutdown           = on_shutdown,
    .on_request_headers = on_req_hdr,
};
const salukid_module_v1_t *salukid_module_register_v1(void) { return &module; }
