/*
 * modsec_stub.c - v1 stable-ABI ModSecurity-style WAF module.
 *
 * Demonstrates the ABI can support a production WAF. To build against
 * real libmodsecurity link with -lmodsecurity and replace the inline
 * rule set with msc_process_request_headers() etc.
 *
 * Built-in rules:
 *   - per-IP rate limiting via shared_incr (leaky bucket)
 *   - path traversal / null-byte rejection (defense-in-depth)
 *   - SQLi / XSS heuristic signatures
 *   - scanner User-Agent blocking
 *   - missing Host rejection on HTTP/1.1
 */
#define _GNU_SOURCE
#include "../include/salukid_hooks.h"
#include <ctype.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static const salukid_host_v1_t *H;

typedef struct { int rate_burst; bool paranoid; } cfg_t;
static cfg_t cfg = { .rate_burst = 100, .paranoid = false };

static int looks_like_injection(const char *s, size_t n)
{
    static const char *needles[] = {
        "union select", "' or 1=1", "' or '1'='1", "drop table",
        "information_schema", "';--", "<script", "javascript:",
        "../../../etc/passwd",
    };
    if (!s) return 0;
    char *lc = malloc(n + 1);
    if (!lc) return 0;
    for (size_t i = 0; i < n; i++) lc[i] = (char)tolower((unsigned char)s[i]);
    lc[n] = '\0';
    int found = 0;
    for (size_t i = 0; i < sizeof needles / sizeof needles[0]; i++) {
        if (strstr(lc, needles[i])) { found = 1; break; }
    }
    free(lc);
    return found;
}

static int bad_ua(const char *ua)
{
    if (!ua) return 0;
    return (strstr(ua, "sqlmap") || strstr(ua, "Nikto") ||
           strstr(ua, "nmap")   || strstr(ua, "dirbuster") ||
           strstr(ua, "acunetix")) ? 1 : 0;
}

static int deny(salukid_req_t *r, int code, const char *msg)
{
    salukid_resp_t *rs = H->resp_begin(r, code);
    H->resp_set_header(rs, "content-type", "application/json");
    char body[256];
    int n = snprintf(body, sizeof body, "{\"error\":\"%s\"}\n", msg);
    H->resp_send(rs, body, (size_t)n);
    return SALUKID_DENY;
}

static int on_req_hdr(void *ctx, salukid_req_t *r)
{
    (void)ctx;
    const char *path; size_t plen;
    H->path(r, &path, &plen);
    const char *qry;  size_t qlen;
    H->query(r, &qry, &qlen);
    const char *ua   = H->header_get(r, "user-agent");
    const char *host = H->header_get(r, "host");

    char key[96];
    snprintf(key, sizeof key, "modsec:rl:%s", H->remote_addr(r));
    int64_t count = H->shared_incr("modsec", key, 1, 1, 1);
    if (count > cfg.rate_burst) return deny(r, 429, "rate limited");

    for (size_t i = 0; i + 2 < plen; i++)
        if (!path[i] || (path[i] == '.' && path[i+1] == '.' && path[i+2] == '/'))
            return deny(r, 403, "blocked");

    if (qry && looks_like_injection(qry, qlen)) {
        H->log(SALUKID_LOG_WARN, "modsec: injection from %s", H->remote_addr(r));
        return deny(r, 403, "blocked by WAF");
    }
    if (path && looks_like_injection(path, plen)) return deny(r, 403, "blocked by WAF");
    if (bad_ua(ua)) return deny(r, 403, "scanner blocked");
    if (!host || !*host) return deny(r, 400, "missing Host");
    return SALUKID_PASS;
}

static int on_init(void **ctxp, const char *cfgs, size_t cl,
                   const salukid_host_v1_t *h, uint32_t id)
{
    H = h; (void)id;
    if (cfgs && cl) {
        if (memmem(cfgs, cl, "paranoid=1", 10)) cfg.paranoid = true;
        const char *b = memmem(cfgs, cl, "burst=", 6);
        if (b) cfg.rate_burst = atoi(b + 6);
    }
    *ctxp = &cfg;
    H->log(SALUKID_LOG_INFO, "modsec_stub loaded (burst=%d paranoid=%d)",
           cfg.rate_burst, cfg.paranoid);
    return 0;
}

static void on_shutdown(void *ctx) { (void)ctx; }

static const salukid_module_v1_t module = {
    .magic              = SALUKID_MODULE_MAGIC,
    .abi_version        = SALUKID_ABI_V1,
    .name               = "modsec_stub",
    .init               = on_init,
    .shutdown           = on_shutdown,
    .on_request_headers = on_req_hdr,
};

const salukid_module_v1_t *salukid_module_register_v1(void) { return &module; }
