/*
 * modapi.c - dlopen loader for the stable v1 ABI plus the host vtable
 * that modules call back into.
 *
 * Modules loaded via dlopen have access to salukid services only through
 * the host vtable - they don't (and shouldn't) resolve internal symbols.
 */

#include "modapi.h"
#include "conn.h"
#include "response.h"
#include "metrics.h"
#include "log.h"
#include "subrequester.h"
#include <dlfcn.h>
#include <pthread.h>

/* ---- per-loaded module ---- */
typedef struct salukid_module_entry {
    void                    *dlh;
    const salukid_module_v1_t *vt;
    void                    *ctx;
    uint32_t                 id;
    struct salukid_module_entry *next;
} salukid_module_entry_t;

struct salukid_modlist {
    salukid_module_entry_t *head;
    uint32_t                next_id;
};

/* ---- shared dict (hash + TTL, coarse mutex) ---- */

#define SHARD_BUCKETS 256
typedef struct sh_ent {
    char         *key;
    char         *val;
    int64_t       num;
    bool          is_num;
    time_t        expires;
    struct sh_ent *next;
} sh_ent_t;
typedef struct { sh_ent_t *head; pthread_mutex_t mtx; } sh_bucket_t;
static sh_bucket_t g_shared[SHARD_BUCKETS];
static pthread_once_t g_shared_once = PTHREAD_ONCE_INIT;

static uint64_t sh_hash(const char *scope, const char *k)
{
    uint64_t h = 1469598103934665603ULL;
    for (const char *c = scope; *c; c++) { h ^= (unsigned char)*c; h *= 1099511628211ULL; }
    h ^= 0x1F;
    for (const char *c = k; *c; c++) { h ^= (unsigned char)*c; h *= 1099511628211ULL; }
    return h;
}

static void sh_init_once(void)
{
    for (int i = 0; i < SHARD_BUCKETS; i++) {
        g_shared[i].head = NULL;
        pthread_mutex_init(&g_shared[i].mtx, NULL);
    }
}

int modapi_shared_init(void)
{
    pthread_once(&g_shared_once, sh_init_once);
    return 0;
}

void modapi_shared_shutdown(void)
{
    for (int i = 0; i < SHARD_BUCKETS; i++) {
        sh_ent_t *e = g_shared[i].head;
        while (e) { sh_ent_t *n = e->next; free(e->key); free(e->val); free(e); e = n; }
        pthread_mutex_destroy(&g_shared[i].mtx);
    }
}

int64_t modapi_shared_incr(const char *scope, const char *k,
                           int64_t delta, int64_t initial, uint32_t ttl_sec)
{
    modapi_shared_init();
    uint32_t b = (uint32_t)sh_hash(scope, k) % SHARD_BUCKETS;
    pthread_mutex_lock(&g_shared[b].mtx);
    time_t now = time(NULL);
    sh_ent_t *e = g_shared[b].head;
    while (e) {
        if (e->expires < now) { sh_ent_t *n = e->next; free(e->key); free(e->val); free(e); e = n; continue; }
        if (strcmp(e->key, k) == 0) {
            if (!e->is_num) { e->num = initial + delta; e->is_num = true; }
            else e->num += delta;
            e->expires = now + ttl_sec;
            int64_t v = e->num;
            pthread_mutex_unlock(&g_shared[b].mtx);
            return v;
        }
        e = e->next;
    }
    sh_ent_t *ne = calloc(1, sizeof *ne);
    if (!ne) { pthread_mutex_unlock(&g_shared[b].mtx); return initial + delta; }
    ne->key = strdup(k);
    if (!ne->key) { free(ne); pthread_mutex_unlock(&g_shared[b].mtx); return initial + delta; }
    ne->num = initial + delta;
    ne->is_num = true;
    ne->expires = now + ttl_sec;
    ne->next = g_shared[b].head;
    g_shared[b].head = ne;
    pthread_mutex_unlock(&g_shared[b].mtx);
    return initial + delta;
}

int modapi_shared_get(const char *scope, const char *k, char *out, size_t cap)
{
    modapi_shared_init();
    uint32_t b = (uint32_t)sh_hash(scope, k) % SHARD_BUCKETS;
    pthread_mutex_lock(&g_shared[b].mtx);
    time_t now = time(NULL);
    int rc = -1;
    for (sh_ent_t *e = g_shared[b].head; e; e = e->next) {
        if (e->expires < now) continue;
        if (strcmp(e->key, k) == 0) {
            if (e->is_num) snprintf(out, cap, "%lld", (long long)e->num);
            else snprintf(out, cap, "%s", e->val ? e->val : "");
            rc = 0;
            break;
        }
    }
    pthread_mutex_unlock(&g_shared[b].mtx);
    return rc;
}

int modapi_shared_set(const char *scope, const char *k, const char *v, uint32_t ttl_sec)
{
    modapi_shared_init();
    uint32_t b = (uint32_t)sh_hash(scope, k) % SHARD_BUCKETS;
    pthread_mutex_lock(&g_shared[b].mtx);
    time_t now = time(NULL);
    for (sh_ent_t *e = g_shared[b].head; e; e = e->next) {
        if (e->expires < now) continue;
        if (strcmp(e->key, k) == 0) {
            char *nv = strdup(v);
            if (!nv) { pthread_mutex_unlock(&g_shared[b].mtx); return -1; }
            free(e->val); e->val = nv; e->is_num = false; e->expires = now + ttl_sec;
            pthread_mutex_unlock(&g_shared[b].mtx); return 0;
        }
    }
    sh_ent_t *ne = calloc(1, sizeof *ne);
    if (!ne) { pthread_mutex_unlock(&g_shared[b].mtx); return -1; }
    ne->key = strdup(k);
    ne->val = strdup(v);
    if (!ne->key || !ne->val) {
        free(ne->key); free(ne->val); free(ne);
        pthread_mutex_unlock(&g_shared[b].mtx); return -1;
    }
    ne->is_num = false;
    ne->expires = now + ttl_sec;
    ne->next = g_shared[b].head;
    g_shared[b].head = ne;
    pthread_mutex_unlock(&g_shared[b].mtx);
    return 0;
}

/* ---- Host vtable (functions exposed to modules) ---- */

static salukid_req_t  *H_to_req(conn_t *c) { return (salukid_req_t*)c; }
static salukid_resp_t *H_to_resp(conn_t *c) { return (salukid_resp_t*)&c->resp; }
static conn_t         *H_from_req(salukid_req_t *r) { return (conn_t*)r; }

static void H_log(int level, const char *fmt, ...)
{
    char buf[512];
    va_list ap; va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    if (n > 0) log_emit_plain(level, "%s", buf);
}
static const char *H_config_get(const char *key, const char *dflt)
{
    if (!strcmp(key, "www_dir")) return g_cfg.www_dir;
    if (!strcmp(key, "user"))    return g_cfg.user;
    return dflt;
}
static int64_t H_config_get_int(const char *key, int64_t dflt)
{
    if (!strcmp(key, "cb_threshold"))    return g_cfg.cb_threshold;
    if (!strcmp(key, "cb_recovery_ms"))  return g_cfg.cb_recovery_ms;
    if (!strcmp(key, "cache_max_mb"))    return (int64_t)g_cfg.cache_max_mb;
    if (!strcmp(key, "workers"))         return (int64_t)g_cfg.num_workers;
    return dflt;
}
static const char *H_method(salukid_req_t *r) { return http_method_str(((conn_t*)r)->req.method); }
static int H_path(salukid_req_t *r, const char **out, size_t *outlen)
{ conn_t *c = (conn_t*)r; *out = c->req.path; *outlen = c->req.path_len; return 0; }
static int H_query(salukid_req_t *r, const char **out, size_t *outlen)
{ conn_t *c = (conn_t*)r; *out = c->req.query ? c->req.query : ""; *outlen = c->req.query_len; return 0; }
static int H_authority(salukid_req_t *r, const char **out, size_t *outlen)
{ conn_t *c = (conn_t*)r; *out = c->req.host; *outlen = strlen(c->req.host); return 0; }
static const char *H_scheme(salukid_req_t *r) { return ((conn_t*)r)->tls ? "https" : "http"; }
static const char *H_remote_addr(salukid_req_t *r) { return ((conn_t*)r)->peer; }
static uint16_t H_remote_port(salukid_req_t *r) { return ((conn_t*)r)->peer_port; }

static const char *H_header_get(salukid_req_t *r, const char *name)
{
    conn_t *c = (conn_t*)r;
    size_t nl = strlen(name);
    for (size_t i = 0; i < c->req.nheaders; i++) {
        if (c->req.headers[i].name_len == nl &&
            !strncasecmp(c->req.headers[i].name, name, nl)) {
            /* Return a NUL-terminated copy via arena (cached in slot) */
            static __thread char tlsbuf[2048];
            size_t vl = MIN(c->req.headers[i].value_len, sizeof tlsbuf - 1);
            memcpy(tlsbuf, c->req.headers[i].value, vl);
            tlsbuf[vl] = '\0';
            return tlsbuf;
        }
    }
    return NULL;
}
static size_t H_header_count(salukid_req_t *r) { return ((conn_t*)r)->req.nheaders; }
static const salukid_kv_t *H_header_idx(salukid_req_t *r, size_t i)
{
    conn_t *c = (conn_t*)r;
    if (i >= c->req.nheaders) return NULL;
    return (const salukid_kv_t*)&c->req.headers[i];
}

static int H_set_path(salukid_req_t *r, const char *p, size_t plen)
{
    conn_t *c = (conn_t*)r;
    if (plen >= sizeof c->req.uri) return -1;
    /* Copy and re-set path/query split */
    memmove(c->req.uri, p, plen); c->req.uri[plen] = '\0';
    c->req.uri_len = plen;
    c->req.path = c->req.uri; c->req.path_len = plen;
    c->req.query = NULL; c->req.query_len = 0;
    return 0;
}
static int H_set_header(salukid_req_t *r, const char *n, const char *v)
{ (void)r;(void)n;(void)v; return 0; /* we'll add to a mutation list for v2 */ }
static int H_add_header(salukid_req_t *r, const char *n, const char *v)
{ (void)r;(void)n;(void)v; return 0; }
static int H_remove_header(salukid_req_t *r, const char *n) { (void)r;(void)n; return 0; }

static salukid_resp_t *H_resp_begin(salukid_req_t *r, int code) {
    conn_t *c = (conn_t*)r;
    http_response_t *hr = &c->resp;
    /* Idempotent: if resp is already initialised (head != NULL), just set
     * the status. Modules may call resp_begin multiple times; the last
     * status wins, but slices accumulate. Core response_init is only
     * called once. */
    if (!hr->head) {
        response_init(hr, &c->arena, c->req.method == HTTP_M_HEAD,
                      c->req.version == HTTP_VER_11 && !c->req.connection_close);
    }
    response_set_status(hr, code);
    return (salukid_resp_t*)hr;
}
static void H_resp_set_status(salukid_resp_t *rs, int code) {
    if (!rs) return;
    response_set_status((http_response_t*)rs, code);
}
static salukid_resp_t *resp_default(salukid_resp_t *rs, salukid_req_t *r) {
    return rs ? rs : H_resp_begin(r, 200);
}
static void H_resp_set_header(salukid_resp_t *rs, const char *n, const char *v)
{
    if (!rs) return;
    http_response_t *hr = (http_response_t*)rs;
    if (!strcasecmp(n, "content-type")) response_set_content_type(hr, v);
    else if (!strcasecmp(n, "etag"))    response_set_etag(hr, v);
    else {
        size_t need = strlen(n) + strlen(v) + 8;
        char *b = arena_alloc(hr->arena, need);
        if (!b) return;
        int bl = snprintf(b, need, "%s: %s\r\n", n, v);
        slice_t *sl = arena_alloc(hr->arena, sizeof *sl);
        if (!sl) return;
        sl->kind = SLICE_BUF; sl->base = b; sl->len = (size_t)bl;
        sl->next = hr->head; hr->head = sl; if (!hr->tail) hr->tail = sl;
    }
}
static void H_resp_send(salukid_resp_t *rs, const void *buf, size_t len)
{
    if (!rs) return;
    response_add_buf((http_response_t*)rs, buf, len);
    ((http_response_t*)rs)->has_body = true;
}
static void H_resp_send_str(salukid_resp_t *rs, const char *s)
{
    if (!rs) return;
    H_resp_send(rs, s, strlen(s));
}

static void *H_mem_alloc(salukid_req_t *r, size_t sz) { return arena_alloc(&((conn_t*)r)->arena, sz); }
static char *H_mem_strdup(salukid_req_t *r, const char *s)
{ return arena_strndup(&((conn_t*)r)->arena, s, strlen(s)); }

static void H_resume(salukid_req_t *r, void *tag) { (void)r; (void)tag; /* re-armed via epoll */ }
static uint64_t H_now_ns(void)
{ struct timespec ts; clock_gettime(CLOCK_REALTIME,&ts); return (uint64_t)ts.tv_sec*1000000000ULL + ts.tv_nsec; }

static void H_local_set(salukid_req_t *r, uint32_t mid, void *p) { (void)r;(void)mid;(void)p; }
static void *H_local_get(salukid_req_t *r, uint32_t mid) { (void)r;(void)mid; return NULL; }

/* Forward decl for async http_call trampoline */
static void http_call_trampoline(conn_t *c, int status,
                                 const subreq_kv_t *hdrs, size_t nhdrs,
                                 const uint8_t *body, size_t blen,
                                 void *module_ctx, void *tag);

static int H_http_call(salukid_req_t *r,
                       const char *method, const char *url,
                       const salukid_kv_t *hdrs, size_t nhdrs,
                       const uint8_t *body, size_t blen,
                       uint32_t timeout_ms,
                       salukid_subreq_cb cb, void *tag)
{
    conn_t *c = H_from_req(r);
    subrequest_t *sr = subrequest_new();
    if (!sr) return -1;

    /* Copy method/url/body into sr (sr is heap-allocated, body is copied in worker) */
    size_t ml = strlen(method);
    if (ml >= sizeof sr->method) { subrequest_free(sr); return -1; }
    memcpy(sr->method, method, ml); sr->method[ml] = '\0';
    size_t ul = strlen(url);
    if (ul >= sizeof sr->url) { subrequest_free(sr); return -1; }
    memcpy(sr->url, url, ul); sr->url[ul] = '\0';

    /* Duplicate body on the heap (the arena body may be gone by the time
     * the worker transmits) */
    if (body && blen) {
        uint8_t *bc = malloc(blen);
        if (!bc) { subrequest_free(sr); return -1; }
        memcpy(bc, body, blen);
        sr->body = bc;
        sr->body_len = blen;
        sr->heap_body = true;
    }
    /* Headers: copy to heap so they outlive the caller. */
    if (nhdrs) {
        subreq_kv_t *kh = calloc(nhdrs, sizeof *kh);
        if (!kh) { subrequest_free(sr); return -1; }
        for (size_t i = 0; i < nhdrs; i++) {
            size_t nl = hdrs[i].nlen ? hdrs[i].nlen : strlen(hdrs[i].name);
            size_t vl = hdrs[i].vlen ? hdrs[i].vlen : strlen(hdrs[i].val);
            char *nm = malloc(nl + 1); char *vl2 = malloc(vl + 1);
            if (!nm || !vl2) { free(nm); free(vl2);
                for (size_t j = 0; j < i; j++) { free((void*)kh[j].name); free((void*)kh[j].value); }
                free(kh); subrequest_free(sr); return -1;
            }
            memcpy(nm, hdrs[i].name, nl); nm[nl] = '\0';
            memcpy(vl2, hdrs[i].val, vl); vl2[vl] = '\0';
            kh[i].name = nm; kh[i].value = vl2;
        }
        sr->headers = kh;
        sr->nheaders = nhdrs;
        sr->heap_headers = true;
    }
    sr->timeout_ms = timeout_ms ? timeout_ms : SALUKID_SUBREQ_DEFAULT_MS;
    sr->origin = c;
    sr->cb = http_call_trampoline;
    sr->module_ctx = (void*)cb;
    sr->tag = tag;

    if (subrequester_submit(sr) < 0) {
        /* Queue full: 503 backpressure. subrequest_free cleans heap_*. */
        subrequest_free(sr);
        errno = EBUSY;
        return -1;
    }
    c->pending_subreq = sr;
    c->state = CONN_SUBREQ_PENDING;
    return 0;
}

static void http_call_trampoline(conn_t *c, int status,
                                 const subreq_kv_t *hdrs, size_t nhdrs,
                                 const uint8_t *body, size_t blen,
                                 void *module_ctx, void *tag)
{
    salukid_subreq_cb cb = (salukid_subreq_cb)module_ctx;
    if (!cb) return;
    /* Convert native subreq_kv_t (NUL-term strings) to salukid_kv_t */
    salukid_kv_t stack_kv[16];
    memset(stack_kv, 0, sizeof(stack_kv));
    memset(stack_kv, 0, sizeof(stack_kv));
    salukid_kv_t *kvp = stack_kv;
    if (nhdrs > 16) {
        kvp = calloc(nhdrs, sizeof *kvp);
        if (!kvp) { cb(H_to_req(c), 500, NULL, 0, NULL, 0, tag); return; }
    }
    size_t i;
    for (i = 0; i < nhdrs && hdrs; i++) {
        kvp[i].name = hdrs[i].name;
        kvp[i].nlen = strlen(hdrs[i].name);
        kvp[i].val = hdrs[i].value;
        kvp[i].vlen = strlen(hdrs[i].value);
    }
    (void)cb(H_to_req(c), status, kvp, nhdrs, body, blen, tag);
    if (kvp != stack_kv) free(kvp);
}

static const salukid_host_v1_t g_host_v1 = {
    .host_abi        = SALUKID_ABI_V1,
    .server_version  = SALUKID_SERVER_NAME,
    .log             = H_log,
    .config_get      = H_config_get,
    .config_get_int  = H_config_get_int,
    .method          = H_method,
    .path            = H_path,
    .query           = H_query,
    .authority       = H_authority,
    .scheme          = H_scheme,
    .remote_addr     = H_remote_addr,
    .remote_port     = H_remote_port,
    .header_get      = H_header_get,
    .header_count    = H_header_count,
    .header_idx      = H_header_idx,
    .set_path        = H_set_path,
    .set_header      = H_set_header,
    .add_header      = H_add_header,
    .remove_header   = H_remove_header,
    .resp_begin      = H_resp_begin,
    .resp_set_status = H_resp_set_status,
    .resp_set_header = H_resp_set_header,
    .resp_send       = H_resp_send,
    .resp_send_str   = H_resp_send_str,
    .mem_alloc       = H_mem_alloc,
    .mem_strdup      = H_mem_strdup,
    .shared_incr     = modapi_shared_incr,
    .shared_get      = modapi_shared_get,
    .shared_set      = modapi_shared_set,
    .resume          = H_resume,
    .now_ns          = H_now_ns,
    .http_call       = H_http_call,
    .local_set       = H_local_set,
    .local_get       = H_local_get,
};

/* ---- Module lifecycle ---- */

int modapi_load(salukid_modlist_t **ml, const char *path, const char *cfg, size_t cfglen)
{
    if (!*ml) { *ml = calloc(1, sizeof **ml); if (!*ml) return -1; }
    void *h = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (!h) { salukid_log(LOG_ERR, "modapi: dlopen %s: %s", path, dlerror()); return -1; }

    typedef const salukid_module_v1_t *(*reg_fn)(void);
    reg_fn reg = (reg_fn)dlsym(h, "salukid_module_register_v1");
    if (!reg) { dlclose(h); salukid_log(LOG_ERR, "modapi: %s missing salukid_module_register_v1", path); return -1; }
    const salukid_module_v1_t *vt = reg();
    if (!vt || vt->magic != SALUKID_MODULE_MAGIC || vt->abi_version != SALUKID_ABI_V1) {
        dlclose(h); salukid_log(LOG_ERR, "modapi: %s bad ABI", path); return -1;
    }

    salukid_module_entry_t *e = calloc(1, sizeof *e);
    if (!e) { dlclose(h); return -1; }
    e->dlh = h; e->vt = vt; e->id = (*ml)->next_id++;
    void *ctx = NULL;
    if (vt->ctx_size) {
        ctx = calloc(1, vt->ctx_size);
        if (!ctx) { free(e); dlclose(h); return -1; }
    }
    if (vt->init && vt->init(&ctx, cfg, cfglen, &g_host_v1, e->id) != 0) {
        salukid_log(LOG_ERR, "modapi: %s init failed", vt->name);
        free(ctx); free(e); dlclose(h); return -1;
    }
    e->ctx = ctx;
    e->next = (*ml)->head; (*ml)->head = e;
    salukid_log(LOG_INFO, "modapi: loaded %s (id=%u, abi=v1)", vt->name, e->id);
    return 0;
}

void modapi_unload_all(salukid_modlist_t *ml)
{
    if (!ml) return;
    for (salukid_module_entry_t *e = ml->head; e; ) {
        salukid_module_entry_t *n = e->next;
        if (e->vt->shutdown) e->vt->shutdown(e->ctx);
        free(e->ctx);
        dlclose(e->dlh);
        free(e);
        e = n;
    }
    free(ml);
}

int modapi_reload_all(salukid_modlist_t *ml)
{
    if (!ml) return 0;
    for (salukid_module_entry_t *e = ml->head; e; e = e->next) {
        if (e->vt->reload) e->vt->reload(e->ctx, NULL, 0);
    }
    return 0;
}

int modapi_run_request_headers(salukid_modlist_t *ml, struct conn *c)
{
    if (!ml) return SALUKID_PASS;
    /* Modules call resp_begin to emit a response; otherwise return PASS
     * without touching c->resp (serve_request will init it). */
    c->resp.head = c->resp.tail = NULL;
    int result = SALUKID_PASS;
    for (salukid_module_entry_t *e = ml->head; e; e = e->next) {
        if (!e->vt->on_request_headers) continue;
        int rc = e->vt->on_request_headers(e->ctx, H_to_req(c));
        if (rc == SALUKID_HANDLED || rc == SALUKID_DENY) { result = rc; break; }
        if (rc == SALUKID_AGAIN) { result = SALUKID_AGAIN; break; }
    }
    return result;
}

int modapi_run_response_headers(salukid_modlist_t *ml, struct conn *c)
{
    if (!ml) return SALUKID_PASS;
    for (salukid_module_entry_t *e = ml->head; e; e = e->next) {
        if (!e->vt->on_response_headers) continue;
        int rc = e->vt->on_response_headers(e->ctx, H_to_req(c), H_to_resp(c));
        if (rc == SALUKID_HANDLED || rc == SALUKID_DENY) return rc;
    }
    return SALUKID_PASS;
}
