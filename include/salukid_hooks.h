/*
 * salukid_hooks.h - Stable module ABI v1.
 *
 * Contract between salukid core and .so modules (dlopen). Every field is
 * versioned; v1 is frozen. New capabilities arrive as new exported
 * symbols (salukid_module_register_v2) so v1 modules never silently break.
 *
 * Design:
 *   - POD structs only; no libc types in the ABI.
 *   - Every callback returns an explicit status; modules may never abort/exit.
 *   - salukid exposes helpers to modules through the host vtable; modules
 *     do NOT resolve salukid symbols via dlsym.
 *   - The callback shape mirrors proxy-wasm so the WAMR shim is also a v1
 *     module (architectural symmetry).
 */
#ifndef SALUKID_HOOKS_H
#define SALUKID_HOOKS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SALUKID_ABI_V1       1u
#define SALUKID_MODULE_MAGIC UINT32_C(0x53414c53)  /* "SALS" */

/* Callback return codes */
#define SALUKID_PASS      0   /* continue chain */
#define SALUKID_HANDLED   1   /* module produced a final response */
#define SALUKID_DENY      2   /* deny (403); module has set response */
#define SALUKID_AGAIN     3   /* async pending; core will call on_wakeup */

/* Log levels passed to host->log() */
#define SALUKID_LOG_ERR   3
#define SALUKID_LOG_WARN  4
#define SALUKID_LOG_INFO  6
#define SALUKID_LOG_DEBUG 7

/* Opaque handles */
typedef struct salukid_req  salukid_req_t;
typedef struct salukid_resp salukid_resp_t;

/* Key/value pair for headers */
typedef struct { const char *name; size_t nlen; const char *val; size_t vlen; } salukid_kv_t;
typedef int (*salukid_subreq_cb)(salukid_req_t *r, int status,
                                const salukid_kv_t *hdrs, size_t nhdrs,
                                const uint8_t *body, size_t blen, void *tag);

/* --- Host vtable: helpers exposed to modules --- */
typedef struct salukid_host_v1 {
    uint32_t    host_abi;        /* SALUKID_ABI_V1 */
    const char *server_version;  /* "salukid/0.1.0" */

    /* logging */
    void        (*log)(int level, const char *fmt, ...);

    /* config */
    const char *(*config_get)(const char *key, const char *dflt);
    int64_t     (*config_get_int)(const char *key, int64_t dflt);

    /* request accessors (all return lengths via out-param; strings are not
     * guaranteed NUL-terminated unless explicitly allocated by strndup) */
    const char       *(*method)(salukid_req_t *r);            /* static string, e.g. "GET" */
    int               (*path)(salukid_req_t *r, const char **out, size_t *outlen);
    int               (*query)(salukid_req_t *r, const char **out, size_t *outlen);
    int               (*authority)(salukid_req_t *r, const char **out, size_t *outlen);
    const char       *(*scheme)(salukid_req_t *r);            /* "http" or "https" */
    const char       *(*remote_addr)(salukid_req_t *r);       /* NUL-terminated */
    uint16_t          (*remote_port)(salukid_req_t *r);
    const char       *(*header_get)(salukid_req_t *r, const char *name);
    size_t            (*header_count)(salukid_req_t *r);
    const salukid_kv_t *(*header_idx)(salukid_req_t *r, size_t i);

    /* request mutation (rewrites / authz header injection) */
    int               (*set_path)(salukid_req_t *r, const char *p, size_t plen);
    int               (*set_header)(salukid_req_t *r, const char *n, const char *v);
    int               (*add_header)(salukid_req_t *r, const char *n, const char *v);
    int               (*remove_header)(salukid_req_t *r, const char *n);

    /* response (pass NULL for rs when called from request phase; host will
     * bind to the current response) */
    salukid_resp_t *(*resp_begin)(salukid_req_t *r, int code);
    void           (*resp_set_status)(salukid_resp_t *rs, int code);
    void           (*resp_set_header)(salukid_resp_t *rs, const char *n, const char *v);
    void           (*resp_send)(salukid_resp_t *rs, const void *buf, size_t len);
    void           (*resp_send_str)(salukid_resp_t *rs, const char *s);

    /* per-request arena allocation (freed when request ends) */
    void             *(*mem_alloc)(salukid_req_t *r, size_t sz);
    char             *(*mem_strdup)(salukid_req_t *r, const char *s);

    /* shared dict (rate-limits, counters) */
    int64_t           (*shared_incr)(const char *scope, const char *k,
                                     int64_t delta, int64_t initial, uint32_t ttl_sec);
    int               (*shared_get)(const char *scope, const char *k,
                                    char *out, size_t out_cap);
    int               (*shared_set)(const char *scope, const char *k,
                                    const char *v, uint32_t ttl_sec);

    /* async resume */
    void              (*resume)(salukid_req_t *r, void *tag);
    uint64_t          (*now_ns)(void);

    /* HTTP subrequest (used by ext_authz / proxy-wasm http_call) */
    int               (*http_call)(salukid_req_t *r,
                                   const char *method, const char *url,
                                   const salukid_kv_t *hdrs, size_t nhdrs,
                                   const uint8_t *body, size_t blen,
                                   uint32_t timeout_ms,
                                   salukid_subreq_cb cb, void *tag);

    /* Set a per-request local storage slot for this module (indexed by
     * module id assigned at load time). */
    void              (*local_set)(salukid_req_t *r, uint32_t module_id, void *p);
    void             *(*local_get)(salukid_req_t *r, uint32_t module_id);
} salukid_host_v1_t;

/* --- Module vtable --- */
typedef struct salukid_module_v1 {
    uint32_t      magic;          /* SALUKID_MODULE_MAGIC */
    uint32_t      abi_version;    /* SALUKID_ABI_V1 */
    size_t        ctx_size;       /* 0 for no per-process state */
    const char   *name;           /* static NUL-terminated ASCII */

    /* lifecycle */
    int  (*init)(void **ctxp, const char *cfg, size_t cfglen,
                 const salukid_host_v1_t *host, uint32_t module_id);
    void (*shutdown)(void *ctx);
    int  (*reload)(void *ctx, const char *cfg, size_t cfglen);

    /* per-request hooks */
    int  (*on_request_headers)(void *ctx, salukid_req_t *r);
    int  (*on_request_body)(void *ctx, salukid_req_t *r,
                            const uint8_t *data, size_t len, int last);
    int  (*on_response_headers)(void *ctx, salukid_req_t *r, salukid_resp_t *rs);
    int  (*on_response_body)(void *ctx, salukid_req_t *r, salukid_resp_t *rs,
                             uint8_t **buf, size_t *len, int last);
    void (*on_log)(void *ctx, salukid_req_t *r, salukid_resp_t *rs);
    int  (*on_wakeup)(void *ctx, salukid_req_t *r, void *tag, int status);
} salukid_module_v1_t;

/* Modules export this symbol. */
const salukid_module_v1_t *salukid_module_register_v1(void);

/* Helper macro to make C modules ergonomic */
#define SALUKID_MODULE_V1(name_str)                                        \
    static const salukid_host_v1_t *H;                                     \
    static uint32_t                MID;                                    \
    static void                   *MCTX;                                   \
    static int  M_init(void **, const char *, size_t,                     \
                       const salukid_host_v1_t *, uint32_t);               \
    static void M_shutdown(void *);                                        \
    static int  M_req_hdr(void *, salukid_req_t *);                        \
    static const salukid_module_v1_t M_v1 = {                              \
        .magic           = SALUKID_MODULE_MAGIC,                           \
        .abi_version     = SALUKID_ABI_V1,                                 \
        .name            = (name_str),                                     \
        .init            = M_init,                                         \
        .shutdown        = M_shutdown,                                     \
        .reload          = NULL,                                           \
        .on_request_headers = M_req_hdr,                                   \
        .on_request_body    = NULL,                                        \
        .on_response_headers= NULL,                                        \
        .on_response_body   = NULL,                                        \
        .on_log            = NULL,                                         \
        .on_wakeup         = NULL,                                         \
    };                                                                     \
    const salukid_module_v1_t *salukid_module_register_v1(void) {         \
        return &M_v1;                                                      \
    }                                                                      \
    static int M_init(void **ctxp, const char *cfg, size_t cl,             \
                     const salukid_host_v1_t *h, uint32_t id) {            \
        (void)cfg; (void)cl; H = h; MID = id;

#define SALUKID_MODULE_V1_END                   \
        return 0;                               \
    }                                           \
    static void M_shutdown(void *ctx) { (void)ctx; }

/* Shorthand for common calls */
#define H_LOG(level, ...)          H->log(SALUKID_LOG_##level, __VA_ARGS__)
#define H_ALLOC(r, n)              H->mem_alloc((r), (n))
#define H_STRDUP(r, s)             H->mem_strdup((r), (s))
#define H_CONF(k, d)               H->config_get((k),(d))
#define H_CONF_INT(k,d)            H->config_get_int((k),(d))
#define H_SET_RESP(r,c,b,bl)       H->resp_send((r),(b),(bl))
#define H_SET_STATUS(r,c)          H->resp_set_status((r),(c))
#define H_ADD_HDR(r,n,v)           H->add_header((r),(n),(v))
#define H_DENY_BODY(r,b)           do{ H->resp_set_status(r,403); H->resp_send_str(r,(b)); return SALUKID_DENY;}while(0)

#ifdef __cplusplus
}
#endif

#endif /* SALUKID_HOOKS_H */
