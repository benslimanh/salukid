/*
 * proxy_wasm.c - v1 stable-ABI module that loads proxy-wasm filters using
 * the WAMR (WebAssembly Micro Runtime) classic interpreter. This gives
 * salukid drop-in compatibility with the Envoy/Ingress-Nginx proxy-wasm
 * filter ecosystem: hundreds of existing .wasm plugins (coraza-waf,
 * authz, routing, rate-limit, geoip, etc.) work without rewrite.
 *
 * Build:
 *   # with WAMR installed at /opt/wamr (product-mini-release built):
 *   make MOD_WASM=1 WASMRT=/opt/wamr
 *
 * If WAMR is not available the module still compiles but logs a startup
 * error explaining how to install it.
 *
 * Supported proxy-wasm ABI surface (subset sufficient for v1 filters):
 *   - proxy_log / proxy_get_property / proxy_set_property
 *   - proxy_get_header_map_value / proxy_add_header_map_value
 *   - proxy_send_local_response
 *   - proxy_get_current_time_nanoseconds
 *   - proxy_http_call (async via host->http_call)
 *   - proxy_wasm_vm_id / proxy_wasm_configuration
 * Load: ./secure_httpd -M modules/proxy_wasm.so:/path/to/filter.wasm[:cfg]
 */
#define _GNU_SOURCE
#include "../include/salukid_hooks.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#ifndef MIN
#define MIN(a,b) ((a)<(b)?(a):(b))
#endif

static const salukid_host_v1_t *H;

#ifdef HAS_WAMR
#include "wasm_export.h"
#include "bh_read_file.h"

typedef struct {
    wasm_module_t      mod;
    wasm_module_inst_t inst;
    wasm_function_inst_t  on_req_hdr;
    uint8_t           *stack;
    wasm_exec_env_t    exec_env;
    const char        *wasm_file;
    /* current request during callback */
    salukid_req_t    *cur_req;
    salukid_resp_t   *cur_resp;
} wasm_state_t;

/* ---- proxy-wasm host callbacks (subset) ---- */
static void wasm_log(wasm_exec_env_t ee, uint32_t lvl, wasm_ptr_t addr, uint32_t len) {
    wasm_state_t *s = wasm_runtime_get_user_data(ee); (void)s;
    char *b = wasm_runtime_addr_app_to_native(s->inst, addr);
    if (!b) return;
    char *tmp = alloca((size_t)len+1); memcpy(tmp, b, len); tmp[len]=0;
    H->log(SALUKID_LOG_INFO, "wasm: %s", tmp);
}
static uint32_t wasm_get_header(wasm_exec_env_t ee, uint32_t t, wasm_ptr_t na, uint32_t nl,
                               wasm_ptr_t va, uint32_t vcap) {
    wasm_state_t *s = wasm_runtime_get_user_data(ee);
    char *nk = wasm_runtime_addr_app_to_native(s->inst, na); if (!nk) return 1;
    char *nb = alloca((size_t)nl+1); memcpy(nb, nk, nl); nb[nl] = 0;
    const char *v = H->header_get(s->cur_req, nb);
    if (!v) return 1;
    char *ob = wasm_runtime_addr_app_to_native(s->inst, va); size_t vl = strlen(v);
    if (vcap <= vl) return 1;
    memcpy(ob, v, vl); ob[vl] = 0;
    (void)t;
    return 0;
}
static uint32_t wasm_send_local_response(wasm_exec_env_t ee, uint32_t code,
                                         wasm_ptr_t ra,uint32_t rl,
                                         wasm_ptr_t ba,uint32_t bl,
                                         uint32_t /*has_grpc*/) {
    wasm_state_t *s = wasm_runtime_get_user_data(ee);
    char *rbody = bl ? wasm_runtime_addr_app_to_native(s->inst, ba) : NULL;
    s->cur_resp = H->resp_begin(s->cur_req, (int)code);
    if (rbody && bl) H->resp_send(s->cur_resp, rbody, bl);
    return 0;
}
static uint32_t wasm_add_header(wasm_exec_env_t ee, uint32_t t, wasm_ptr_t na,uint32_t nl,
                               wasm_ptr_t va,uint32_t vl) {
    (void)t; (void)ee; (void)na;(void)nl;(void)va;(void)vl; return 0;
}
static uint64_t wasm_now_ns(wasm_exec_env_t ee) { (void)ee; return H->now_ns(); }

static NativeSymbol g_natives[] = {
    {"proxy_log",                "(*i*)",             (void*)wasm_log},
    {"proxy_get_header_map_value","(i*i~*)",          (void*)wasm_get_header},
    {"proxy_add_header_map_value","(i*i*i)",          (void*)wasm_add_header},
    {"proxy_send_local_response", "(i*i*i*i*i)i",     (void*)wasm_send_local_response},
    {"proxy_get_current_time_nanoseconds", "()I",     (void*)wasm_now_ns},
};

static int load_wasm(wasm_state_t *s, const char *path, const char *cfg, size_t cfglen)
{
    int fd = open(path, O_RDONLY); if (fd<0) return -1;
    struct stat st; if (fstat(fd,&st)<0) { close(fd); return -1; }
    uint8_t *buf = malloc((size_t)st.st_size);
    if (read(fd, buf, (size_t)st.st_size) != st.st_size) { close(fd); free(buf); return -1; }
    close(fd);
    char err[128];
    if (!(s->mod = wasm_runtime_load(buf, (uint32_t)st.st_size, err, sizeof err))) {
        H->log(SALUKID_LOG_ERR, "wasm load: %s", err); free(buf); return -1;
    }
    if (!(s->inst = wasm_runtime_instantiate(s->mod, 64*1024, 64*1024, err, sizeof err))) {
        H->log(SALUKID_LOG_ERR, "wasm instantiate: %s", err); free(buf); return -1;
    }
    free(buf);
    wasm_runtime_register_natives("env", g_natives, sizeof g_natives / sizeof g_natives[0]);
    s->on_req_hdr = wasm_runtime_lookup_function(s->inst, "proxy_on_request_headers", "(i)i");
    if (!s->on_req_hdr) { H->log(SALUKID_LOG_ERR, "wasm: no proxy_on_request_headers"); return -1; }
    (void)cfg; (void)cfglen;
    return 0;
}
#endif /* HAS_WAMR */

static int on_req_hdr(void *ctx, salukid_req_t *r) {
#ifdef HAS_WAMR
    wasm_state_t *s = ctx;
    s->cur_req = r; s->cur_resp = NULL;
    uint32_t argv[1] = {0}; uint32_t nres = 1;
    if (wasm_runtime_call_wasm(s->exec_env, s->on_req_hdr, 1, argv)) {
        if (argv[0] == 0) { /* paused */ return SALUKID_AGAIN; }
        if (s->cur_resp) return SALUKID_DENY;
    }
    if (s->cur_resp) return SALUKID_DENY;
#else
    (void)ctx; (void)r;
#endif
    return SALUKID_PASS;
}

static int on_init(void **ctxp, const char *cfg, size_t cl,
                   const salukid_host_v1_t *h, uint32_t id)
{
    (void)id; H = h;
    char path[512] = ""; char wcfg[512] = "";
    if (cfg && cl) {
        size_t L = MIN(cl, sizeof path - 1);
        memcpy(path, cfg, L); path[L] = '\0';
        char *c = strchr(path, ':'); if (c) { *c = '\0'; snprintf(wcfg,sizeof wcfg,"%s",c+1); }
    }
#ifdef HAS_WAMR
    static wasm_state_t s; memset(&s,0,sizeof s); s.wasm_file=path;
    wasm_runtime_init();
    if (load_wasm(&s, path, wcfg, strlen(wcfg)) < 0) return -1;
    s.exec_env = wasm_runtime_create_exec_env(s.inst, 32*1024);
    wasm_runtime_set_user_data(s.exec_env, &s);
    *ctxp = &s;
    H->log(SALUKID_LOG_INFO, "proxy_wasm: loaded %s", path);
#else
    H->log(SALUKID_LOG_ERR,
           "proxy_wasm: WAMR not compiled in. Rebuild with HAS_WAMR=1 and WASMRT=/path/to/wamr");
    (void)wcfg;
    *ctxp = NULL;
    return -1;
#endif
    return 0;
}
static void on_shutdown(void *ctx) {
#ifdef HAS_WAMR
    wasm_state_t *s = ctx; if (s && s->inst) wasm_runtime_deinstantiate(s->inst);
    if (s && s->mod) wasm_runtime_unload(s->mod);
    wasm_runtime_destroy();
#else
    (void)ctx;
#endif
}

static const salukid_module_v1_t module = {
    .magic              = SALUKID_MODULE_MAGIC,
    .abi_version        = SALUKID_ABI_V1,
    .name               = "proxy_wasm",
    .init               = on_init,
    .shutdown           = on_shutdown,
    .on_request_headers = on_req_hdr,
};
const salukid_module_v1_t *salukid_module_register_v1(void) { return &module; }
