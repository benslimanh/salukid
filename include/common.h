/*
 * salukid - Hardened high-performance HTTP server
 * Copyright (c) 2024 salukid contributors
 * SPDX-License-Identifier: MIT
 *
 * common.h - Shared definitions, macros, and type aliases
 */
#ifndef SALUKID_COMMON_H
#define SALUKID_COMMON_H

#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <pwd.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <zlib.h>

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/pk.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509.h>

#include <nghttp2/nghttp2.h>

/* ---------- Hardening / compiler ---------- */
#define SALUKID_UNUSED       __attribute__((unused))
#define SALUKID_PACKED       __attribute__((packed))
#define SALUKID_NORETURN     __attribute__((noreturn))
#define SALUKID_NONNULL(...) __attribute__((nonnull(__VA_ARGS__)))
#define SALUKID_ALIGNED(x)   __attribute__((aligned(x)))
#define SALUKID_LIKELY(x)    __builtin_expect(!!(x), 1)
#define SALUKID_UNLIKELY(x)  __builtin_expect(!!(x), 0)
#define SALUKID_PRINTF(f,a)  __attribute__((format(printf,f,a)))
#define SALUKID_MALLOC       __attribute__((malloc))

/* ---------- Compile-time constants ---------- */
#define SALUKID_VERSION           "0.1.0"
#define SALUKID_SERVER_NAME       "salukid/" SALUKID_VERSION
#define SALUKID_LISTEN_BACKLOG    4096
#define SALUKID_MAX_CLIENTS       65536
#define SALUKID_IOBUF_SZ          (128 * 1024)
#define SALUKID_SMALLBUF_SZ       4096
#define SALUKID_PATH_MAX          4096
#define SALUKID_MAX_HEADERS       128
#define SALUKID_MAX_HEADER_SZ     16384
#define SALUKID_MAX_URI           8192
#define SALUKID_EPOLL_EVENTS_MAX  2048
#define SALUKID_CACHE_ENTRIES     8192
#define SALUKID_CACHE_MAX_BODY    (1u << 20)   /* 1 MiB per cache entry */
#define SALUKID_CACHE_TTL_SEC     60
#define SALUKID_RING_SZ           (1u << 18)   /* 256 KiB lock-free ring */
#define SALUKID_ARENA_CHUNK       (256 * 1024)
#define SALUKID_SLAB_SZ           2048
#define SALUKID_KEEPALIVE_SEC     75
#define SALUKID_GZIP_MIN          128
#define SALUKID_GZIP_LEVEL        6
#define SALUKID_DEFAULT_WWW_DIR   "./www"
#define SALUKID_DEFAULT_USER      "nobody"
#define SALUKID_METRICS_PATH      "/metrics"
#define SALUKID_HEALTHZ_PATH      "/healthz"
#define SALUKID_MAX_REQ_BODY      (1u << 20)   /* 1 MiB max request body */
#define SALUKID_CHUNK_BUF         (16 * 1024)  /* scratch for chunk size parsing */

typedef enum {
    SALUKID_BODY_NONE = 0,
    SALUKID_BODY_CL,        /* Content-Length fixed */
    SALUKID_BODY_CHUNKED    /* Transfer-Encoding: chunked */
} salukid_body_kind_t;

/* ---------- Return codes ---------- */
typedef enum {
    SALUKID_OK    = 0,
    SALUKID_ERR   = -1,
    SALUKID_RC_AGAIN = -2,   /* internal: I/O would block (EAGAIN) */
    SALUKID_EOF   = -3,
    SALUKID_FULL  = -4
} salukid_rc_t;

/* NOTE: the module ABI uses SALUKID_AGAIN=3 (see salukid_hooks.h) which is
 * a *different* value from the internal SALUKID_RC_AGAIN=-2. The modapi
 * layer translates 3 -> internal pending state; core code must never
 * compare a module return code against SALUKID_RC_AGAIN. */

/* ---------- HTTP versions / methods ---------- */
typedef enum {
    HTTP_VER_UNKNOWN = 0,
    HTTP_VER_10,
    HTTP_VER_11,
    HTTP_VER_20
} http_version_t;

typedef enum {
    HTTP_M_UNKNOWN = 0,
    HTTP_M_GET,
    HTTP_M_HEAD,
    HTTP_M_POST,
    HTTP_M_PUT,
    HTTP_M_DELETE,
    HTTP_M_OPTIONS
} http_method_t;

/* ---------- HTTP status codes ---------- */
typedef enum {
    HTTP_200 = 200, HTTP_206 = 206, HTTP_301 = 301, HTTP_302 = 302,
    HTTP_304 = 304, HTTP_400 = 400, HTTP_403 = 403, HTTP_404 = 404,
    HTTP_405 = 405, HTTP_409 = 409, HTTP_416 = 416, HTTP_413 = 413,
    HTTP_414 = 414, HTTP_431 = 431, HTTP_500 = 500, HTTP_501 = 501,
    HTTP_502 = 502, HTTP_503 = 503, HTTP_504 = 504
} http_status_t;

/* ---------- Generic header key/value ---------- */
typedef struct {
    const char *name;
    size_t      name_len;
    const char *value;
    size_t      value_len;
} http_header_t;

/* ---------- Parsed request ---------- */
typedef struct http_request {
    http_method_t  method;
    http_version_t version;
    char           uri[SALUKID_MAX_URI];
    size_t         uri_len;
    const char    *path;              /* points into uri (query stripped) */
    size_t         path_len;
    const char    *query;             /* points into uri or NULL */
    size_t         query_len;

    http_header_t  headers[SALUKID_MAX_HEADERS];
    size_t         nheaders;

    /* Parsed conditional / range */
    bool           has_if_none_match;
    char           if_none_match[256];
    bool           has_range;
    off_t          range_start;
    off_t          range_end;              /* -1 until suffix */
    bool           range_suffix;
    char           accept_encoding[64];
    char           host[256];
    bool           connection_close;
    bool           upgrade_h2c;

    /* Parsed request body */
    salukid_body_kind_t body_kind;
    size_t         content_length;     /* declared Content-Length */
    bool           expect_100;         /* Expect: 100-continue */
    char          *body;               /* arena-allocated, NUL-terminated */
    size_t         body_len;           /* actual body bytes */
    size_t         body_cap;           /* allocation size */
    size_t         body_need;          /* remaining bytes needed */
    /* chunked decoding state */
    int            chunk_state;        /* 0=size, 1=data, 2=trialer */
    size_t         chunk_remaining;    /* bytes left in current chunk */
} http_request_t;

/* ---------- Server configuration ---------- */
typedef struct salukid_config {
    uint16_t    http_port;
    uint16_t    https_port;
    char        cert_path[SALUKID_PATH_MAX];
    char        key_path[SALUKID_PATH_MAX];
    char        www_dir[SALUKID_PATH_MAX];
    char        user[64];
    char        chroot_dir[SALUKID_PATH_MAX];
    int         num_workers;          /* 0 = auto (cpu count) */
    bool        daemonize;
    bool        tcp_cork;
    bool        gzip;
    bool        enable_cache;
    bool        enable_metrics;
    bool        enable_proxy;
    char        proxy_upstream[1024];
        char        modules[16][SALUKID_PATH_MAX];
        int         nmodules;
        char        v1modules[16][SALUKID_PATH_MAX];  /* stable v1 ABI */
        char        v1modcfg[16][256];
        int         nv1modules;
        char        wasm[8][SALUKID_PATH_MAX];        /* .wasm (proxy-wasm) */
        int         nwasm;
    int         cb_threshold;         /* circuit breaker */
    int         cb_recovery_ms;
    size_t      cache_max_mb;
    char        admin_token[128];
    /* TLS configurability */
    bool        tls13_only;
    char        tls_ciphers[256];
    char        tls_ciphersuites[256];
    char        log_path[SALUKID_PATH_MAX];
    bool        log_syslog;
} salukid_config_t;

extern salukid_config_t g_cfg;
extern volatile sig_atomic_t g_shutdown;
extern volatile sig_atomic_t g_reload;

/* ---------- Shared utility declarations ---------- */
void salukid_die(const char *fmt, ...) SALUKID_NORETURN SALUKID_PRINTF(1, 2);
void salukid_log(int level, const char *fmt, ...) SALUKID_PRINTF(2, 3);

/* Log levels */
#define LOG_EMERG  0
#define LOG_ALERT  1
#define LOG_CRIT   2
#define LOG_ERR    3
#define LOG_WARN   4
#define LOG_NOTICE 5
#define LOG_INFO   6
#define LOG_DEBUG  7

/* status line + header buffers */
const char *http_status_text(http_status_t s);
const char *http_method_str(http_method_t m);
const char *content_type_for(const char *path, size_t plen);

/* path confinement */
int safe_resolve_path(const char *root, const char *uri_path, size_t uri_plen,
                      char *out, size_t out_sz, struct stat *st_out, bool *is_dir);

/* etag / gzip helpers */
void etag_for(const struct stat *st, char *out, size_t outsz);
bool etag_match(const char *inm, const char *etag);
bool client_accepts_gzip(const char *ae);
int  gzip_compress(const uint8_t *in, size_t inlen, uint8_t **out, size_t *outlen);

/* Security headers (added to every response) */
size_t append_security_headers(char *buf, size_t cap, bool tls);

/* Parsing */
int  http_request_parse(http_request_t *req, const char *buf, size_t len,
                        size_t *consumed);
void http_request_reset(http_request_t *req);

/* min/max, ALIGN, arraysize */
#ifndef MIN
#define MIN(a,b) ((a)<(b)?(a):(b))
#endif
#ifndef MAX
#define MAX(a,b) ((a)>(b)?(a):(b))
#endif
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#endif
#define ALIGN_UP(x,a) (((x)+((a)-1)) & ~((size_t)(a)-1))

/* Set a socket option without aborting */
int  salukid_set_nonblock(int fd);
void salukid_set_cloexec(int fd);

/* Networking helpers */
int salukid_listen_tcp(uint16_t port, bool reuseport);
int salukid_drop_privileges(const char *user, const char *chroot_dir);
int salukid_prefork(int nworkers, void (*worker_fn)(int id, int fd_http, int fd_https));
void salukid_install_signals(void);

#endif /* SALUKID_COMMON_H */


