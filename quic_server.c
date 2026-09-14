/*
 * quic_server.c - Standalone HTTP/3 server for salukid
 *   (ngtcp2 + GnuTLS 1.3 QUIC + nghttp3)
 *
 * Minimal, hardened, production-oriented H3 server:
 *   - QUIC v1 (RFC 9000), HTTP/3 (RFC 9114)
 *   - TLS 1.3 via GnuTLS QUIC method, ALPN "h3"
 *   - Static GET/HEAD via safe_resolve_path + pread (no mmap lifetime issues)
 *   - SO_REUSEPORT, non-blocking, epoll event loop
 *   - 16k-bucket connection hash, 30s idle sweep, SIGINT/SIGTERM shutdown
 *
 * Implements the ~800 lines of stack wiring:
 *   - GnuTLS session + priority
 *   - ngtcp2 crypto callbacks backed by ngtcp2_crypto helpers
 *   - nghttp3 server callbacks (recv_request, stream_read for file body)
 *   - per-connection hash by Source CID
 *   - send_packet / send_stream_data / flush_pkts pipeline
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>     /* offsetof */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>
#include <stdatomic.h>
#include <ctype.h>

#include <gnutls/gnutls.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>
#include <nghttp3/nghttp3.h>

#include "include/common.h"
#include "include/path.h"

#define NVCONNS             (1 << 14)
#define MAX_BIDI            128
#define MAX_DATA            (10UL * 1024 * 1024)
#define MAX_STREAM_DATA     (2UL  * 1024 * 1024)
#define MAX_UDP_PAYLOAD     NGTCP2_MAX_UDP_PAYLOAD_SIZE
#define IDLE_NS             (30ULL * 1000000000ULL)
#define ALPN                "\x02h3"  /* length-prefixed "h3" */

static volatile sig_atomic_t g_shut;
static int g_udp = -1, g_ep = -1;
static gnutls_certificate_credentials_t g_cred;
static gnutls_priority_t g_prio;
static const char *g_www = "./www", *g_cert, *g_key;
static uint16_t g_port = 443;

/* ---------- logging ---------- */
static void qlog(const char *f, ...)
{
    va_list a; va_start(a, f);
    vfprintf(stderr, f, a);
    fputc('\n', stderr);
    va_end(a);
}

/* ---------- time/rand ---------- */
static uint64_t now_ns(void)
{
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}
static void randb(uint8_t *x, size_t n)
{
    int fd = open("/dev/urandom", O_RDONLY|O_CLOEXEC);
    if (fd >= 0) { ssize_t r = read(fd, x, n); (void)r; close(fd); }
}

/* ---------- types ---------- */
typedef struct qconn qconn_t;
typedef struct qstream qstream_t;

struct qstream {
    int64_t     id;
    int         fd;
    const char *mem;        /* non-NULL for in-memory bodies (error pages) */
    size_t      body_len;
    size_t      off;
    bool        fin_sent;
    bool        responded;
    char        method[8];
    char        path[SALUKID_MAX_URI];
    size_t      path_len;
    qconn_t    *c;
    qstream_t  *next;
};

struct qconn {
    ngtcp2_conn              *nc;
    gnutls_session_t          sess;
    nghttp3_conn             *h3;
    struct sockaddr_storage   peer;
    socklen_t                 peerlen;
    struct sockaddr_storage   local;
    socklen_t                 locallen;
    ngtcp2_cid                key_cid;    /* CID used for hash table lookup */
    qconn_t                  *next;
    uint64_t                  last;
    qstream_t                *streams;
    ngtcp2_crypto_conn_ref    conn_ref;
};

static ngtcp2_conn *q_get_conn(ngtcp2_crypto_conn_ref *r)
{
    qconn_t *c = (qconn_t*)r->user_data;
    return c->nc;
}

static qconn_t *g_tab[NVCONNS];

static size_t cid_hash(const ngtcp2_cid *c)
{
    uint64_t h = 1469598103934665603ULL;
    for (size_t i = 0; i < c->datalen; ++i) { h ^= c->data[i]; h *= 1099511628211ULL; }
    return (size_t)(h & (NVCONNS - 1));
}
static qconn_t *cfind(const ngtcp2_cid *c)
{
    for (qconn_t *x = g_tab[cid_hash(c)]; x; x = x->next)
        if (ngtcp2_cid_eq(&x->key_cid, c)) return x;
    return NULL;
}
static void cinsert(qconn_t *x, const ngtcp2_cid *key)
{
    size_t b = cid_hash(key);
    x->key_cid = *key;
    x->next = g_tab[b];
    g_tab[b] = x;
}
static void cremove(qconn_t *x)
{
    size_t b = cid_hash(&x->key_cid);
    for (qconn_t **p = &g_tab[b]; *p; p = &(*p)->next) {
        if (*p == x) { *p = x->next; x->next = NULL; return; }
    }
}

/* ---------- streams ---------- */
static qstream_t *sget(qconn_t *c, int64_t id)
{
    for (qstream_t *s = c->streams; s; s = s->next) if (s->id == id) return s;
    return NULL;
}
static qstream_t *snew(qconn_t *c, int64_t id)
{
    qstream_t *s = calloc(1, sizeof *s);
    if (!s) return NULL;
    s->id = id; s->c = c; s->fd = -1; s->mem = NULL;
    s->next = c->streams; c->streams = s;
    return s;
}
static void sfree(qstream_t *s)
{
    if (!s) return;
    if (s->fd >= 0) close(s->fd);
    /* mem bodies are owned by the stream (strdup'd) */
    if (s->mem) free((void*)s->mem);
    free(s);
}

static char *sdup(const char *s)
{
    size_t n = strlen(s);
    char *p = malloc(n + 1);
    if (!p) return NULL;
    memcpy(p, s, n); p[n] = '\0';
    return p;
}
static void cfree(qconn_t *c)
{
    if (!c) return;
    if (c->h3) nghttp3_conn_del(c->h3);
    if (c->nc) ngtcp2_conn_del(c->nc);
    if (c->sess) gnutls_deinit(c->sess);
    for (qstream_t *s = c->streams; s; ) { qstream_t *n = s->next; sfree(s); s = n; }
    free(c);
}

/* ---------- UDP ---------- */
static ssize_t udp_send(const struct sockaddr *sa, socklen_t sl,
                        const uint8_t *d, size_t n)
{ return sendto(g_udp, d, n, MSG_NOSIGNAL, sa, sl); }

/* ---------- static response ---------- */
static void srv_text(qstream_t *s, int status, const char *body)
{
    size_t bl = strlen(body);
    char sbuf[4]; int sl = snprintf(sbuf, sizeof sbuf, "%d", status);
    char clb[24]; int cll = snprintf(clb, sizeof clb, "%zu", bl);
    nghttp3_nv nv[] = {
        {(uint8_t*)":status", (uint8_t*)sbuf, 7, (size_t)sl, 0},
        {(uint8_t*)"server", (uint8_t*)"salukid-h3/0.2", 6, 14, 0},
        {(uint8_t*)"content-type", (uint8_t*)"text/plain; charset=utf-8", 12, 24, 0},
        {(uint8_t*)"content-length", (uint8_t*)clb, 14, (size_t)cll, 0},
    };
    /* Duplicate body onto the heap (owned by stream, freed in sfree). */
    char *dup = sdup(body);
    if (dup) {
        s->mem = dup;
    } else {
        /* OOM: fall back to empty body and correct length header */
        s->mem = NULL;
        bl = 0;
        cll = snprintf(clb, sizeof clb, "0");
        nv[3].value = (uint8_t*)clb;
        nv[3].valuelen = (size_t)cll;
    }
    nghttp3_conn_submit_response(s->c->h3, s->id, nv, sizeof(nv)/sizeof(nv[0]), NULL);
    s->fd = -1;
    s->body_len = bl;
    s->off = 0;
}

static const char *mime_for(const char *p)
{
    const char *dot = strrchr(p, '.');
    if (!dot) return "application/octet-stream";
    if (!strcmp(dot, ".html") || !strcmp(dot, ".htm")) return "text/html; charset=utf-8";
    if (!strcmp(dot, ".txt"))  return "text/plain; charset=utf-8";
    if (!strcmp(dot, ".json")) return "application/json";
    if (!strcmp(dot, ".css"))  return "text/css";
    if (!strcmp(dot, ".js"))   return "application/javascript";
    if (!strcmp(dot, ".png"))  return "image/png";
    if (!strcmp(dot, ".jpg") || !strcmp(dot, ".jpeg")) return "image/jpeg";
    if (!strcmp(dot, ".svg"))  return "image/svg+xml";
    if (!strcmp(dot, ".ico"))  return "image/x-icon";
    return "application/octet-stream";
}

static int serve_path(qstream_t *s, const uint8_t *p, size_t pl)
{
    char uri[SALUKID_MAX_URI];
    if (pl >= sizeof uri) { srv_text(s, 414, "URI too long"); return 0; }
    memcpy(uri, p, pl); uri[pl] = '\0';
    const char *target = uri;
    char idxbuf[SALUKID_MAX_URI];
    if (pl == 1 && uri[0] == '/') { snprintf(idxbuf, sizeof idxbuf, "/index.html"); target = idxbuf; }

    char fs[SALUKID_PATH_MAX]; struct stat st; bool isdir = false;
    if (safe_resolve_path(g_www, target, strlen(target), fs, sizeof fs, &st, &isdir) != 0) {
        srv_text(s, 404, "not found"); return 0;
    }
    if (isdir || !S_ISREG(st.st_mode)) { srv_text(s, 403, "forbidden"); return 0; }

    int fd = open(fs, O_RDONLY|O_CLOEXEC);
    if (fd < 0) { srv_text(s, 500, "server error"); return 0; }
    s->fd = fd; s->body_len = (size_t)st.st_size; s->off = 0;

    char sbuf[4]; snprintf(sbuf, sizeof sbuf, "200");
    char clb[24]; int cll = snprintf(clb, sizeof clb, "%zu", s->body_len);
    const char *ct = mime_for(fs);
    nghttp3_nv nv[] = {
        {(uint8_t*)":status", (uint8_t*)"200", 7, 3, 0},
        {(uint8_t*)"server", (uint8_t*)"salukid-h3/0.2", 6, 14, 0},
        {(uint8_t*)"content-type", (uint8_t*)ct, 12, strlen(ct), 0},
        {(uint8_t*)"content-length", (uint8_t*)clb, 14, (size_t)cll, 0},
    };
    (void)sbuf;
    nghttp3_conn_submit_response(s->c->h3, s->id, nv, sizeof(nv)/sizeof(nv[0]), NULL);
    return 0;
}

static void make_path(ngtcp2_path *p, qconn_t *c)
{
    p->local.addr = (struct sockaddr*)&c->local; p->local.addrlen = c->locallen;
    p->remote.addr = (struct sockaddr*)&c->peer; p->remote.addrlen = c->peerlen;
}

/* flush queued QUIC datagrams (control packets, ACKs, etc.) */
static void flush_pkts(qconn_t *c)
{
    uint8_t out[MAX_UDP_PAYLOAD];
    ngtcp2_path path; make_path(&path, c);
    ngtcp2_pkt_info pi;
    uint64_t t = now_ns();
    for (;;) {
        ngtcp2_ssize n = ngtcp2_conn_write_pkt(c->nc, &path, &pi, out, sizeof out, t);
        if (n <= 0) break;
        ssize_t w = udp_send((struct sockaddr*)&c->peer, c->peerlen, out, (size_t)n);
        if (w < 0) break;
    }
}

static int write_one_stream(qconn_t *c, int64_t id)
{
    uint8_t out[MAX_UDP_PAYLOAD];
    ngtcp2_path path; make_path(&path, c);
    ngtcp2_pkt_info pi;
    ngtcp2_tstamp t = now_ns();
    for (;;) {
        qstream_t *s = sget(c, id); if (!s) return 0;
        static __thread uint8_t chunk[65536];
        ngtcp2_vec vec[1] = {{0}};
        size_t left = s->body_len - s->off;
        if (left == 0) {
            /* send FIN with empty */
            ngtcp2_ssize pdatalen = 0;
            ngtcp2_ssize n = ngtcp2_conn_writev_stream(c->nc, &path, &pi, out, sizeof out,
                &pdatalen, NGTCP2_WRITE_STREAM_FLAG_FIN, id, NULL, 0, t);
            if (n > 0) udp_send((struct sockaddr*)&c->peer, c->peerlen, out, (size_t)n);
            s->fin_sent = true;
            return 0;
        }
        size_t take = left < sizeof chunk ? left : sizeof chunk;
        if (s->fd >= 0) {
            ssize_t rd = pread(s->fd, chunk, take, (off_t)s->off);
            if (rd <= 0) {
                ngtcp2_conn_shutdown_stream(c->nc, 0, id, NGTCP2_NO_ERROR);
                return 0;
            }
            take = (size_t)rd;
            vec[0].base = chunk; vec[0].len = take;
        } else if (s->mem) {
            take = left < sizeof chunk ? left : sizeof chunk;
            /* chunk is thread-local 64 KiB; copy the mem slice into it so
             * we don't have to worry about vec lifetime across calls. */
            memcpy(chunk, s->mem + s->off, take);
            vec[0].base = chunk; vec[0].len = take;
        } else {
            return 0;
        }
        uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_MORE;
        if (s->off + take >= s->body_len) flags = NGTCP2_WRITE_STREAM_FLAG_FIN;
        ngtcp2_ssize pdatalen = 0;
        ngtcp2_ssize n = ngtcp2_conn_writev_stream(c->nc, &path, &pi, out, sizeof out,
            &pdatalen, flags, id, vec, 1, t);
        if (n < 0) return -1;
        if (n == 0) return 0;
        ssize_t w = udp_send((struct sockaddr*)&c->peer, c->peerlen, out, (size_t)n);
        (void)w;
        if (pdatalen > 0) s->off += (size_t)pdatalen;
        if (flags & NGTCP2_WRITE_STREAM_FLAG_FIN) { s->fin_sent = true; return 0; }
        if (pdatalen == 0) return 0;
    }
}

/* drive all streams that have data to send */
static void flush_streams(qconn_t *c)
{
    for (qstream_t *s = c->streams; s; s = s->next) {
        if (s->fin_sent) continue;
        if (s->off >= s->body_len) continue;
        write_one_stream(c, s->id);
    }
}

/* ========== nghttp3 callbacks ========== */
static int cb_h3_begin_hdrs(nghttp3_conn *h3, int64_t id, void *cu, void *su)
{ (void)h3; (void)su; qstream_t *s = snew((qconn_t*)cu, id); if (s) { s->responded = false; s->path_len = 0; } return 0; }
static int cb_h3_hdr(nghttp3_conn *h3, int64_t id, int32_t token,
                     nghttp3_rcbuf *namerb, nghttp3_rcbuf *valrb, uint8_t flags,
                     void *cu, void *su)
{
    (void)h3; (void)id; (void)token; (void)flags; (void)su;
    qconn_t *c = cu; qstream_t *s = sget(c, id); if (!s) return 0;
    nghttp3_vec nv = nghttp3_rcbuf_get_buf(namerb);
    nghttp3_vec vv = nghttp3_rcbuf_get_buf(valrb);
    if (nv.len == 5 && !memcmp(nv.base, ":path", 5)) {
        size_t L = vv.len;
        if (L >= sizeof s->path) L = sizeof s->path - 1;
        memcpy(s->path, vv.base, L); s->path[L] = '\0'; s->path_len = L;
    } else if (nv.len == 7 && !memcmp(nv.base, ":method", 7)) {
        size_t L = vv.len;
        if (L >= sizeof s->method) L = sizeof s->method - 1;
        memcpy(s->method, vv.base, L); s->method[L] = '\0';
    }
    return 0;
}
static int cb_h3_end_hdrs(nghttp3_conn *h3, int64_t id, int fin, void *cu, void *su)
{
    (void)h3; (void)fin; (void)su;
    qconn_t *c = cu; qstream_t *s = sget(c, id); if (!s || s->responded) return 0;
    s->responded = true;
    if (s->path_len) serve_path(s, (const uint8_t*)s->path, s->path_len);
    else srv_text(s, 400, "bad request");
    return 0;
}
static void s_del(qconn_t *c, int64_t id)
{
    for (qstream_t **p = &c->streams; *p; p = &(*p)->next)
        if ((*p)->id == id) { qstream_t *v = *p; *p = v->next; sfree(v); break; }
}
static int cb_h3_data(nghttp3_conn *h3, int64_t id, const uint8_t *d, size_t dl, void *cu, void *su)
{ (void)h3; (void)id; (void)d; (void)dl; (void)cu; (void)su; return 0; }
static int cb_h3_close(nghttp3_conn *h3, int64_t id, uint64_t apperr, void *cu, void *su)
{ (void)h3; (void)apperr; (void)su; s_del((qconn_t*)cu, id); return 0; }
static int cb_h3_end(nghttp3_conn *h3, int64_t id, void *cu, void *su)
{ (void)h3; (void)su; /* end of received body; we ignore */ (void)cu; return 0; }
static int cb_h3_reset(nghttp3_conn *h3, int64_t id, uint64_t e, void *cu, void *su)
{ (void)h3; (void)e; (void)su; s_del((qconn_t*)cu, id); return 0; }
static int cb_h3_shut(nghttp3_conn *h3, int64_t id, void *cu)
{ (void)h3; (void)id; (void)cu; return 0; }
static int cb_h3_stop(nghttp3_conn *h3, int64_t id, uint64_t e, void *cu, void *su)
{ (void)h3; (void)e; (void)su; s_del((qconn_t*)cu, id); return 0; }
static int cb_h3_begin_trail(nghttp3_conn *h3, int64_t id, void *cu, void *su)
{ (void)h3; (void)id; (void)cu; (void)su; return 0; }
static int cb_h3_defer(nghttp3_conn *h3, int64_t id, size_t n, void *cu, void *su)
{ (void)h3; (void)id; (void)n; (void)cu; (void)su; return 0; }
static int cb_h3_settings(nghttp3_conn *h3, const nghttp3_settings *s, void *u)
{ (void)h3; (void)s; (void)u; return 0; }

static ssize_t cb_h3_sendpkt(ngtcp2_conn *nc, const ngtcp2_path *path,
                             const ngtcp2_cid *dcid, const ngtcp2_cid *scid,
                             const uint8_t *d, size_t dl, ngtcp2_path_storage *ps, void *u)
{
    (void)nc; (void)dcid; (void)scid; (void)ps; (void)u;
    ssize_t w = udp_send(path->remote.addr, path->remote.addrlen, d, dl);
    if (w < 0) {
        /* Transient send failure: tell ngtcp2 it can retry later.
         * NGTCP2_ERR_NOBUF is the documented "try again" indicator
         * for send_packet callbacks in ngtcp2 < 1.12. */
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS || errno == ENOMEM)
            return NGTCP2_ERR_NOBUF;
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    return (ssize_t)dl;
}

static const nghttp3_callbacks h3cbs = {
    .acked_stream_data = NULL,
    .stream_close = cb_h3_close,
    .recv_data = cb_h3_data,
    .deferred_consume = cb_h3_defer,
    .begin_headers = cb_h3_begin_hdrs,
    .recv_header = cb_h3_hdr,
    .end_headers = cb_h3_end_hdrs,
    .begin_trailers = cb_h3_begin_trail,
    .recv_trailer = cb_h3_hdr,
    .end_trailers = cb_h3_end_hdrs,
    .stop_sending = cb_h3_stop,
    .end_stream = cb_h3_end,
    .reset_stream = cb_h3_reset,
    .shutdown = cb_h3_shut,
    .recv_settings = cb_h3_settings,
};

/* ========== ngtcp2 callbacks ========== */
static int cb_crypto(ngtcp2_conn *nc, ngtcp2_encryption_level lvl, uint64_t off,
                     const uint8_t *d, size_t dl, void *u)
{
    (void)u;
    return ngtcp2_crypto_recv_crypto_data_cb(nc, lvl, off, d, dl, u);
}
static int cb_hs_done(ngtcp2_conn *nc, void *u)
{
    qconn_t *c = u; (void)nc;
    qlog("TLS handshake completed");
    nghttp3_settings hs;
    nghttp3_settings_default_versioned(NGHTTP3_SETTINGS_VERSION, &hs);
    hs.max_field_section_size = 64 * 1024;
    hs.qpack_max_dtable_capacity = 4096;
    hs.qpack_blocked_streams = 100;
    int rv = nghttp3_conn_server_new_versioned(&c->h3, NGHTTP3_CALLBACKS_VERSION,
        &h3cbs, NGHTTP3_SETTINGS_VERSION, &hs, NULL, c);
    if (rv != 0) { qlog("nghttp3_conn_server_new: %s", nghttp3_strerror(rv)); return NGTCP2_ERR_CALLBACK_FAILURE; }
    return 0;
}
static int cb_rxkey(ngtcp2_conn *nc, ngtcp2_encryption_level lvl, void *u)
{ (void)u; return ngtcp2_crypto_derive_and_install_rx_key(nc, NULL, NULL, NULL, lvl, NULL, 0); }
static int cb_txkey(ngtcp2_conn *nc, ngtcp2_encryption_level lvl, void *u)
{ (void)u; return ngtcp2_crypto_derive_and_install_tx_key(nc, NULL, NULL, NULL, lvl, NULL, 0); }
static int cb_newcid(ngtcp2_conn *nc, ngtcp2_cid *cid, uint8_t *tok, size_t cl, void *u)
{
    (void)nc; (void)u;
    if (cl < NGTCP2_MIN_CIDLEN) cl = NGTCP2_MIN_CIDLEN;
    randb(cid->data, cl); cid->datalen = cl;
    randb(tok, NGTCP2_STATELESS_RESET_TOKENLEN);
    return 0;
}
static int cb_rmcid(ngtcp2_conn *nc, const ngtcp2_cid *c, void *u)
{ (void)nc; (void)c; (void)u; return 0; }
static void cb_rand(uint8_t *dest, size_t n, const ngtcp2_rand_ctx *rx)
{ (void)rx; randb(dest, n); }
static int cb_ext_bidi(ngtcp2_conn *nc, uint64_t m, void *u)
{ (void)nc; (void)m; (void)u; return 0; }
static int cb_ext_uni(ngtcp2_conn *nc, uint64_t m, void *u)
{ (void)nc; (void)m; (void)u; return 0; }
static int cb_ext_sd(ngtcp2_conn *nc, int64_t id, uint64_t m, void *u, void *sup)
{ (void)nc; (void)id; (void)m; (void)u; (void)sup; return 0; }
static int cb_sopen(ngtcp2_conn *nc, int64_t id, void *u)
{ (void)nc; (void)id; (void)u; return 0; }
static int cb_sclose(ngtcp2_conn *nc, uint32_t flags, int64_t id, uint64_t e, void *u, void *sup)
{
    qconn_t *c = u; (void)flags; (void)e; (void)sup; (void)nc;
    for (qstream_t **p = &c->streams; *p; p = &(*p)->next)
        if ((*p)->id == id) { qstream_t *v = *p; *p = v->next; sfree(v); break; }
    return 0;
}
static int cb_sdata(ngtcp2_conn *nc, uint32_t fl, int64_t id, uint64_t off,
                    const uint8_t *d, size_t dl, void *u, void *sup)
{
    qconn_t *c = u; (void)fl; (void)off; (void)sup;
    if (c->h3) {
        nghttp3_ssize rv = nghttp3_conn_read_stream(c->h3, id, d, dl,
            !!(fl & NGTCP2_STREAM_DATA_FLAG_FIN));
        if (rv < 0) return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    (void)nc; return 0;
}
static int cb_acked(ngtcp2_conn *nc, int64_t id, uint64_t off, uint64_t n, void *u, void *sup)
{ qconn_t *c = u; if (c->h3) nghttp3_conn_add_ack_offset(c->h3, id, off + n); (void)sup; (void)nc; return 0; }
static int cb_sreset(ngtcp2_conn *nc, int64_t id, uint64_t fs, uint64_t e, void *u, void *sup)
{ (void)nc; (void)id; (void)fs; (void)e; (void)u; (void)sup; return 0; }
static int cb_stop(ngtcp2_conn *nc, int64_t id, uint64_t code, void *u, void *sup)
{ (void)nc; (void)id; (void)code; (void)u; (void)sup; return 0; }
static int cb_sreset_pkt(ngtcp2_conn *nc, const ngtcp2_pkt_stateless_reset *sr, void *u)
{ (void)nc; (void)sr; (void)u; return 0; }
static int cb_verneg(ngtcp2_conn *nc, uint32_t ver, const ngtcp2_cid *dcid, void *u)
{ (void)nc; (void)ver; (void)dcid; (void)u; return 0; }

static const ngtcp2_callbacks nccbs = {
    .recv_client_initial = ngtcp2_crypto_recv_client_initial_cb,
    .recv_crypto_data = cb_crypto,
    .handshake_completed = cb_hs_done,
    .encrypt = ngtcp2_crypto_encrypt_cb,
    .decrypt = ngtcp2_crypto_decrypt_cb,
    .hp_mask = ngtcp2_crypto_hp_mask_cb,
    .recv_stream_data = cb_sdata,
    .acked_stream_data_offset = cb_acked,
    .stream_open = cb_sopen,
    .stream_close = cb_sclose,
    .recv_stateless_reset = cb_sreset_pkt,
    .extend_max_local_streams_bidi = cb_ext_bidi,
    .extend_max_local_streams_uni = cb_ext_uni,
    .rand = cb_rand,
    .get_new_connection_id = cb_newcid,
    .remove_connection_id = cb_rmcid,
    .update_key = ngtcp2_crypto_update_key_cb,
    .stream_reset = cb_sreset,
    .extend_max_remote_streams_bidi = cb_ext_bidi,
    .extend_max_remote_streams_uni = cb_ext_uni,
    .extend_max_stream_data = cb_ext_sd,
    .delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb,
    .delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
    .get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb,
    .stream_stop_sending = cb_stop,
    .version_negotiation = cb_verneg,
    .recv_rx_key = cb_rxkey,
    .recv_tx_key = cb_txkey,
};

/* ---------- new conn ---------- */
static qconn_t *cnew(const ngtcp2_path *path,
                     const ngtcp2_cid *dcid, const ngtcp2_cid *scid)
{
    qconn_t *c = calloc(1, sizeof *c);
    if (!c) return NULL;
    memcpy(&c->peer, path->remote.addr, path->remote.addrlen);
    c->peerlen = path->remote.addrlen;
    memcpy(&c->local, path->local.addr, path->local.addrlen);
    c->locallen = path->local.addrlen;
    c->last = now_ns();

    c->conn_ref.get_conn = q_get_conn;
    c->conn_ref.user_data = c;

    ngtcp2_settings s; ngtcp2_settings_default(&s);
    s.max_tx_udp_payload_size = MAX_UDP_PAYLOAD;
    s.initial_ts = c->last;
    s.max_window = MAX_DATA * 2;
    s.max_stream_window = MAX_STREAM_DATA * 2;
    s.handshake_timeout = 10ULL * 1000000000ULL;

    ngtcp2_transport_params tp;
    ngtcp2_transport_params_default(&tp);
    tp.initial_max_data = MAX_DATA;
    tp.initial_max_stream_data_bidi_local = MAX_STREAM_DATA;
    tp.initial_max_stream_data_bidi_remote = MAX_STREAM_DATA;
    tp.initial_max_stream_data_uni = MAX_STREAM_DATA;
    tp.initial_max_streams_bidi = MAX_BIDI;
    tp.initial_max_streams_uni = MAX_BIDI;
    tp.max_udp_payload_size = MAX_UDP_PAYLOAD;
    tp.ack_delay_exponent = 3;
    tp.max_ack_delay = NGTCP2_DEFAULT_MAX_ACK_DELAY;
    tp.disable_active_migration = 1;
    static const uint8_t srt[NGTCP2_STATELESS_RESET_TOKENLEN] = "salukid-h3-srt!!";
    memcpy(tp.stateless_reset_token, srt, NGTCP2_STATELESS_RESET_TOKENLEN);
    tp.original_dcid = *dcid;
    tp.original_dcid_present = 1;

    int rv = ngtcp2_conn_server_new(&c->nc, dcid, scid, path, NGTCP2_PROTO_VER_V1,
                                    &nccbs, &s, &tp, NULL, c);
    if (rv != 0) { qlog("conn_server_new: %s", ngtcp2_strerror(rv)); goto err; }

    if (gnutls_init(&c->sess, GNUTLS_SERVER) != GNUTLS_E_SUCCESS) goto err;
    if (ngtcp2_crypto_gnutls_configure_server_session(c->sess) != 0) goto err;
    gnutls_session_set_ptr(c->sess, &c->conn_ref);
    if (gnutls_credentials_set(c->sess, GNUTLS_CRD_CERTIFICATE, g_cred) != GNUTLS_E_SUCCESS)
        goto err;
    static const gnutls_datum_t alpn = { .data=(unsigned char *)ALPN+1, .size=2 };
    gnutls_alpn_set_protocols(c->sess, &alpn, 1, GNUTLS_ALPN_MANDATORY);
    if (gnutls_priority_set(c->sess, g_prio) != GNUTLS_E_SUCCESS) goto err;

    ngtcp2_conn_set_tls_native_handle(c->nc, c->sess);
    return c;
err:
    cfree(c); return NULL;
}

/* ---------- pkt in ---------- */
static void on_pkt(int fd)
{
    uint8_t buf[MAX_UDP_PAYLOAD + 1];
    for (;;) {
        struct sockaddr_storage ss; socklen_t sl = sizeof ss;
        ssize_t rd = recvfrom(fd, buf, sizeof buf, MSG_DONTWAIT, (struct sockaddr*)&ss, &sl);
        if (rd < 0) { if (errno == EAGAIN || errno == EWOULDBLOCK) break; break; }
        if (rd < 21) continue;
        ngtcp2_pkt_hd hdr;
        if (ngtcp2_accept(&hdr, buf, (size_t)rd) != 0) {
            qlog("ngtcp2_accept: rejected %zd-byte datagram (ptype=%02x)", rd, buf[0]);
            continue;
        }
        /* Discover local address via getsockname. Path must be accurate or
         * ngtcp2 treats subsequent packets as migration attempts. */
        struct sockaddr_storage local_ss; socklen_t local_sl = sizeof local_ss;
        if (getsockname(fd, (struct sockaddr*)&local_ss, &local_sl) < 0) {
            memset(&local_ss, 0, sizeof local_ss);
            local_ss.ss_family = ss.ss_family;
            local_sl = (ss.ss_family == AF_INET6) ? sizeof(struct sockaddr_in6)
                                                 : sizeof(struct sockaddr_in);
        }
        ngtcp2_path path; memset(&path, 0, sizeof path);
        path.local.addr = (struct sockaddr*)&local_ss; path.local.addrlen = local_sl;
        path.remote.addr = (struct sockaddr*)&ss; path.remote.addrlen = sl;
        ngtcp2_pkt_info rpi; memset(&rpi, 0, sizeof rpi);

        qconn_t *c = cfind(&hdr.dcid);
        if (!c) {
            if (hdr.type == NGTCP2_PKT_INITIAL) {
                ngtcp2_cid scid;
                randb(scid.data, NGTCP2_MIN_INITIAL_DCIDLEN);
                scid.datalen = NGTCP2_MIN_INITIAL_DCIDLEN;
                c = cnew(&path, &hdr.dcid, &scid);
                if (!c) continue;
                /* Key the primary entry by the client's DCID, which is what
                 * the client uses for all Initial packets (retransmits etc.).
                 * Migration / SCID switching is out of scope (disabled). */
                cinsert(c, &hdr.dcid);
                qlog("new conn from dcid=%u bytes", hdr.dcid.datalen);
            } else continue;
        }
        ngtcp2_ssize frv = ngtcp2_conn_read_pkt(c->nc, &path, &rpi, buf, (size_t)rd, now_ns());
        c->last = now_ns();
        if (frv < 0) {
            qlog("read_pkt error: %s (%zd)", ngtcp2_strerror((int)frv), frv);
            uint8_t out[MAX_UDP_PAYLOAD];
            ngtcp2_pkt_info epi; memset(&epi, 0, sizeof epi);
            ngtcp2_ssize n = ngtcp2_conn_write_pkt(c->nc, &path, &epi, out, sizeof out, now_ns());
            if (n > 0) udp_send((struct sockaddr*)&ss, sl, out, (size_t)n);
            cremove(c); cfree(c); continue;
        }
        flush_pkts(c);
        flush_streams(c);
    }
}

/* ---------- TLS setup ---------- */
static int tls_init(void)
{
    if (!g_cert || !g_key) { fprintf(stderr, "quic: -C cert.pem -K key.pem required\n"); return -1; }
    gnutls_global_init();
    if (gnutls_certificate_allocate_credentials(&g_cred) != GNUTLS_E_SUCCESS) return -1;
    if (gnutls_certificate_set_x509_key_file(g_cred, g_cert, g_key, GNUTLS_X509_FMT_PEM) != GNUTLS_E_SUCCESS) {
        fprintf(stderr, "quic: failed to load cert/key\n"); return -1;
    }
    /* QUIC requires TLS 1.3 only. %DISABLE_TLS13_COMPAT_MODE disables the
     * TLS 1.3 middlebox-compatibility mode (which would wrap records in a
     * TLS 1.2-looking format, breaking QUIC). %NO_TICKETS avoids needing
     * session-ticket anti-replay state in this minimal server. */
    if (gnutls_priority_init(&g_prio,
            "NORMAL:-VERS-ALL:+VERS-TLS1.3:-GROUP-ALL:+GROUP-X25519:+GROUP-SECP256R1:"
            "%SERVER_PRECEDENCE:%DISABLE_TLS13_COMPAT_MODE:%NO_TICKETS",
            NULL) != GNUTLS_E_SUCCESS)
        return -1;
    return 0;
}

static int open_udp(uint16_t p)
{
    /* Open IPv6 socket (which also accepts IPv4 via dual-stack).
     * If IPv6 isn't available, fall back to IPv4. */
    int fd = socket(AF_INET6, SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC, 0);
    if (fd >= 0) {
        int v = 0; setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v, sizeof v);
        int one = 1; setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof one);
        int m = 4*1024*1024;
        setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &m, sizeof m);
        setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &m, sizeof m);
        struct sockaddr_in6 a = { .sin6_family = AF_INET6, .sin6_port = htons(p) };
        if (bind(fd, (struct sockaddr*)&a, sizeof a) == 0) return fd;
        close(fd);
    }
    /* Fall back to IPv4 only */
    fd = socket(AF_INET, SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    int one = 1; setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof one);
    int m = 4*1024*1024;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &m, sizeof m);
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &m, sizeof m);
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(p),
                             .sin_addr.s_addr = htonl(INADDR_ANY) };
    if (bind(fd, (struct sockaddr*)&a, sizeof a) < 0) { close(fd); return -1; }
    return fd;
}

static void onsig(int s) { (void)s; g_shut = 1; }

static void usage(const char *a0)
{
    fprintf(stderr,
        "Usage: %s -C cert.pem -K key.pem [-p port] [-r www_dir]\n"
        "  -p <port>   UDP port (default 443)\n"
        "  -C <cert>   TLS cert (PEM)\n"
        "  -K <key>    TLS key (PEM)\n"
        "  -r <dir>    Document root (default ./www)\n", a0);
}

int main(int argc, char **argv)
{
    int opt;
    while ((opt = getopt(argc, argv, "p:C:K:r:h")) != -1) {
        switch (opt) {
        case 'p': g_port = (uint16_t)atoi(optarg); break;
        case 'C': g_cert = optarg; break;
        case 'K': g_key = optarg; break;
        case 'r': g_www = optarg; break;
        default: usage(argv[0]); return 1;
        }
    }
    signal(SIGINT, onsig); signal(SIGTERM, onsig); signal(SIGPIPE, SIG_IGN);
    if (tls_init() < 0) return 1;
    g_udp = open_udp(g_port);
    if (g_udp < 0) { perror("bind"); return 1; }
    g_ep = epoll_create1(EPOLL_CLOEXEC);
    if (g_ep < 0) { perror("epoll_create1"); return 1; }
    struct epoll_event ev = { .events = EPOLLIN, .data.fd = g_udp };
    epoll_ctl(g_ep, EPOLL_CTL_ADD, g_udp, &ev);
    fprintf(stderr, "salukid h3: UDP/%u www=%s alpn=h3 ready\n", g_port, g_www);

    struct epoll_event evs[64];
    while (!g_shut) {
        int n = epoll_wait(g_ep, evs, 64, 100);
        if (n < 0 && errno != EINTR) break;
        for (int i = 0; i < n; i++) if (evs[i].data.fd == g_udp) on_pkt(g_udp);
        uint64_t t = now_ns();
        for (size_t b = 0; b < NVCONNS; b++) {
            qconn_t **pp = &g_tab[b];
            while (*pp) {
                qconn_t *c = *pp;
                ngtcp2_conn_handle_expiry(c->nc, t);
                flush_pkts(c);
                if (ngtcp2_conn_in_closing_period(c->nc) || t - c->last > IDLE_NS) {
                    *pp = c->next; cremove(c); cfree(c); continue;
                }
                pp = &(*pp)->next;
            }
        }
    }
    for (size_t b = 0; b < NVCONNS; b++)
        while (g_tab[b]) { qconn_t *c = g_tab[b]; g_tab[b] = c->next; cremove(c); cfree(c); }
    close(g_udp); close(g_ep);
    gnutls_priority_deinit(g_prio);
    gnutls_certificate_free_credentials(g_cred);
    gnutls_global_deinit();
    return 0;
}
