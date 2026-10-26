/*
 * h2.c - HTTP/2 (nghttp2) integration.
 *
 * Uses the send_callback / recv_callback API paired with mem_recv (we
 * explicitly feed decrypted TLS bytes via nghttp2_session_mem_recv,
 * and rely on the send_callback to queue output frames). This mirrors
 * the nghttp2 "server" example and is the path that produces the
 * correct server connection preface (27-byte SETTINGS frame) BEFORE
 * any client preface is received.
 */
#include "h2.h"
#include "response.h"
#include "path.h"
#include "metrics.h"
#include "log.h"
#include "gzip_etag.h"
#include "salukid_hooks.h"
#include <fcntl.h>
#include <time.h>
#include <unistd.h>

typedef struct {
    int         fd;
    const uint8_t *mem;
    size_t      body_len;       /* bytes we will transmit (after range) */
    size_t      content_len;    /* actual resource size (for HEAD CL header) */
    size_t      off;            /* current read offset into file/memory */
    size_t      range_start;
    size_t      range_end;
    bool        have_range;
    int         status;
    char        path[SALUKID_MAX_URI];
    size_t      path_len;
    char        method[12];
    char        inm[256];
    char        range_hdr[128];
    bool        has_inm;
    bool        has_range;
    bool        head_only;
} h2_stream_t;

typedef struct { const uint8_t *p; size_t len; } drv_t;

static ssize_t h2_send(nghttp2_session *s, const uint8_t *data, size_t len,
                       int flags, void *userp)
{
    (void)s;(void)flags;
    conn_t *c = userp;
    uint8_t *copy = arena_alloc(&c->arena, len);
    if (!copy) return NGHTTP2_ERR_CALLBACK_FAILURE;
    memcpy(copy, data, len);
    slice_t *sl = arena_alloc(&c->arena, sizeof *sl);
    if (!sl) return NGHTTP2_ERR_CALLBACK_FAILURE;
    sl->kind = SLICE_BUF; sl->base = (char*)copy; sl->len = len;
    sl->fd = -1; sl->next = NULL;
    if (!c->whead) c->whead = sl; else c->wtail->next = sl;
    c->wtail = sl; c->wqueued += len;
    return (ssize_t)len;
}

static ssize_t drv_read(nghttp2_session *ss, int32_t si, uint8_t *b, size_t bl,
                        uint32_t *fl, nghttp2_data_source *ds, void *up)
{
    (void)ss;(void)si;(void)up;
    drv_t *d = ds->ptr;
    h2_stream_t *st = (h2_stream_t*)(d + 1);
    if (st->head_only || st->body_len == 0) { *fl = NGHTTP2_DATA_FLAG_EOF; return 0; }
    /* st->off tracks bytes emitted so far; stop after body_len */
    size_t remain = st->body_len - st->off;
    if (remain == 0) { *fl = NGHTTP2_DATA_FLAG_EOF; return 0; }
    if (st->fd >= 0) {
        static __thread uint8_t chunk[65536];
        size_t take = bl < sizeof chunk ? bl : sizeof chunk;
        if (take > remain) take = remain;
        off_t foff = (off_t)(st->have_range ? st->range_start : 0) + (off_t)st->off;
        ssize_t rd = pread(st->fd, chunk, take, foff);
        if (rd <= 0) { *fl = NGHTTP2_DATA_FLAG_EOF; return 0; }
        memcpy(b, chunk, (size_t)rd);
        st->off += (size_t)rd;
        if (st->off >= st->body_len) *fl = NGHTTP2_DATA_FLAG_EOF;
        return (ssize_t)rd;
    }
    if (!d->p || d->len == 0) { *fl = NGHTTP2_DATA_FLAG_EOF; return 0; }
    size_t take = MIN(bl, d->len);
    if (take > remain) take = remain;
    memcpy(b, d->p, take);
    d->p += take; d->len -= take;
    st->off += take;
    if (d->len == 0 || st->off >= st->body_len) *fl = NGHTTP2_DATA_FLAG_EOF;
    return (ssize_t)take;
}

static void nv_add(nghttp2_nv *nv, int *idx, const char *n, const char *v)
{
    nv[*idx].name = (uint8_t*)n; nv[*idx].namelen = strlen(n);
    nv[*idx].value = (uint8_t*)v; nv[*idx].valuelen = strlen(v);
    nv[*idx].flags = NGHTTP2_NV_FLAG_NONE;
    (*idx)++;
}

/* Append a fixed set of baseline security/date headers to the H2 nv array.
 * HTTP/2 forbids connection-specific headers and the obsolete 'Date' is not
 * required by RFC 9110 for H2, but we add it (plus the same security headers
 * we send on H1) for client-compatibility and defense-in-depth. */
static int nv_add_standard_headers(nghttp2_nv *nv, int nh, int max)
{
    /* date */
    static __thread char datebuf[64];
    time_t now = time(NULL);
    struct tm gmt;
    gmtime_r(&now, &gmt);
    size_t dl = strftime(datebuf, sizeof datebuf, "%a, %d %b %Y %H:%M:%S GMT", &gmt);
    datebuf[dl] = '\0';
    if (nh < max) nv_add(nv, &nh, "date", datebuf);
    if (nh < max) nv_add(nv, &nh, "x-content-type-options", "nosniff");
    if (nh < max) nv_add(nv, &nh, "x-frame-options", "DENY");
    if (nh < max) nv_add(nv, &nh, "referrer-policy", "no-referrer");
    if (nh < max) nv_add(nv, &nh, "content-security-policy", "default-src 'self'");
    if (nh < max) nv_add(nv, &nh, "permissions-policy", "geolocation=(), microphone=(), camera=()");
    if (nh < max) nv_add(nv, &nh, "strict-transport-security", "max-age=63072000; includeSubDomains; preload");
    return nh;
}

static int on_begin_hdrs(nghttp2_session *s, const nghttp2_frame *fr, void *u)
{
    conn_t *c = u;
    if (fr->hd.type != NGHTTP2_HEADERS || fr->headers.cat != NGHTTP2_HCAT_REQUEST)
        return 0;
    h2_stream_t *st = arena_alloc(&c->arena, sizeof *st);
    if (!st) return NGHTTP2_ERR_CALLBACK_FAILURE;
    memset(st, 0, sizeof *st);
    st->fd = -1; st->status = HTTP_404;
    nghttp2_session_set_stream_user_data(s, fr->hd.stream_id, st);
    return 0;
}

static int on_hdr(nghttp2_session *s, const nghttp2_frame *fr,
                  const uint8_t *n, size_t nl,
                  const uint8_t *v, size_t vl, uint8_t flags, void *u)
{
    (void)flags;(void)u;
    h2_stream_t *st = nghttp2_session_get_stream_user_data(s, fr->hd.stream_id);
    if (!st) return 0;
    if (nl == 5 && !memcmp(n, ":path", 5)) {
        size_t L = vl < sizeof st->path - 1 ? vl : sizeof st->path - 1;
        memcpy(st->path, v, L); st->path[L] = '\0'; st->path_len = L;
    } else if (nl == 7 && !memcmp(n, ":method", 7)) {
        size_t L = vl < sizeof st->method - 1 ? vl : sizeof st->method - 1;
        memcpy(st->method, v, L); st->method[L] = '\0';
        if (L == 4 && !memcmp(v, "HEAD", 4)) st->head_only = true;
    } else if (nl == 13 && !strncasecmp((const char*)n, "if-none-match", 13)) {
        size_t L = vl < sizeof st->inm - 1 ? vl : sizeof st->inm - 1;
        memcpy(st->inm, v, L); st->inm[L] = '\0'; st->has_inm = true;
    } else if (nl == 5 && !strncasecmp((const char*)n, "range", 5)) {
        size_t L = vl < sizeof st->range_hdr - 1 ? vl : sizeof st->range_hdr - 1;
        memcpy(st->range_hdr, v, L); st->range_hdr[L] = '\0'; st->has_range = true;
    }
    return 0;
}

static int on_frame_recv(nghttp2_session *s, const nghttp2_frame *frame, void *userp)
{
    conn_t *c = userp;
    if (frame->hd.type != NGHTTP2_HEADERS || frame->headers.cat != NGHTTP2_HCAT_REQUEST)
        return 0;
    int32_t sid = frame->hd.stream_id;
    h2_stream_t *st = nghttp2_session_get_stream_user_data(s, sid);
    if (!st) return 0;

    /* nghttp2 auto-acks SETTINGS; we don't need to do anything special. */

    const char *path = st->path[0] ? st->path : "/";
    size_t plen = st->path_len ? st->path_len : 1;

    /* Parse simple "bytes=start-end" Range header. */
    size_t range_start = 0, range_end = 0;
    bool have_range = false;
    if (st->has_range) {
        /* Accept "bytes=a-b" where a is required; b optional (-> end). */
        if (strncmp(st->range_hdr, "bytes=", 6) == 0) {
            const char *p = st->range_hdr + 6;
            char *endp;
            long sv = strtol(p, &endp, 10);
            if (endp != p && sv >= 0 && *endp == '-') {
                range_start = (size_t)sv;
                p = endp + 1;
                if (*p) {
                    long ev = strtol(p, &endp, 10);
                    if (endp != p && ev >= sv) range_end = (size_t)ev;
                    else range_end = (size_t)-1;
                } else {
                    range_end = (size_t)-1;
                }
                have_range = true;
            }
        }
    }

    /* /metrics shortcut */
    if (g_cfg.enable_metrics &&
        plen == strlen(SALUKID_METRICS_PATH) &&
        memcmp(path, SALUKID_METRICS_PATH, plen) == 0) {
        
        size_t bl = 0; 
        char *b = metrics_render_prometheus(&bl);
        
        nghttp2_nv hdrs[32]; int nh = 0;
        nv_add(hdrs, &nh, ":status", "200");
        nv_add(hdrs, &nh, "content-type", "text/plain; version=0.0.4");
        char clb[24]; snprintf(clb, sizeof clb, "%zu", bl);
        nv_add(hdrs, &nh, "content-length", clb);
        nv_add(hdrs, &nh, "server", SALUKID_SERVER_NAME);
        nh = nv_add_standard_headers(hdrs, nh, 32);

        if (b && !st->head_only && bl > 0) {
            /* تخصيص مساحة آمنة للمؤشرات وبيانات الإحصائيات معاً في الـ Arena */
            drv_t *d = arena_alloc(&c->arena, sizeof *d + sizeof *st + bl);
            if (!d) return NGHTTP2_ERR_CALLBACK_FAILURE;
            
            h2_stream_t *fp = (h2_stream_t*)(d + 1); 
            *fp = *st;
            
            uint8_t *safe_buf = (uint8_t*)(fp + 1);
            memcpy(safe_buf, b, bl); /* النسخ الآمن */

            d->p = safe_buf; 
            d->len = bl;
            fp->body_len = bl; 
            fp->content_len = bl; 
            fp->mem = safe_buf;
            fp->off = 0;
            
            nghttp2_data_provider pr; memset(&pr, 0, sizeof pr);
            pr.read_callback = drv_read; pr.source.ptr = d;
            nghttp2_session_set_stream_user_data(s, sid, fp);
            nghttp2_submit_response(s, sid, hdrs, (size_t)nh, &pr);
        } else {
            nghttp2_submit_response(s, sid, hdrs, (size_t)nh, NULL);
        }
        
        if (g_metrics) g_metrics->requests_total++;
        return 0;
    }

    /* /healthz shortcut */
    if (plen == strlen(SALUKID_HEALTHZ_PATH) &&
        memcmp(path, SALUKID_HEALTHZ_PATH, plen) == 0) {
        nghttp2_nv hdrs[32]; int nh = 0;
        const char *b = "ok"; size_t bl = 2;
        size_t content_len = bl, send_len = bl;
        nv_add(hdrs, &nh, ":status", "200");
        nv_add(hdrs, &nh, "content-type", "text/plain");
        char clb[24]; snprintf(clb, sizeof clb, "%zu", content_len);
        nv_add(hdrs, &nh, "content-length", clb);
        nv_add(hdrs, &nh, "server", SALUKID_SERVER_NAME);
        nh = nv_add_standard_headers(hdrs, nh, 32);
        if (!st->head_only && send_len > 0) {
            drv_t *d = arena_alloc(&c->arena, sizeof *d + sizeof *st);
            if (!d) return NGHTTP2_ERR_CALLBACK_FAILURE;
            h2_stream_t *fp = (h2_stream_t*)(d + 1); *fp = *st;
            d->p = (const uint8_t*)b; d->len = send_len;
            fp->body_len = send_len; fp->content_len = content_len; fp->mem = (const uint8_t*)b;
            fp->off = 0;
            nghttp2_data_provider pr; memset(&pr, 0, sizeof pr);
            pr.read_callback = drv_read; pr.source.ptr = d;
            nghttp2_session_set_stream_user_data(s, sid, fp);
            nghttp2_submit_response(s, sid, hdrs, (size_t)nh, &pr);
        } else {
            nghttp2_submit_response(s, sid, hdrs, (size_t)nh, NULL);
        }
        if (g_metrics) g_metrics->requests_total++;
        return 0;
    }

    char fs[SALUKID_PATH_MAX]; struct stat stbuf; bool isdir = false;
    const uint8_t *body = NULL; size_t blen = 0;
    int status = HTTP_404; char ctype[96] = "text/plain";
    char etag[32] = {0};
    bool has_body_fd = false; size_t file_total = 0;
    int resp_status = HTTP_404;

    int rc __attribute__((unused)) =
        safe_resolve_path(g_cfg.www_dir, path, plen, fs, sizeof fs, &stbuf, &isdir);
    if (rc == 0) {
        if (!isdir && S_ISREG(stbuf.st_mode)) {
            etag_for(&stbuf, etag, sizeof etag);
            bool hit304 = st->has_inm && etag_match(st->inm, etag);
            if (hit304) {
                resp_status = HTTP_304;
            } else {
                int fd = open(fs, O_RDONLY|O_NONBLOCK|O_CLOEXEC);
                if (fd >= 0) {
                    const char *ct = content_type_for(fs, strlen(fs));
                    snprintf(ctype, sizeof ctype, "%s", ct);
                    file_total = (size_t)stbuf.st_size;
                    /* Clamp range */
                    if (have_range) {
                        if (range_start >= file_total) {
                            /* 416 out of range; fall back to full 200 */
                            have_range = false;
                        } else {
                            if (range_end == (size_t)-1 || range_end >= file_total)
                                range_end = file_total - 1;
                        }
                    }
                    resp_status = have_range ? HTTP_206 : HTTP_200;
                    size_t send_len = have_range ? (range_end - range_start + 1) : file_total;
                    if (!st->head_only) {
                        if (file_total <= 131072) {
                            uint8_t *buf = arena_alloc(&c->arena, file_total);
                            if (buf) {
                                ssize_t rd = pread(fd, buf, file_total, 0);
                                if (rd > 0) {
                                    body = buf + (have_range ? range_start : 0);
                                    blen = have_range ? (range_end - range_start + 1) : (size_t)rd;
                                    send_len = blen;
                                }
                                close(fd); fd = -1;
                            } else {
                                has_body_fd = true; st->fd = fd;
                            }
                        } else {
                            has_body_fd = true; st->fd = fd;
                        }
                    } else {
                        close(fd); fd = -1;
                    }
                    status = resp_status;
                }
            }
        } else {
            resp_status = HTTP_403;
            body = (const uint8_t*)"forbidden"; blen = 9; file_total = 9;
        }
    } else {
        resp_status = HTTP_404;
        body = (const uint8_t*)"not found"; blen = 9; file_total = 9;
    }

    st->status = resp_status;
    st->mem = body;
    size_t content_len = file_total;
    size_t send_len;
    if (resp_status == HTTP_304) {
        send_len = 0;
        content_len = 0;
    } else if (st->head_only) {
        send_len = 0;
        /* content-length is the resource length for HEAD */
    } else {
        send_len = has_body_fd
            ? (have_range ? (range_end - range_start + 1) : file_total)
            : blen;
        if (!has_body_fd) content_len = blen;
    }
    if (resp_status == HTTP_403 || resp_status == HTTP_404) {
        content_len = blen;
        send_len = st->head_only ? 0 : blen;
    }
    st->body_len = send_len;
    st->content_len = content_len;
    st->off = 0;
    st->range_start = range_start;
    st->range_end = range_end;
    st->have_range = have_range && resp_status == HTTP_206;

    nghttp2_nv hdrs[32]; int nh = 0;
    char sbuf[4]; snprintf(sbuf, sizeof sbuf, "%03d", resp_status);
    char clb[24]; snprintf(clb, sizeof clb, "%zu", content_len);
    nv_add(hdrs, &nh, ":status", sbuf);
    nv_add(hdrs, &nh, "content-type", ctype);
    nv_add(hdrs, &nh, "content-length", clb);
    nv_add(hdrs, &nh, "server", SALUKID_SERVER_NAME);
    if (etag[0]) nv_add(hdrs, &nh, "etag", etag);
    if (have_range && resp_status == HTTP_206) {
        char cr[96];
        snprintf(cr, sizeof cr, "bytes %zu-%zu/%zu", range_start, range_end, file_total);
        nv_add(hdrs, &nh, "content-range", cr);
        nv_add(hdrs, &nh, "accept-ranges", "bytes");
    }
    nh = nv_add_standard_headers(hdrs, nh, 32);

    if (!st->head_only && send_len > 0) {
        drv_t *d = arena_alloc(&c->arena, sizeof *d + sizeof *st);
        if (d) {
            h2_stream_t *fp = (h2_stream_t*)(d + 1);
            *fp = *st;
            d->p = has_body_fd ? NULL : body;
            d->len = send_len;
            fp->body_len = send_len;
            fp->content_len = content_len;
            nghttp2_data_provider pr;
            memset(&pr, 0, sizeof pr);
            pr.read_callback = drv_read;
            pr.source.ptr = d;
            nghttp2_session_set_stream_user_data(s, sid, fp);
            nghttp2_submit_response(s, sid, hdrs, (size_t)nh, &pr);
            if (g_metrics) g_metrics->requests_total++;
            return 0;
        }
    }
    nghttp2_submit_response(s, sid, hdrs, (size_t)nh, NULL);
    if (g_metrics) g_metrics->requests_total++;
    return 0;
}

static int on_stream_close(nghttp2_session *s, int32_t sid, uint32_t ec, void *u)
{
    (void)ec;(void)u;
    h2_stream_t *st = nghttp2_session_get_stream_user_data(s, sid);
    if (st && st->fd >= 0) { close(st->fd); st->fd = -1; }
    return 0;
}

int h2_session_init(conn_t *c)
{
    nghttp2_session_callbacks *cbs;
    nghttp2_session_callbacks_new(&cbs);
    nghttp2_session_callbacks_set_send_callback(cbs, h2_send);
    nghttp2_session_callbacks_set_on_begin_headers_callback(cbs, on_begin_hdrs);
    nghttp2_session_callbacks_set_on_header_callback(cbs, on_hdr);
    nghttp2_session_callbacks_set_on_frame_recv_callback(cbs, on_frame_recv);
    nghttp2_session_callbacks_set_on_stream_close_callback(cbs, on_stream_close);

    nghttp2_option *opt;
    nghttp2_option_new(&opt);
    if (nghttp2_session_server_new2(&c->h2, cbs, c, opt) != 0) {
        nghttp2_session_callbacks_del(cbs);
        nghttp2_option_del(opt);
        return -1;
    }
    nghttp2_session_callbacks_del(cbs);
    nghttp2_option_del(opt);
    nghttp2_settings_entry settings[] = {
        { NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100 },
        { NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, 65535 },
        { NGHTTP2_SETTINGS_ENABLE_PUSH, 0 },
    };
    nghttp2_submit_settings(c->h2, NGHTTP2_FLAG_NONE, settings,
                            sizeof(settings)/sizeof(settings[0]));
    /* Send server connection preface (SETTINGS frame) immediately. */
    if (nghttp2_session_send(c->h2) != 0) {
        nghttp2_session_del(c->h2); c->h2 = NULL;
        return -1;
    }
    return 0;
}

void h2_session_destroy(conn_t *c)
{
    if (c->h2) { nghttp2_session_del(c->h2); c->h2 = NULL; }
}

int h2_feed(conn_t *c, const uint8_t *data, size_t len)
{
    ssize_t rv = nghttp2_session_mem_recv(c->h2, data, len);
    if (rv < 0) return -1;
    /* After processing received frames, send any queued responses. */
    if (nghttp2_session_send(c->h2) != 0) return -1;
    return 0;
}

int h2_flush(conn_t *c)
{
    if (nghttp2_session_send(c->h2) != 0) return -1;
    return 0;
}

int h2_want_readwrite(conn_t *c, bool *want_read, bool *want_write)
{
    *want_read = true;
    *want_write = (c->wqueued > 0);
    return 0;
}

int h2_stream_read(conn_t *c, int32_t stream_id, uint8_t *buf, size_t len, size_t *rlen)
{
    (void)c; (void)stream_id; (void)buf; (void)len; *rlen = 0;
    return SALUKID_EOF;
}