/*
 * conn.c - Per-connection FSM: create, reset, read, process, write.
 *
 * Async subrequest lifecycle:
 *   - Modules return SALUKID_AGAIN after submitting a subrequest.
 *   - conn->state becomes CONN_SUBREQ_PENDING; we DO NOT parse, compact,
 *     or arena_reset while in this state (the rbuf still holds the
 *     unconsumed request, the arena still holds request data).
 *   - When the subrequest completes, the callback either:
 *       (a) builds a response and calls finalize_conn_response, or
 *       (b) calls serve_request_on_conn(c) to resume normal serving
 *           (skipping the request_headers phase via req_phase_done flag).
 *   - After the response is written (conn_flush returns OK/EOF) we
 *     compact/arena_reset/reset for keepalive.
 */
#include "conn.h"
#include "tls.h"
#include "h2.h"
#include "path.h"
#include "response.h"
#include "metrics.h"
#include "log.h"
#include "module.h"
#include "modapi.h"
#include "cache.h"
#include "proxy.h"
#include "salukid_hooks.h"
#include "subrequester.h"
#include "admin.h"
#include "parser.h"
#include <sys/sendfile.h>
#include <fcntl.h>
#include <unistd.h>

extern salukid_module_t *g_modules;
extern salukid_modlist_t*g_modlist;
extern cache_t           g_cache;

extern slab_t            g_conn_slab;

static uint64_t ns_now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

conn_t *conn_create(int fd, bool tls, int worker_id)
{
    conn_t *c = slab_alloc(&g_conn_slab);
    if (!c) return NULL;
    memset(c, 0, sizeof *c);
    c->fd = fd; c->worker_id = worker_id; c->tls = tls;
    c->state = CONN_READING;
    c->mode = tls ? CONN_TLS : CONN_PLAIN;
    c->keepalive = true;
    c->rbuf_cap = SALUKID_IOBUF_SZ;
    c->rbuf = mmap(NULL, c->rbuf_cap, PROT_READ|PROT_WRITE,
                   MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (c->rbuf == MAP_FAILED) { c->rbuf = NULL; slab_free(&g_conn_slab, c); return NULL; }
    salukid_set_nonblock(fd);
    salukid_set_cloexec(fd);

    struct sockaddr_in sa; socklen_t sl = sizeof sa;
    if (getpeername(fd, (struct sockaddr*)&sa, &sl) == 0) {
        inet_ntop(AF_INET, &sa.sin_addr, c->peer, sizeof c->peer);
        c->peer_port = ntohs(sa.sin_port);
    }
    arena_init(&c->arena);
    http_request_reset(&c->req);
    c->last_io_ns = ns_now();
    c->req_start_ns = c->last_io_ns;
    metrics_incr_conn(+1);
    return c;
}

void conn_destroy(conn_t *c)
{
    if (!c) return;
    /* Cancel any in-flight async subrequest so its callback is dropped
     * and it frees itself. */
    if (c->pending_subreq) {
        subrequester_cancel(c->pending_subreq);
        c->pending_subreq = NULL;
    }
    if (c->ssl_ready) mbedtls_ssl_free(&c->ssl);
    if (c->h2_active) h2_session_destroy(c);
    if (c->rbuf) munmap(c->rbuf, c->rbuf_cap);
    if (c->fd >= 0) close(c->fd);
    arena_destroy(&c->arena);
    metrics_incr_conn(-1);
    slab_free(&g_conn_slab, c);
}

void conn_reset(conn_t *c)
{
    /* conn_reset is for per-request reuse (keepalive). It must only be
     * called when NO subrequest is pending. */
    if (c->pending_subreq) {
        subrequester_cancel(c->pending_subreq);
        c->pending_subreq = NULL;
    }
    if (c->ssl_ready) { mbedtls_ssl_free(&c->ssl); c->ssl_ready = false; c->ssl_hs_done = false; }
    if (c->h2_active) { h2_session_destroy(c); c->h2_active = false; }
    arena_reset(&c->arena);
    c->rbuf_len = c->rbuf_parsed = 0;
    c->whead = c->wtail = NULL;
    c->wqueued = c->wsent = 0;
    c->state = CONN_READING;
    http_request_reset(&c->req);
    c->keepalive = true;
    c->want_close = false;
    c->req_parsed = false;
    c->req_consumed = 0;
    c->subreq_deadline_ns = 0;
    c->last_io_ns = ns_now();
    c->req_start_ns = c->last_io_ns;
}

/* ---------- I/O ---------- */

static int conn_recv(conn_t *c)
{
    if (c->rbuf_len >= c->rbuf_cap) return SALUKID_FULL;
    size_t space = c->rbuf_cap - c->rbuf_len;
    ssize_t n;
    if (c->tls && c->ssl_ready) {
        /* Even after H2 is negotiated over TLS (h2_active=true), the
         * wire is still TLS-encrypted. The mbedtls_ssl BIO is already
         * pointed at c->fd, so we MUST keep using mbedtls_ssl_read() to
         * produce plaintext for the H2 parser. The only time we use
         * plain read() for H2 is h2c upgrade (no TLS). */
        n = mbedtls_ssl_read(&c->ssl, c->rbuf + c->rbuf_len, space);
        if (n == MBEDTLS_ERR_SSL_WANT_READ || n == MBEDTLS_ERR_SSL_WANT_WRITE) return SALUKID_RC_AGAIN;
        if (n == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) return SALUKID_EOF;
        if (n < 0) return SALUKID_ERR;
    } else {
        n = read(c->fd, c->rbuf + c->rbuf_len, space);
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return SALUKID_RC_AGAIN;
        if (n == 0) return SALUKID_EOF;
        if (n < 0) return SALUKID_ERR;
    }
    c->rbuf_len += (size_t)n;
    c->last_io_ns = ns_now();
    if (g_metrics) g_metrics->bytes_recv += (uint64_t)n;
    return SALUKID_OK;
}

/* Write as much of the queued slice chain as possible without blocking.
 * Does NOT free slices or reset per-request state — used by HTTP/2
 * where the connection is long-lived and slices are arena-owned.
 * Returns SALUKID_OK (all flushed), SALUKID_RC_AGAIN (would block), or
 * SALUKID_ERR. */
static int conn_flush_h2(conn_t *c)
{
    if (!c->whead) return SALUKID_OK;
    while (c->whead) {
        slice_t *s = c->whead;
        if (s->kind != SLICE_BUF) {
            /* H2 send callback always emits SLICE_BUF; file-send on H2
             * goes through drv_read chunked copies. Skip unexpected. */
            c->whead = s->next; c->wsent = 0; continue;
        }
        size_t off = c->wsent;
        ssize_t n;
        if (c->tls && c->ssl_ready) {
            n = mbedtls_ssl_write(&c->ssl, (const uint8_t*)s->base + off, s->len - off);
            if (n == MBEDTLS_ERR_SSL_WANT_READ || n == MBEDTLS_ERR_SSL_WANT_WRITE)
                return SALUKID_RC_AGAIN;
            if (n < 0) {
                salukid_log(LOG_ERR, "mbedtls_ssl_write returned %d", (int)n);
                return SALUKID_ERR;
            }
        } else {
            n = write(c->fd, (const char*)s->base + off, s->len - off);
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return SALUKID_RC_AGAIN;
            if (n < 0) return SALUKID_ERR;
        }
        c->wsent += (size_t)n;
        if (c->wsent < s->len) return SALUKID_RC_AGAIN;
        c->whead = s->next;
        c->wsent = 0;
    }
    c->wtail = NULL; c->wqueued = 0;
    return SALUKID_OK;
}

int conn_flush(conn_t *c)
{
    if (!c->whead) { c->state = CONN_READING; return SALUKID_OK; }

    if (g_cfg.tcp_cork) { int one = 1; setsockopt(c->fd, IPPROTO_TCP, TCP_CORK, &one, sizeof one); }

    while (c->whead) {
        slice_t *s = c->whead;
        if (s->kind == SLICE_BUF) {
            size_t off = c->wsent;
            ssize_t n;
            if (c->tls && c->ssl_ready) {
                n = mbedtls_ssl_write(&c->ssl, (const uint8_t*)s->base + off, s->len - off);
                if (n == MBEDTLS_ERR_SSL_WANT_READ || n == MBEDTLS_ERR_SSL_WANT_WRITE) return SALUKID_RC_AGAIN;
                if (n < 0) {
                    salukid_log(LOG_ERR, "mbedtls_ssl_write2 returned %d", (int)n);
                    return SALUKID_ERR;
                }
            } else {
                n = write(c->fd, (const char*)s->base + off, s->len - off);
                if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return SALUKID_RC_AGAIN;
                if (n < 0) return SALUKID_ERR;
            }
            c->wsent += (size_t)n;
            if (c->wsent < s->len) return SALUKID_RC_AGAIN;
        } else if (s->kind == SLICE_FILE) {
            off_t foff = s->file_off + (off_t)c->wsent;
            size_t left = s->len - c->wsent;
            ssize_t n = 0;
            /* On TLS connections we can NOT use sendfile(2) because the
             * file bytes would bypass mbedTLS and hit the TCP socket
             * unencrypted, corrupting the TLS record stream. Always
             * fall back to pread-into-buffer + mbedtls_ssl_write. On
             * plaintext connections we can use sendfile's zero-copy
             * path. */
            if (c->tls && c->ssl_ready) {
                char tmp[16384];
                size_t take = MIN(left, sizeof tmp);
                ssize_t rd = pread(s->fd, tmp, take, foff);
                if (rd <= 0) { close(s->fd); return SALUKID_ERR; }
                int w = mbedtls_ssl_write(&c->ssl, (const uint8_t*)tmp, (size_t)rd);
                if (w == MBEDTLS_ERR_SSL_WANT_READ || w == MBEDTLS_ERR_SSL_WANT_WRITE)
                    return SALUKID_RC_AGAIN;
                if (w < 0) { close(s->fd); return SALUKID_ERR; }
                n = w;
            } else {
                n = sendfile(c->fd, s->fd, &foff, left);
                if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return SALUKID_RC_AGAIN;
                if (n < 0) {
                    char tmp[16384];
                    size_t take = MIN(left, sizeof tmp);
                    ssize_t rd = pread(s->fd, tmp, take, foff);
                    if (rd <= 0) { close(s->fd); return SALUKID_ERR; }
                    ssize_t w = write(c->fd, tmp, (size_t)rd);
                    if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return SALUKID_RC_AGAIN;
                    if (w < 0) { close(s->fd); return SALUKID_ERR; }
                    n = w;
                }
            }
            c->wsent += (size_t)n;
            if (c->wsent < s->len) return SALUKID_RC_AGAIN;
            close(s->fd);
        }
        c->whead = s->next;
        c->wsent = 0;
    }
    c->wtail = NULL; c->wqueued = 0;

    if (g_cfg.tcp_cork) { int zero = 0; setsockopt(c->fd, IPPROTO_TCP, TCP_CORK, &zero, sizeof zero); }

    /* Response fully flushed. If an async subrequest was pending, the
     * sr was already freed in the callback via subrequest_free(). */
    c->pending_subreq = NULL;

    if (c->h2_active) {
        /* HTTP/2: keep connection open, do not reset arena or req state. */
        c->state = CONN_H2;
        return SALUKID_OK;
    }

    if (c->keepalive && !c->want_close) {
        /* Compact rbuf past the just-served request and reset per-request
         * state, but leave any pipelined bytes in rbuf so we parse them. */
        if (c->req_consumed < c->rbuf_len)
            memmove(c->rbuf, c->rbuf + c->req_consumed, c->rbuf_len - c->req_consumed);
        c->rbuf_len -= c->req_consumed;
        arena_reset(&c->arena);
        http_request_reset(&c->req);
        c->req_parsed = false;
        c->req_consumed = 0;
        c->subreq_deadline_ns = 0;
        c->state = CONN_READING;
        c->last_io_ns = ns_now();
        c->req_start_ns = c->last_io_ns;
        return SALUKID_OK;
    }
    c->state = CONN_CLOSING;
    return SALUKID_EOF;
}

/* ---------- Dispatch ---------- */


static int serve_request(conn_t *c)
{
    return serve_request_on_conn(c);
}

int serve_request_on_conn(conn_t *c)
{
    http_request_t *req = &c->req;
    http_response_t *resp = &c->resp;

    /* v1 stable ABI modules run once per request. If a subrequest already
     * completed and called back to resume serving, skip the request
     * headers phase so we don't re-enter modules. */
    int mr = SALUKID_PASS;
    if (g_modlist && !c->req_mod_done) {
        /* Clear any partial response state but do NOT memset the resp
         * struct to zero after resp_begin has been called (it would wipe
         * slices). Instead reset head/tail/len only. */
        c->resp.head = c->resp.tail = NULL;
        c->resp.total_len = 0;
        c->resp.has_body = false;
        c->resp.status = 0;
        c->resp.content_type[0] = '\0';
        c->resp.etag[0] = '\0';
        mr = modapi_run_request_headers(g_modlist, c);
        if (mr == 3 /* SALUKID_AGAIN from module ABI */) {
            c->req_mod_done = true;
            return 0; /* CONN_SUBREQ_PENDING was set by module */
        }
        c->req_mod_done = true;
        if (mr == SALUKID_HANDLED || mr == SALUKID_DENY) {
            resp = &c->resp;
            resp->keepalive = (req->version == HTTP_VER_11 && !req->connection_close);
            resp->head_only = (req->method == HTTP_M_HEAD);
            c->keepalive = resp->keepalive;
            goto emit;
        }
    }

    response_init(resp, &c->arena, req->method == HTTP_M_HEAD,
                  req->version == HTTP_VER_11 && !req->connection_close);
    c->keepalive = resp->keepalive;

    /* Internal endpoints */
    if (g_cfg.enable_metrics &&
        req->path_len == strlen(SALUKID_METRICS_PATH) &&
        memcmp(req->path, SALUKID_METRICS_PATH, req->path_len) == 0) {
        size_t bl = 0; char *b = metrics_render_prometheus(&bl);
        response_set_status(resp, HTTP_200);
        response_set_content_type(resp, "text/plain; version=0.0.4");
        
        if (b && !resp->head_only) {
            
            char *safe_buf = arena_alloc(&c->arena, bl);
            if (safe_buf) {
                memcpy(safe_buf, b, bl); 
                response_add_buf(resp, safe_buf, bl); 
            }
        }
        
        resp->total_len = bl; resp->has_body = true;
        free(b);
        goto emit;
    }
    
    if (req->path_len == strlen(SALUKID_HEALTHZ_PATH) &&
        memcmp(req->path, SALUKID_HEALTHZ_PATH, req->path_len) == 0) {
        const char *b = "ok";
        response_set_status(resp, HTTP_200);
        response_set_content_type(resp, "text/plain");
        if (!resp->head_only) response_add_cstr(resp, b);
        resp->total_len = 2; resp->has_body = true;
        goto emit;
    }
    /* Dynamic admin API /_admin/... */
    if (req->path_len > 8 && memcmp(req->path, "/_admin/", 8) == 0) {
        if (admin_handle_request(c, req, resp) > 0) goto emit;
    }

    /* Legacy modules */
    if (g_modules && module_invoke(g_modules, c, resp) == 0) goto emit;

    /* Proxy */
    if (g_cfg.enable_proxy && req->path_len > 1 && req->path[1] == '_') {
        char *body = NULL; size_t bl = 0; char ct[64] = "";
        char uri[SALUKID_MAX_URI];
        size_t L = MIN(req->uri_len, sizeof uri - 1);
        memcpy(uri, req->uri, L); uri[L] = '\0';
        const char *cookie = NULL;
        for (size_t i = 0; i < req->nheaders; i++) {
            if (req->headers[i].name_len == 6 &&
                !strncasecmp(req->headers[i].name, "Cookie", 6)) {
                cookie = req->headers[i].value;
                break;
            }
        }
        uint16_t st = 0;
        proxy_do(&g_proxy, &c->arena, uri, c->peer, cookie,
                 &body, &bl, ct, &st);
        response_set_status(resp, (http_status_t)st);
        response_set_content_type(resp, ct[0] ? ct : "text/plain");
        if (body && !resp->head_only) response_add_buf(resp, body, bl);
        resp->total_len = bl; resp->has_body = body != NULL;
        goto emit;
    }

    /* Static file */
    char fs[SALUKID_PATH_MAX];
    struct stat st; bool isdir = false;
    if (safe_resolve_path(g_cfg.www_dir, req->path, req->path_len,
                          fs, sizeof fs, &st, &isdir) == 0) {
        if (isdir) {
            response_error(resp, HTTP_403, "forbidden");
        } else {
            char ckey[SALUKID_MAX_URI + 64];
            bool dogz = g_cfg.gzip && client_accepts_gzip(req->accept_encoding) &&
                        st.st_size > SALUKID_GZIP_MIN;
            cache_make_key(ckey, sizeof ckey, http_method_str(req->method),
                           req->path, dogz ? "gzip" : "");
            const cache_entry_t *ce = g_cfg.enable_cache ? cache_get(&g_cache, ckey) : NULL;
            if (ce) {
                if (g_metrics) g_metrics->cache_hits++;
                response_set_status(resp, (http_status_t)ce->status);
                response_set_content_type(resp, ce->content_type);
                response_set_etag(resp, ce->etag);
                resp->gzipped = ce->gzipped;
                resp->has_body = true;
                resp->total_len = ce->body_len;
                if (!resp->head_only) response_add_buf(resp, ce->body, ce->body_len);
                goto emit;
            }
            if (g_metrics) g_metrics->cache_misses++;
            response_serve_file(resp, fs, &st, false, req);
            if (g_cfg.enable_cache && resp->status == HTTP_200 && !resp->head_only
                && resp->tail && resp->tail->kind == SLICE_BUF) {
                cache_put(&g_cache, ckey, resp->status, resp->content_type, resp->etag,
                          false, resp->tail->base, resp->tail->len,
                          SALUKID_CACHE_TTL_SEC);
            }
        }
    } else {
        response_error(resp, HTTP_404, "not found");
    }

emit:
    if (g_modlist) modapi_run_response_headers(g_modlist, c);
    if (response_finalize_headers(resp, c->tls) < 0) return -1;

    c->whead = resp->head; c->wtail = resp->tail;
    c->wqueued = resp->write_total; c->wsent = 0;
    c->state = CONN_WRITING;

    uint64_t dur = (ns_now() - c->req_start_ns) / 1000;
    log_emit(LOG_INFO, c->worker_id, c->peer, http_method_str(req->method),
             req->uri, resp->status, resp->total_len, dur);
    metrics_incr_request(resp->status, resp->total_len);
    return 0;
}

int finalize_conn_response(conn_t *c)
{
    http_response_t *resp = &c->resp;
    if (g_modlist) modapi_run_response_headers(g_modlist, c);
    if (response_finalize_headers(resp, c->tls) < 0) return -1;
    c->whead = resp->head; c->wtail = resp->tail;
    c->wqueued = resp->write_total; c->wsent = 0;
    c->state = CONN_WRITING;

    uint64_t dur = (ns_now() - c->req_start_ns) / 1000;
    log_emit(LOG_INFO, c->worker_id, c->peer, http_method_str(c->req.method),
             c->req.uri, resp->status, resp->total_len, dur);
    metrics_incr_request(resp->status, resp->total_len);
    return 0;
}

/* ---------- Event loop hooks ---------- */

void conn_on_readable(conn_t *c)
{
    if (c->h2_active) {
        c->state = CONN_H2;
        for (;;) {
            int rc = conn_recv(c);
            if (rc == SALUKID_RC_AGAIN || rc == SALUKID_EOF) break;
            if (rc == SALUKID_ERR) { c->want_close = true; return; }
            size_t n = c->rbuf_len - c->rbuf_parsed;
            if (n == 0) break;
            if (h2_feed(c, c->rbuf + c->rbuf_parsed, n) < 0) {
                c->want_close = true; return;
            }
            c->rbuf_len = c->rbuf_parsed = 0;
        }
        /* Always try to push outgoing bytes whenever we get IN, since
         * responses (SETTINGS ack, HEADERS, DATA) may have just been
         * queued by nghttp2_session_send. */
        if (c->whead) {
            int fr = conn_flush_h2(c);
            if (fr == SALUKID_ERR) { c->want_close = true; return; }
        }
        return;
    }
    if (c->tls && !c->ssl_hs_done) {
        int hr = tls_handshake(c);
        if (hr == SALUKID_RC_AGAIN) return;
        if (hr == SALUKID_ERR) { c->want_close = true; return; }
        if (c->h2_active) {
            /* h2_session_init queued the server connection preface
             * (SETTINGS frame) via send_callback. Flush it now before
             * processing client frames, otherwise the peer sees
             * "expected SETTINGS" errors. */
            if (c->whead) {
                int fr = conn_flush_h2(c);
                if (fr == SALUKID_ERR) { c->want_close = true; return; }
            }
            conn_on_readable(c);
            return;
        }
        /* For HTTP/1.1 over TLS, handshake just completed; fall through
         * into the normal read/parse loop below to receive and serve
         * the request on this same epoll callback. */
    }

    /* If we are waiting for an async subrequest, do NOT read new data
     * or touch the parse state. The rbuf still holds the unconsumed
     * request. We also don't want to buffer unbounded data - just
     * stop recv until we return to READING. */
    if (c->state == CONN_SUBREQ_PENDING) return;

    for (;;) {
        int rc = conn_recv(c);
        if (rc == SALUKID_RC_AGAIN) break;
        if (rc == SALUKID_EOF) { c->want_close = true; return; }
        if (rc == SALUKID_ERR) { c->want_close = true; return; }
        if (rc == SALUKID_FULL) { c->want_close = true; return; }

        size_t consumed = 0;
        int pr;
        if (c->req_parsed) {
            /* A prior async resume re-entered serving without re-parsing
             * (request was already in c->req). Skip to serve. */
            pr = SALUKID_OK;
            consumed = c->req_consumed;
        } else {
            pr = http_request_parse(&c->req, (const char*)c->rbuf, c->rbuf_len, &consumed);
        }
        if (pr == SALUKID_RC_AGAIN) break;  /* need more bytes */
        if (pr == SALUKID_ERR)  { c->want_close = true; return; }

        c->req_parsed = true;
        c->req_consumed = consumed;
        c->req_start_ns = ns_now();
        c->req_mod_done = false;

        /* 501 Not Implemented for unknown/unsupported HTTP methods.
         * The parser leaves method == HTTP_M_UNKNOWN rather than
         * silently rewriting to GET (which would be a policy bypass).
         * We build the response through the normal init/error/finalize
         * pipeline but inline here to keep the flow simple. */
        if (c->req.method == HTTP_M_UNKNOWN) {
            http_response_t *r2 = &c->resp;
            response_init(r2, &c->arena, false /*head_only*/,
                          c->req.version == HTTP_VER_11 && !c->req.connection_close);
            c->keepalive = r2->keepalive;
            response_error(r2, HTTP_501, "method not implemented");
            if (g_modlist) modapi_run_response_headers(g_modlist, c);
            if (response_finalize_headers(r2, c->tls) < 0) { c->want_close = true; return; }
            c->whead = r2->head; c->wtail = r2->tail;
            c->wqueued = r2->write_total; c->wsent = 0;
            c->state = CONN_WRITING;
            metrics_incr_request(r2->status, r2->total_len);
            if (consumed < c->rbuf_len)
                memmove(c->rbuf, c->rbuf + consumed, c->rbuf_len - consumed);
            c->rbuf_len -= consumed;
            break;
        }

        /* ---------- Request body collection ----------
         * If this request declares a body (Content-Length or chunked),
         * drain bytes from rbuf until the body is complete BEFORE
         * calling serve_request(). If we don't yet have enough bytes,
         * return to epoll and wait for more reads. Body is bounded by
         * SALUKID_MAX_REQ_BODY (1 MiB); overflow -> 413. */
        if (c->req.body_kind != SALUKID_BODY_NONE) {
            bool body_done = false;
            size_t after_hdrs = consumed; /* start of body */
            size_t avail = c->rbuf_len - after_hdrs;
            if (avail) {
                if (c->req.body_kind == SALUKID_BODY_CL) {
                    size_t have = c->req.body_len;
                    size_t need = c->req.content_length;
                    if (have < need) {
                        size_t take = need - have;
                        if (take > avail) take = avail;
                        if (http_request_body_append(&c->req, (const char*)((const char*)(c->rbuf + after_hdrs)), take) < 0) {
                            /* 413 */
                            http_response_t *r3 = &c->resp;
                            response_init(r3, &c->arena, false, false);
                            c->keepalive = false;
                            response_error(r3, HTTP_413, "payload too large");
                            if (g_modlist) modapi_run_response_headers(g_modlist, c);
                            if (response_finalize_headers(r3, c->tls) < 0) { c->want_close = true; return; }
                            c->whead = r3->head; c->wtail = r3->tail;
                            c->wqueued = r3->write_total; c->wsent = 0;
                            c->state = CONN_WRITING;
                            metrics_incr_request(r3->status, r3->total_len);
                            c->want_close = true;
                            break;
                        }
                        after_hdrs += take;
                    }
                    if (c->req.body_len == c->req.content_length) {
                        body_done = true;
                    }
                } else {
                    /* chunked */
                    size_t ch_consumed = 0;
                    bool ch_done = false;
                    int cr = http_request_chunked_feed(&c->req,
                                (const char*)((const char*)(c->rbuf + after_hdrs)), avail, &ch_consumed, &ch_done);
                    if (cr < 0) {
                        http_response_t *r3 = &c->resp;
                        response_init(r3, &c->arena, false, false);
                        c->keepalive = false;
                        response_error(r3, HTTP_400, "bad chunked encoding");
                        if (g_modlist) modapi_run_response_headers(g_modlist, c);
                        if (response_finalize_headers(r3, c->tls) < 0) { c->want_close = true; return; }
                        c->whead = r3->head; c->wtail = r3->tail;
                        c->wqueued = r3->write_total; c->wsent = 0;
                        c->state = CONN_WRITING;
                        metrics_incr_request(r3->status, r3->total_len);
                        c->want_close = true;
                        break;
                    }
                    after_hdrs += ch_consumed;
                    if (ch_done) body_done = true;
                }
            }
            /* Update req_consumed to advance past body bytes we already
             * absorbed. If body isn't done, we need more data; compact
             * and keep reading. */
            c->req_consumed = after_hdrs;
            if (!body_done) {
                /* If content-length is already fully satisfied we're done
                 * (the check above sets body_done). Otherwise we need
                 * more bytes from the network. Compact the rbuf so
                 * unconsumed body bytes are at the front. */
                if (after_hdrs < c->rbuf_len)
                    memmove(c->rbuf, (const char*)((const char*)(c->rbuf + after_hdrs)), c->rbuf_len - after_hdrs);
                c->rbuf_len -= after_hdrs;
                /* Avoid keeping a huge parsed flag while waiting for body */
                if (c->rbuf_len == 0) c->rbuf_parsed = 0;
                break;
            }
        }

        if (serve_request(c) < 0) { c->want_close = true; return; }

        /* If serve_request transitioned to CONN_SUBREQ_PENDING we must
         * NOT compact/reset the rbuf or arena. Break out and wait for
         * the subrequest to complete. */
        if (c->state == CONN_SUBREQ_PENDING) break;

        /* Request fully served; per-request cleanup happens in conn_flush
         * after write completes. But if there is no response body queued
         * (e.g. error path that set want_close), just reset now. */
        if (!c->whead) {
            if (consumed < c->rbuf_len)
                memmove(c->rbuf, c->rbuf + consumed, c->rbuf_len - consumed);
            c->rbuf_len -= consumed;
            arena_reset(&c->arena);
            http_request_reset(&c->req);
            c->req_parsed = false;
            c->req_consumed = 0;
            c->req_mod_done = false;
        }
        if (!c->keepalive) { c->want_close = true; return; }
        if (c->state != CONN_READING) break; /* WRITING */
    }
}

void conn_on_writable(conn_t *c)
{
    if (c->tls && !c->ssl_hs_done) {
        int hr = tls_handshake(c);
        if (hr == SALUKID_RC_AGAIN) return;
        if (hr == SALUKID_ERR) { c->want_close = true; return; }
        if (c->h2_active) {
            if (c->whead) {
                int fr = conn_flush_h2(c);
                if (fr == SALUKID_ERR) { c->want_close = true; return; }
            }
        }
        conn_on_readable(c);
        return;
    }

    if (c->h2_active) {
        c->state = CONN_H2;
        h2_flush(c);
        int rc = conn_flush_h2(c);
        if (rc == SALUKID_ERR) c->want_close = true;
        return;
    }
    int rc = conn_flush(c);
    if (rc == SALUKID_ERR || rc == SALUKID_EOF) c->want_close = true;
}
