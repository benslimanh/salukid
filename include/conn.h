/*
 * conn.h - Per-connection FSM. Each connection is allocated from a slab,
 * driven by epoll between READING/WRITING/CLOSING states. TLS is handled
 * by mbedTLS BIO-style calls; HTTP/2 is multiplexed via nghttp2 sessions
 * that share the same conn for I/O.
 */
#ifndef SALUKID_CONN_H
#define SALUKID_CONN_H

#include "common.h"
#include "arena.h"
#include "response.h"

typedef enum {
    CONN_READING,
    CONN_WRITING,
    CONN_CLOSING,
    CONN_H2,
    CONN_SUBREQ_PENDING   /* waiting for async subrequest (authz, http_call) */
} conn_state_t;

typedef enum {
    CONN_PLAIN = 0,
    CONN_TLS,
    CONN_H2_UPGRADED
} conn_mode_t;

typedef struct conn {
    int              fd;
    int              worker_id;
    conn_state_t     state;
    conn_mode_t      mode;
    bool             want_close;
    bool             keepalive;
    bool             tls;
    char             peer[64];
    uint16_t         peer_port;

    /* Read buffer */
    uint8_t         *rbuf;
    size_t           rbuf_cap;
    size_t           rbuf_len;
    size_t           rbuf_parsed;

    /* Write queue (slices, vectored) */
    slice_t         *whead;
    slice_t         *wtail;
    size_t           wqueued;
    size_t           wsent;        /* offset into head slice */

    /* Per-request arena */
    arena_t          arena;
    http_request_t   req;
    http_response_t  resp;

    /* TLS state */
    mbedtls_ssl_context  ssl;
    mbedtls_ssl_config   ssl_conf;
    bool                 ssl_ready;      /* ssl ctx initialised (ssl_init+setup done) */
    bool                 ssl_hs_done;    /* TLS handshake completed successfully */
    bool                 tls_want_read;
    bool                 tls_want_write;

    /* HTTP/2 state */
    nghttp2_session   *h2;
    bool               h2_active;

    /* Async subrequest (authz, ext_authz, proxy-wasm http_call) */
    struct subrequest *pending_subreq;
    uint64_t          subreq_deadline_ns;  /* 0 = none */
    bool              req_parsed;          /* we've parsed a full request and haven't reset yet */
    bool              req_mod_done;        /* on_request_headers phase already ran */
    size_t            req_consumed;        /* bytes in rbuf belonging to the current request */

    /* Timing */
    uint64_t         last_io_ns;
    uint64_t         req_start_ns;

    /* Intrusive slab freelist */
    struct conn     *slab_next;
} conn_t;

conn_t *conn_create(int fd, bool tls, int worker_id);
void    conn_destroy(conn_t *c);
void    conn_reset(conn_t *c);

/* Called by epoll when readable/writable */
void    conn_on_readable(conn_t *c);
void    conn_on_writable(conn_t *c);

/* Flush the write queue (non-blocking). Returns SALUKID_RC_AGAIN if pending. */
int     conn_flush(conn_t *c);

/* Exposed for async subrequest completion callbacks */
int     serve_request_on_conn(conn_t *c);
int     finalize_conn_response(conn_t *c);

#endif
