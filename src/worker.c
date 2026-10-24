/*
 * worker.c - Per-process epoll event loop. SO_REUSEPORT means each worker
 * process (forked from parent) has its own listener socket competing on
 * the same port, giving the kernel load distribution and eliminating
 * thundering-herd. SIGHUP causes workers to reload config (v0.1:
 * log message + cache purge).
 */
#include "conn.h"
#include "tls.h"
#include "h2.h"
#include "path.h"
#include "response.h"
#include "metrics.h"
#include "log.h"
#include "cache.h"
#include "modapi.h"
#include "ringbuf.h"
#include "subrequester.h"
#include "proxy.h"
#include <sys/epoll.h>

extern cache_t g_cache;
extern ringbuf_t g_log_ring;
extern slab_t g_conn_slab;
extern salukid_modlist_t *g_modlist;
extern int   g_lsock_http;
extern int   g_lsock_https;
extern volatile sig_atomic_t g_logrotate;

static void conn_register(int epfd, conn_t *c)
{
    struct epoll_event ev = { .events = EPOLLIN | EPOLLRDHUP, .data.ptr = c };
    if (c->tls && !c->ssl_hs_done) ev.events |= EPOLLOUT;
    epoll_ctl(epfd, EPOLL_CTL_ADD, c->fd, &ev);
}

static void conn_modify(int epfd, conn_t *c)
{
    struct epoll_event ev;
    ev.data.ptr = c;
    ev.events = EPOLLRDHUP;
    if (c->tls && !c->ssl_hs_done) {
        if (c->tls_want_read) ev.events |= EPOLLIN;
        if (c->tls_want_write) ev.events |= EPOLLOUT;
    } else {
        if (c->state == CONN_READING) ev.events |= EPOLLIN;
        if (c->state == CONN_WRITING) ev.events |= EPOLLOUT;
        if (c->state == CONN_H2)      ev.events |= EPOLLIN | EPOLLOUT;
    }
    epoll_ctl(epfd, EPOLL_CTL_MOD, c->fd, &ev);
}

static void conn_unregister(int epfd, conn_t *c)
{
    epoll_ctl(epfd, EPOLL_CTL_DEL, c->fd, NULL);
}

static void accept_all(int epfd, int lsock, bool tls, int wid)
{
    for (;;) {
        struct sockaddr_in sa; socklen_t sl = sizeof sa;
        int fd = accept4(lsock, (struct sockaddr*)&sa, &sl,
                         SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (fd < 0) break;
        if (g_metrics && g_metrics->active_connections >= SALUKID_MAX_CLIENTS) {
            close(fd); continue;
        }
        /* Defer ACCEPT to after handshake; enable TCP_DEFER_ACCEPT on http */
        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
        conn_t *c = conn_create(fd, tls, wid);
        conn_register(epfd, c);
        if (!c) { close(fd); continue; }
    }
}

static void drain_log(ringbuf_t *r, int outfd)
{
    (void)outfd;
    log_drain_to_backend(r);
}

/* Special sentinel pointer that identifies the subrequester eventfd */
static char g_subreq_sentinel;

extern void worker_fn(int wid, int fd_http, int fd_https); void worker_fn(int wid, int fd_http, int fd_https)
{
    salukid_log(LOG_INFO, "worker %d started (pid=%d)", wid, getpid());
    if (g_cfg.enable_proxy) proxy_start_hc(&g_proxy);
    if (g_cfg.https_port > 0) {
        if (!g_cfg.cert_path[0] || !g_cfg.key_path[0]) salukid_die("HTTPS enabled but -C/-K not provided");
        if (tls_worker_init() < 0) salukid_die("TLS worker init failed");
    }
    int epfd = epoll_create1(EPOLL_CLOEXEC);
    if (epfd < 0) salukid_die("epoll_create1: %s", strerror(errno));

    subrequester_init(2);

    struct epoll_event ev = { .events = EPOLLIN, .data.ptr = &fd_http };
    epoll_ctl(epfd, EPOLL_CTL_ADD, fd_http, &ev);
    if (fd_https >= 0) {
        ev.data.ptr = &fd_https;
        epoll_ctl(epfd, EPOLL_CTL_ADD, fd_https, &ev);
    }
    ev.events = EPOLLIN; ev.data.ptr = &g_subreq_sentinel;
    epoll_ctl(epfd, EPOLL_CTL_ADD, g_subreq.efd, &ev);

    struct epoll_event events[SALUKID_EPOLL_EVENTS_MAX];

    while (!g_shutdown) {
        if (g_reload) {
            g_reload = 0;
            cache_purge(&g_cache);
            modapi_reload_all(g_modlist);
            salukid_log(LOG_INFO, "worker %d reloaded config (cache purged)", wid);
        }
        if (g_logrotate) {
            g_logrotate = 0;
            if (g_cfg.log_path[0]) log_set_file(g_cfg.log_path);
            salukid_log(LOG_INFO, "worker %d reopened log file", wid);
        }
        int n = epoll_wait(epfd, events, SALUKID_EPOLL_EVENTS_MAX, 1000);
        drain_log(&g_log_ring, 2);
        for (int i = 0; i < n; i++) {
            void *p = events[i].data.ptr;
            if (p == &fd_http) {
                accept_all(epfd, fd_http, false, wid);
            } else if (p == &fd_https) {
                accept_all(epfd, fd_https, true, wid);
            } else if (p == &g_subreq_sentinel) {
                subrequester_drain(&g_subreq);
            } else {
                conn_t *c = p;
                if (events[i].events & (EPOLLERR|EPOLLHUP|EPOLLRDHUP)) {
                    salukid_log(LOG_ERR, "Closing connection %d (want_close=%d, events=%x)", c->fd, c->want_close, events[i].events); conn_unregister(epfd, c); conn_destroy(c); continue;
                }
                if (events[i].events & EPOLLIN) conn_on_readable(c);
                if (events[i].events & EPOLLOUT) conn_on_writable(c);
                if (c->want_close) { salukid_log(LOG_ERR, "Closing connection %d (want_close=%d, events=%x)", c->fd, c->want_close, events[i].events); conn_unregister(epfd, c); conn_destroy(c); continue; }
                conn_modify(epfd, c);
            }
        }
    }
    close(epfd);
    salukid_log(LOG_INFO, "worker %d exiting", wid);
}
