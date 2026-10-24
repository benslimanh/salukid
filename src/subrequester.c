/*
 * subrequester.c - Async HTTP subrequest thread pool.
 *
 * Thread-pool of N worker threads per worker process. Blocking HTTP/1.1
 * calls are executed there; completions are posted through an eventfd
 * so the main epoll loop can drain them inline - no per-connection
 * locking, callbacks all run on the main thread.
 *
 * Subrequests are heap-allocated, owned by the pool from submit until
 * drain/cancel, so connection close / arena reset cannot UAF.
 */

#include "subrequester.h"
#include "log.h"
#include <netdb.h>
#include <poll.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

subrequester_t g_subreq;

subrequest_t *subrequest_new(void)
{
    subrequest_t *sr = calloc(1, sizeof *sr);
    if (sr) atomic_init(&sr->cancelled, false);
    return sr;
}

void subrequest_free(subrequest_t *sr)
{
    if (!sr) return;
    if (sr->result_body) { free(sr->result_body); sr->result_body = NULL; }
    /* Caller may have stashed a heap-copied request body in sr->body for
     * POSTs. Free it if present. do_http_call makes its own copy before
     * transmitting so this is safe to free at completion. */
    if (sr->heap_body && sr->body) { free((void*)sr->body); sr->body = NULL; }
    if (sr->heap_headers) {
        for (size_t i = 0; i < sr->nheaders; i++) {
            free((void*)sr->headers[i].name);
            free((void*)sr->headers[i].value);
        }
        free((void*)sr->headers);
        sr->headers = NULL; sr->nheaders = 0;
    }
    free(sr);
}

static int parse_url(const char *url, char *host, size_t hcap,
                     uint16_t *port, const char **path)
{
    if (strncmp(url, "http://", 7) != 0) return -1;
    const char *p = url + 7;
    const char *slash = strchrnul(p, '/');
    size_t hl = (size_t)(slash - p);
    if (hl >= hcap) return -1;
    memcpy(host, p, hl); host[hl] = '\0';
    *path = slash;
    *port = 80;
    char *col = strchr(host, ':');
    if (col) { *col = '\0'; *port = (uint16_t)atoi(col+1); }
    return 0;
}

static int do_http_call(subrequest_t *sr)
{
    char host[256]; uint16_t port; const char *path = "/";
    if (parse_url(sr->url, host, sizeof host, &port, &path) < 0) return 500;

    /* Copy the body (if any) from arena memory NOW, since the arena may be
     * reset before the worker transmits. Body strings are short (OPA JSON). */
    uint8_t *body_copy = NULL;
    if (sr->body && sr->body_len) {
        body_copy = malloc(sr->body_len);
        if (!body_copy) return 500;
        memcpy(body_copy, sr->body, sr->body_len);
    }

    struct addrinfo hints = { .ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM }, *ai = NULL;
    char ps[16]; snprintf(ps, sizeof ps, "%u", port);
    if (getaddrinfo(host, ps, &hints, &ai) != 0 || !ai) { free(body_copy); return 502; }
    int fd = socket(ai->ai_family, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) { freeaddrinfo(ai); free(body_copy); return 502; }
    int flags = fcntl(fd, F_GETFL); fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);

    int rc = connect(fd, ai->ai_addr, ai->ai_addrlen); (void)rc;
    uint32_t tmo = sr->timeout_ms ? sr->timeout_ms : SALUKID_SUBREQ_DEFAULT_MS;
    int status = 502;
    struct pollfd pf = { .fd = fd, .events = POLLOUT };
    int pr = poll(&pf, 1, (int)tmo);
    if (pr <= 0) { close(fd); freeaddrinfo(ai); free(body_copy); return 504; }
    int err = 0; socklen_t el = sizeof err;
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el);
    if (err) { close(fd); freeaddrinfo(ai); free(body_copy); return 502; }

    /* Build request */
    char hdr[2048];
    int hl = snprintf(hdr, sizeof hdr,
        "%s %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n"
        "User-Agent: %s\r\nContent-Length: %zu\r\n",
        sr->method, path, host, SALUKID_SERVER_NAME, sr->body_len);
    for (size_t i = 0; i < sr->nheaders; i++) {
        if (hl >= (int)sizeof hdr - 64) break;
        hl += snprintf(hdr + hl, sizeof hdr - (size_t)hl, "%s: %s\r\n",
                       sr->headers[i].name, sr->headers[i].value);
    }
    if (hl < (int)sizeof hdr - 4)
        hl += snprintf(hdr + hl, sizeof hdr - (size_t)hl, "\r\n");
    ssize_t wr = write(fd, hdr, (size_t)hl);
    if (wr != (ssize_t)hl) { close(fd); freeaddrinfo(ai); free(body_copy); return 502; }
    bool body_ok = true;
    if (body_copy) {
        size_t off = 0;
        struct timespec bt0; clock_gettime(CLOCK_MONOTONIC, &bt0);
        uint64_t bstart = (uint64_t)bt0.tv_sec * 1000000000ULL + bt0.tv_nsec;
        uint64_t bdead = bstart + (uint64_t)tmo * 1000000ULL;
        while (off < sr->body_len) {
            struct timespec btn; clock_gettime(CLOCK_MONOTONIC, &btn);
            uint64_t bnow = (uint64_t)btn.tv_sec * 1000000000ULL + btn.tv_nsec;
            if (bnow >= bdead) { body_ok = false; break; }
            int brm = (int)((bdead - bnow) / 1000000ULL);
            if (brm < 1) brm = 1;
            struct pollfd pfw = { .fd = fd, .events = POLLOUT };
            if (poll(&pfw, 1, brm) <= 0) { body_ok = false; break; }
            ssize_t w = write(fd, body_copy + off, sr->body_len - off);
            if (w <= 0) { body_ok = false; break; }
            off += (size_t)w;
        }
    }
    free(body_copy);
    body_copy = NULL;
    if (!body_ok) { close(fd); freeaddrinfo(ai); return 504; }

    size_t cap = 16384, tot = 0;
    uint8_t *buf = malloc(cap);
    if (!buf) { close(fd); freeaddrinfo(ai); return 500; }
    struct timespec t0; clock_gettime(CLOCK_MONOTONIC, &t0);
    uint64_t start_ns = (uint64_t)t0.tv_sec * 1000000000ULL + t0.tv_nsec;
    uint64_t deadline_ns = start_ns + (uint64_t)tmo * 1000000ULL;
    for (;;) {
        if (atomic_load(&sr->cancelled)) break;
        struct timespec tn; clock_gettime(CLOCK_MONOTONIC, &tn);
        uint64_t now_ns = (uint64_t)tn.tv_sec * 1000000000ULL + tn.tv_nsec;
        if (now_ns >= deadline_ns) { status = 504; break; }
        int remain_ms = (int)((deadline_ns - now_ns) / 1000000ULL);
        if (remain_ms < 1) remain_ms = 1;
        if (remain_ms > 250) remain_ms = 250;
        struct pollfd pfr = { .fd = fd, .events = POLLIN };
        int prr = poll(&pfr, 1, remain_ms);
        if (prr == 0) continue;
        if (prr < 0) { if (errno == EINTR) continue; break; }
        ssize_t rd = read(fd, buf + tot, cap - tot - 1);
        if (rd > 0) {
            tot += (size_t)rd;
            if (tot >= cap - 1) {
                size_t ncap = cap * 2;
                uint8_t *nb = realloc(buf, ncap);
                if (!nb) break;
                buf = nb; cap = ncap;
            }
        } else break;
    }
    close(fd); freeaddrinfo(ai);

    if (tot > 12 && buf[9] >= '1' && buf[9] <= '5')
        status = (buf[9]-'0')*100 + (buf[10]-'0')*10 + (buf[11]-'0');

    /* Skip to body */
    uint8_t *body = NULL; size_t blen = 0;
    uint8_t *eoh = (uint8_t*)memmem(buf, tot, "\r\n\r\n", 4);
    if (eoh) { body = eoh + 4; blen = tot - (size_t)(body - buf); }
    sr->result_body = NULL; sr->result_body_len = 0;
    if (body && blen) {
        uint8_t *cpy = malloc(blen + 1);
        if (cpy) { memcpy(cpy, body, blen); cpy[blen] = '\0'; sr->result_body = cpy; sr->result_body_len = blen; }
    }
    free(buf);
    return status;
}

/* ---- completion queue (produced by workers, consumed by main thread) ---- */

typedef struct done_ent {
    subrequest_t *sr;
    struct done_ent *next;
} done_ent_t;

static done_ent_t *g_done_head;
static pthread_mutex_t g_done_mtx = PTHREAD_MUTEX_INITIALIZER;

/* Pending set for timeout / cancellation scans. Protected by g_pending_mtx,
 * only touched from the main epoll thread OR at completion. */
static subrequest_t *g_pending_head;
static pthread_mutex_t g_pending_mtx = PTHREAD_MUTEX_INITIALIZER;

static void pending_add(subrequest_t *sr)
{
    pthread_mutex_lock(&g_pending_mtx);
    sr->next = g_pending_head;
    g_pending_head = sr;
    pthread_mutex_unlock(&g_pending_mtx);
}

/* Remove sr from the pending list; returns true if found. */
static bool pending_remove(subrequest_t *sr)
{
    pthread_mutex_lock(&g_pending_mtx);
    subrequest_t *p = g_pending_head, *prev = NULL;
    while (p) {
        if (p == sr) {
            if (prev) prev->next = p->next; else g_pending_head = p->next;
            pthread_mutex_unlock(&g_pending_mtx);
            return true;
        }
        prev = p; p = p->next;
    }
    pthread_mutex_unlock(&g_pending_mtx);
    return false;
}

static void subreq_complete(subrequest_t *sr)
{
    done_ent_t *d = malloc(sizeof *d);
    if (!d) { /* OOM: best-effort fire with 500 */
        d = calloc(1, sizeof *d);
        if (!d) { sr->result_status = 500; /* fall through */ }
    }
    if (d) { d->sr = sr; d->next = NULL; }
    pthread_mutex_lock(&g_done_mtx);
    if (d) { d->next = g_done_head; g_done_head = d; }
    pthread_mutex_unlock(&g_done_mtx);
}

static void *subreq_worker(void *arg)
{
    subrequester_t *s = arg;
    while (!atomic_load(&s->stop)) {
        pthread_mutex_lock(&s->mtx);
        while (!s->head && !atomic_load(&s->stop))
            pthread_cond_wait(&s->cv, &s->mtx);
        if (atomic_load(&s->stop)) { pthread_mutex_unlock(&s->mtx); break; }
        subrequest_t *sr = s->head;
        if (sr) { s->head = sr->next; if (!s->head) s->tail = NULL; }
        pthread_mutex_unlock(&s->mtx);
        if (!sr) continue;

        sr->result_status = do_http_call(sr);

        pthread_mutex_lock(&s->mtx);
        atomic_fetch_sub(&s->queued, 1);
        pthread_mutex_unlock(&s->mtx);

        subreq_complete(sr);
        uint64_t one = 1;
        (void)!write(s->efd, &one, sizeof one);
    }
    return NULL;
}

int subrequester_init(int threads)
{
    subrequester_t *s = &g_subreq;
    memset(s, 0, sizeof *s);
    s->efd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (s->efd < 0) return -1;
    pthread_mutex_init(&s->mtx, NULL);
    pthread_cond_init(&s->cv, NULL);
    atomic_init(&s->stop, false);
    atomic_init(&s->queued, 0);
    s->nthreads = threads > 0 ? threads : 2;
    s->threads = calloc((size_t)s->nthreads, sizeof(pthread_t));
    if (!s->threads) return -1;
    for (int i = 0; i < s->nthreads; i++)
        pthread_create(&s->threads[i], NULL, subreq_worker, s);
    return 0;
}

void subrequester_shutdown(void)
{
    subrequester_t *s = &g_subreq;
    atomic_store(&s->stop, true);
    pthread_cond_broadcast(&s->cv);
    for (int i = 0; i < s->nthreads; i++) {
        if (s->threads) pthread_join(s->threads[i], NULL);
    }
    /* Drain any leftover completions */
    pthread_mutex_lock(&g_done_mtx);
    done_ent_t *d = g_done_head; g_done_head = NULL;
    pthread_mutex_unlock(&g_done_mtx);
    while (d) {
        done_ent_t *dn = d->next;
        subrequest_free(d->sr);
        free(d);
        d = dn;
    }
    pthread_mutex_lock(&g_pending_mtx);
    subrequest_t *p = g_pending_head; g_pending_head = NULL;
    pthread_mutex_unlock(&g_pending_mtx);
    while (p) {
        subrequest_t *pn = p->next;
        atomic_store(&p->cancelled, true);
        subrequest_free(p);
        p = pn;
    }
    if (s->efd >= 0) close(s->efd);
    free(s->threads);
    s->threads = NULL; s->nthreads = 0;
    pthread_mutex_destroy(&s->mtx);
    pthread_cond_destroy(&s->cv);
    pthread_mutex_destroy(&g_done_mtx);
    pthread_mutex_destroy(&g_pending_mtx);
}

int subrequester_submit(subrequest_t *sr)
{
    subrequester_t *s = &g_subreq;
    if (atomic_load(&s->queued) >= SALUKID_SUBREQ_QUEUE_MAX) {
        errno = EAGAIN;
        return -1;
    }
    sr->next = NULL;
    sr->in_pool = true;
    if (!sr->timeout_ms) sr->timeout_ms = SALUKID_SUBREQ_DEFAULT_MS;
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    sr->deadline_ns = (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec
                    + (uint64_t)sr->timeout_ms * 1000000ULL;
    pending_add(sr);
    pthread_mutex_lock(&s->mtx);
    if (s->tail) s->tail->next = sr; else s->head = sr;
    s->tail = sr;
    atomic_fetch_add(&s->queued, 1);
    pthread_cond_signal(&s->cv);
    pthread_mutex_unlock(&s->mtx);
    return 0;
}

void subrequester_cancel(subrequest_t *sr)
{
    if (!sr) return;
    atomic_store(&sr->cancelled, true);
    /* Pending list removal happens at drain time to avoid races; cb is skipped. */
}

static void fire_timeout(subrequest_t *sr)
{
    sr->result_status = 504;
    sr->result_body = NULL;
    sr->result_body_len = 0;
    done_ent_t *d = malloc(sizeof *d);
    if (!d) return;
    d->sr = sr; d->next = NULL;
    pthread_mutex_lock(&g_done_mtx);
    d->next = g_done_head; g_done_head = d;
    pthread_mutex_unlock(&g_done_mtx);
    uint64_t one = 1;
    (void)!write(g_subreq.efd, &one, sizeof one);
}

void subrequester_drain(subrequester_t *s)
{
    uint64_t v;
    while (read(s->efd, &v, sizeof v) == sizeof v) { /* consume tokens */ }

    /* First, scan pending list for timeouts. */
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t now = (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;

    pthread_mutex_lock(&g_pending_mtx);
    subrequest_t *p = g_pending_head, *prev = NULL;
    while (p) {
        subrequest_t *pn = p->next;
        bool timed_out = (p->deadline_ns && now >= p->deadline_ns);
        if (timed_out && !atomic_load(&p->cancelled)) {
            /* Fire a synthetic timeout completion and remove from pending. */
            if (prev) prev->next = pn; else g_pending_head = pn;
            /* Release lock before calling fire_timeout which takes g_done_mtx
             * and writes to efd. */
            pthread_mutex_unlock(&g_pending_mtx);
            atomic_store(&p->cancelled, true);
            fire_timeout(p);
            pthread_mutex_lock(&g_pending_mtx);
            p = g_pending_head; prev = NULL;
            continue;
        }
        prev = p; p = pn;
    }
    pthread_mutex_unlock(&g_pending_mtx);

    /* Drain completion list */
    pthread_mutex_lock(&g_done_mtx);
    done_ent_t *list = g_done_head; g_done_head = NULL;
    pthread_mutex_unlock(&g_done_mtx);

    while (list) {
        done_ent_t *dn = list->next;
        subrequest_t *sr = list->sr;
        free(list);
        list = dn;

        bool was_pending = pending_remove(sr);
        (void)was_pending;
        bool cancelled = atomic_load(&sr->cancelled);
        conn_t *origin = sr->origin;

        if (!cancelled && origin && sr->cb) {
            /* Callback runs on the main thread, exactly like Envoy. */
            sr->cb(origin, sr->result_status, NULL, 0,
                   sr->result_body, sr->result_body_len,
                   sr->module_ctx, sr->tag);
        }
        subrequest_free(sr);
    }
}
