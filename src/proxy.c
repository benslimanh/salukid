/*
 * proxy.c - Reverse proxy with advanced load balancing:
 *   - weighted round-robin, least-connections, sticky cookie / IP hash
 *   - per-upstream circuit breaker (failures -> OPEN -> HALF_OPEN probe)
 *   - active health checks (background thread, HTTP GET hc_path)
 *   - runtime reconfiguration (add/remove upstreams without restart)
 *
 * The proxy is still HTTP/1.1 over blocking sockets (per-request), but
 * the selection + failure accounting matches Envoy-style semantics
 * enough for an edge/API gateway.
 */
#include "proxy.h"
#include "metrics.h"
#include "log.h"
#include <netdb.h>
#include <poll.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

static int64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec/1000000;
}

static uint64_t fnv1a(const void *buf, size_t len)
{
    const uint8_t *p = (const uint8_t*)buf;
    uint64_t h = 1469598103934665603ULL;
    for (size_t i = 0; i < len; i++) { h ^= p[i]; h *= 1099511628211ULL; }
    return h;
}

int proxy_init(proxy_t *p, const char *spec, int cb_threshold, int cb_recovery_ms)
{
    memset(p, 0, sizeof *p);
    pthread_mutex_init(&p->mtx, NULL);
    atomic_init(&p->hc_stop, 0);
    atomic_init(&p->rr_idx, 0);
    atomic_init(&p->reconfig_gen, 1);
    p->algo = LB_RR;
    snprintf(p->sticky_cookie, sizeof p->sticky_cookie, "salid");
    p->cap = 16;
    p->ups = calloc(p->cap, sizeof *p->ups);
    if (!p->ups) return -1;
    p->nups = 0;
    /* Parse spec "host:port[:weight],..." */
    if (spec) {
        const char *s = spec;
        while (*s && p->nups < p->cap) {
            const char *c = strchrnul(s, ',');
            size_t L = (size_t)(c - s);
            char tmp[256];
            if (L >= sizeof tmp) return -1;
            memcpy(tmp, s, L); tmp[L] = '\0';
            char *col1 = strchr(tmp, ':');
            char *col2 = col1 ? strchr(col1+1, ':') : NULL;
            uint16_t port = 80; int weight = 1;
            if (col1) {
                *col1 = '\0';
                port = (uint16_t)atoi(col1+1);
                if (col2) { *col2 = '\0'; weight = atoi(col2+1); if (weight<1) weight=1; }
            }
            upstream_t *u = &p->ups[p->nups++];
            memset(u, 0, sizeof *u);
            snprintf(u->host, sizeof u->host, "%s", tmp);
            u->port = port;
            u->threshold   = cb_threshold > 0 ? cb_threshold : 5;
            u->recovery_ms = cb_recovery_ms > 0 ? cb_recovery_ms : 5000;
            u->hc_interval_ms = 2000;
            snprintf(u->hc_path, sizeof u->hc_path, "/healthz");
            atomic_init(&u->state, CB_CLOSED);
            atomic_init(&u->failures, 0);
            atomic_init(&u->successes, 0);
            atomic_init(&u->opened_at_ms, 0);
            atomic_init(&u->in_flight, 0);
            atomic_init(&u->weight, weight);
            atomic_init(&u->healthy, 1);
            atomic_init(&u->last_hc_ns, 0);
            atomic_init(&u->last_rtt_us, 0);
            s = (*c == ',') ? c+1 : c;
        }
    }
    return 0;
}

static void hc_one(upstream_t *u)
{
    struct addrinfo hints = { .ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM }, *res = NULL;
    char ps[16]; snprintf(ps, sizeof ps, "%u", u->port);
    int64_t t0 = now_ms();
    if (getaddrinfo(u->host, ps, &hints, &res) != 0 || !res) {
        atomic_store(&u->healthy, 0); return;
    }
    int fd = socket(res->ai_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) { freeaddrinfo(res); atomic_store(&u->healthy, 0); return; }
    int rc = connect(fd, res->ai_addr, res->ai_addrlen); (void)rc;
    struct pollfd pf = { .fd = fd, .events = POLLOUT };
    bool ok = false;
    if (poll(&pf, 1, 1000) > 0) {
        int err = 0; socklen_t el = sizeof err;
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el);
        if (!err) {
            salukid_set_nonblock(fd);
            char req[512];
            int n = snprintf(req, sizeof req,
                "GET %s HTTP/1.0\r\nHost: %s:%u\r\nConnection: close\r\nUser-Agent: salukid-hc/1.0\r\n\r\n",
                u->hc_path, u->host, u->port);
            (void)!write(fd, req, (size_t)n);
            struct pollfd pr = { .fd = fd, .events = POLLIN };
            if (poll(&pr, 1, 1000) > 0) {
                char rb[128]; ssize_t rd = read(fd, rb, sizeof rb - 1);
                if (rd >= 12 && rb[9] >= '1' && rb[9] <= '3') ok = true;
            }
        }
    }
    close(fd); freeaddrinfo(res);
    int64_t rtt = now_ms() - t0;
    atomic_store(&u->last_rtt_us, (long)(rtt * 1000));
    atomic_store(&u->healthy, ok ? 1 : 0);
    atomic_store(&u->last_hc_ns, now_ms());
}

static void *hc_thread(void *arg)
{
    proxy_t *p = (proxy_t*)arg;
    while (!atomic_load(&p->hc_stop)) {
        pthread_mutex_lock(&p->mtx);
        size_t n = p->nups;
        for (size_t i = 0; i < n; i++) hc_one(&p->ups[i]);
        pthread_mutex_unlock(&p->mtx);
        /* Sleep in small chunks so we respond to stop quickly */
        for (int i = 0; i < 20 && !atomic_load(&p->hc_stop); i++) usleep(100*1000);
    }
    return NULL;
}

int proxy_start_hc(proxy_t *p)
{
    atomic_store(&p->hc_stop, 0);
    return pthread_create(&p->hc_thread, NULL, hc_thread, p) == 0 ? 0 : -1;
}
void proxy_stop_hc(proxy_t *p)
{
    atomic_store(&p->hc_stop, 1);
    pthread_join(p->hc_thread, NULL);
}

int proxy_set_lb(proxy_t *p, lb_algo_t algo, const char *cookie)
{
    p->algo = algo;
    if (cookie && cookie[0])
        snprintf(p->sticky_cookie, sizeof p->sticky_cookie, "%s", cookie);
    return 0;
}

int proxy_reconfigure(proxy_t *p, const char *spec)
{
    upstream_t *nups = calloc(p->cap < 16 ? 16 : p->cap, sizeof *nups);
    if (!nups) return -1;
    size_t n = 0;
    const char *s = spec;
    while (*s && n < p->cap) {
        const char *c = strchrnul(s, ',');
        size_t L = (size_t)(c - s);
        char tmp[256];
        if (L >= sizeof tmp) { free(nups); return -1; }
        memcpy(tmp, s, L); tmp[L] = '\0';
        char *col1 = strchr(tmp, ':');
        char *col2 = col1 ? strchr(col1+1, ':') : NULL;
        uint16_t port = 80; int weight = 1;
        if (col1) {
            *col1 = '\0';
            port = (uint16_t)atoi(col1+1);
            if (col2) { *col2 = '\0'; weight = atoi(col2+1); if (weight<1) weight=1; }
        }
        upstream_t *u = &nups[n++];
        memset(u, 0, sizeof *u);
        snprintf(u->host, sizeof u->host, "%s", tmp);
        u->port = port;
        u->threshold = 5; u->recovery_ms = 5000; u->hc_interval_ms = 2000;
        snprintf(u->hc_path, sizeof u->hc_path, "/healthz");
        atomic_init(&u->state, CB_CLOSED);
        atomic_init(&u->failures, 0); atomic_init(&u->successes, 0);
        atomic_init(&u->opened_at_ms, 0); atomic_init(&u->in_flight, 0);
        atomic_init(&u->weight, weight); atomic_init(&u->healthy, 1);
        atomic_init(&u->last_hc_ns, 0); atomic_init(&u->last_rtt_us, 0);
        s = (*c == ',') ? c+1 : c;
    }
    pthread_mutex_lock(&p->mtx);
    free(p->ups);
    p->ups = nups;
    p->nups = n;
    atomic_fetch_add(&p->reconfig_gen, 1);
    pthread_mutex_unlock(&p->mtx);
    return 0;
}

void proxy_destroy(proxy_t *p)
{
    proxy_stop_hc(p);
    pthread_mutex_destroy(&p->mtx);
    free(p->ups);
    p->ups = NULL; p->nups = 0;
}

static upstream_t *pick_upstream(proxy_t *p, const char *peer_ip, const char *cookie)
{
    pthread_mutex_lock(&p->mtx);
    size_t n = p->nups;
    if (n == 0) { pthread_mutex_unlock(&p->mtx); return NULL; }

    /* Build candidate list of healthy + CB_CLOSED/HALF_OPEN */
    upstream_t *cands[64]; size_t nc = 0;
    int total_weight = 0;
    for (size_t i = 0; i < n && nc < 64; i++) {
        upstream_t *u = &p->ups[i];
        if (!atomic_load(&u->healthy)) continue;
        int st = atomic_load(&u->state);
        if (st == CB_OPEN) {
            if (now_ms() - atomic_load(&u->opened_at_ms) > u->recovery_ms) {
                atomic_store(&u->state, CB_HALF_OPEN);
                cands[nc++] = u; total_weight += atomic_load(&u->weight);
                continue;
            }
            continue;
        }
        cands[nc++] = u;
        total_weight += atomic_load(&u->weight);
    }
    if (nc == 0) { pthread_mutex_unlock(&p->mtx); return NULL; }

    upstream_t *chosen = NULL;
    switch (p->algo) {
    case LB_LEASTCONN: {
        int best = INT_MAX;
        for (size_t i = 0; i < nc; i++) {
            int ic = atomic_load(&cands[i]->in_flight);
            if (ic < best) { best = ic; chosen = cands[i]; }
        }
        break;
    }
    case LB_STICKY_COOKIE: {
        /* Look for sticky cookie value "salid=<hash>"; if present, route
         * to upstream index hash%nups. Only honor sticky if target is healthy. */
        if (cookie && cookie[0]) {
            const char *k = strstr(cookie, p->sticky_cookie);
            if (k) {
                k += strlen(p->sticky_cookie);
                if (*k == '=') {
                    k++;
                    const char *e = strchrnul(k, ';');
                    uint64_t h = fnv1a(k, (size_t)(e - k));
                    size_t idx = h % nc;
                    chosen = cands[idx];
                }
            }
        }
        if (!chosen) goto rr_fallback;
        break;
    }
    case LB_STICKY_IP: {
        if (peer_ip && peer_ip[0]) {
            uint64_t h = fnv1a(peer_ip, strlen(peer_ip));
            chosen = cands[h % nc];
        } else goto rr_fallback;
        break;
    }
    case LB_RR:
    default:
    rr_fallback: {
        /* Weighted RR: atomic increment modulo total_weight, walk candidates */
        if (total_weight <= 0) total_weight = (int)nc;
        size_t pos = (size_t)atomic_fetch_add(&p->rr_idx, 1) % (size_t)total_weight;
        for (size_t i = 0; i < nc; i++) {
            int w = atomic_load(&cands[i]->weight);
            if (pos < (size_t)w) { chosen = cands[i]; break; }
            pos -= (size_t)w;
        }
        if (!chosen) chosen = cands[0];
        break;
    }
    }
    atomic_fetch_add(&chosen->in_flight, 1);
    pthread_mutex_unlock(&p->mtx);
    return chosen;
}

static void on_success(upstream_t *u)
{
    atomic_fetch_sub(&u->in_flight, 1);
    atomic_store(&u->failures, 0);
    atomic_store(&u->successes, atomic_load(&u->successes)+1);
    if (atomic_load(&u->state) == CB_HALF_OPEN)
        atomic_store(&u->state, CB_CLOSED);
}

static void on_failure(upstream_t *u)
{
    atomic_fetch_sub(&u->in_flight, 1);
    int f = atomic_fetch_add(&u->failures, 1) + 1;
    if (f >= u->threshold && atomic_load(&u->state) != CB_OPEN) {
        atomic_store(&u->state, CB_OPEN);
        atomic_store(&u->opened_at_ms, now_ms());
        if (g_metrics) g_metrics->cb_trips++;
    }
}

int proxy_do(proxy_t *p, arena_t *a, const char *path,
             const char *peer_ip, const char *cookie,
             char **body_out, size_t *bodylen_out,
             char ct[static 64], uint16_t *status_out)
{
    upstream_t *u = pick_upstream(p, peer_ip, cookie);
    if (!u) { *status_out = HTTP_503; return HTTP_503; }
    if (atomic_load(&u->state) == CB_OPEN) {
        atomic_fetch_sub(&u->in_flight, 1);
        *status_out = HTTP_503; return HTTP_503;
    }

    struct addrinfo hints = { .ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM }, *res = NULL;
    char ps[16]; snprintf(ps, sizeof ps, "%u", u->port);
    int gai = getaddrinfo(u->host, ps, &hints, &res);
    if (gai != 0 || !res) { on_failure(u); *status_out = HTTP_502; return HTTP_502; }

    int fd = socket(res->ai_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) { freeaddrinfo(res); on_failure(u); *status_out = HTTP_502; return HTTP_502; }
    int rc = connect(fd, res->ai_addr, res->ai_addrlen); (void)rc;
    struct pollfd pf = { .fd = fd, .events = POLLOUT };
    if (poll(&pf, 1, 2000) <= 0) { close(fd); freeaddrinfo(res); on_failure(u); *status_out = HTTP_504; return HTTP_504; }
    int err = 0; socklen_t el = sizeof err;
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el);
    if (err) { close(fd); freeaddrinfo(res); on_failure(u); *status_out = HTTP_502; return HTTP_502; }
    salukid_set_nonblock(fd);

    char req[2048];
    int n = snprintf(req, sizeof req,
        "GET %s HTTP/1.1\r\nHost: %s:%u\r\nConnection: close\r\nAccept: */*\r\nUser-Agent: %s\r\n\r\n",
        path, u->host, u->port, SALUKID_SERVER_NAME);
    ssize_t wr = write(fd, req, (size_t)n); (void)wr;

    size_t cap = 16384, len = 0;
    char *buf = arena_alloc(a, cap);
    if (!buf) { close(fd); freeaddrinfo(res); on_failure(u); *status_out = HTTP_502; return HTTP_502; }
    int status = HTTP_502;
    for (;;) {
        if (len >= cap - 1) break;
        ssize_t rd = read(fd, buf + len, cap - len - 1);
        if (rd > 0) len += (size_t)rd;
        else if (rd == 0) break;
        else if (errno == EAGAIN || errno == EWOULDBLOCK) {
            struct pollfd pfr = { .fd = fd, .events = POLLIN };
            if (poll(&pfr, 1, 2000) <= 0) break;
            continue;
        }
        else break;
    }
    close(fd); freeaddrinfo(res);
    if (len == 0) { on_failure(u); *status_out = HTTP_502; return HTTP_502; }
    buf[len] = '\0';

    char *eoh = strstr(buf, "\r\n\r\n");
    if (eoh) {
        if (len > 12 && !memcmp(buf, "HTTP/1.", 7) && isdigit((unsigned char)buf[9]))
            status = (buf[9]-'0')*100 + (buf[10]-'0')*10 + (buf[11]-'0');
        *eoh = '\0';
        char *ctp = strcasestr(buf, "content-type:");
        if (ctp) {
            ctp += 13; while (*ctp == ' ') ctp++;
            char *crlf = strstr(ctp, "\r\n");
            if (crlf) { size_t L = MIN((size_t)(crlf - ctp), (size_t)63); memcpy(ct, ctp, L); ct[L]='\0'; }
        }
        *eoh = '\r';
        char *body = eoh + 4;
        size_t blen = len - (size_t)(body - buf);
        char *out = arena_alloc(a, blen + 1);
        if (out) { memcpy(out, body, blen); out[blen] = '\0'; *body_out = out; *bodylen_out = blen; }
    }
    if (status >= 500) on_failure(u);
    else if (status > 0) on_success(u);
    if (g_metrics) {
        g_metrics->proxy_requests++;
        if (status >= 500) g_metrics->proxy_errors++;
    }
    *status_out = (uint16_t)status;
    return status;
}
