/*
 * proxy.h - Reverse proxy with advanced load balancing (weighted RR,
 * least-connections, sticky-cookie/IP-hash), active health checks,
 * per-upstream circuit breaker, and runtime-reconfigurable upstreams
 * (add/remove via admin API without restart).
 */
#ifndef SALUKID_PROXY_H
#define SALUKID_PROXY_H

#include "common.h"
#include "arena.h"

typedef enum { CB_CLOSED = 0, CB_OPEN, CB_HALF_OPEN } cb_state_t;
typedef enum {
    LB_RR = 0,       /* round-robin (weighted) */
    LB_LEASTCONN,    /* fewest in-flight requests */
    LB_STICKY_COOKIE,/* consistent hash on cookie `salid` */
    LB_STICKY_IP,    /* hash on client IP */
} lb_algo_t;

#include <stdatomic.h>

typedef struct upstream {
    char               host[256];
    uint16_t           port;
    atomic_int         failures;
    atomic_int         successes;
    atomic_int         state;            /* cb_state_t */
    atomic_long        opened_at_ms;
    atomic_int         in_flight;        /* for least-conn */
    atomic_int         weight;           /* default 1 */
    atomic_int         healthy;          /* 1=healthy (active HC) */
    atomic_long        last_hc_ns;
    atomic_long        last_rtt_us;
    int                threshold;
    int                recovery_ms;
    int                hc_interval_ms;
    char               hc_path[128];     /* /healthz by default */
} upstream_t;

typedef struct proxy {
    upstream_t        *ups;
    size_t             nups;
    size_t             cap;
    atomic_size_t      rr_idx;
    lb_algo_t          algo;
    pthread_mutex_t    mtx;   /* protects ups array reallocation */
    pthread_t          hc_thread;
    atomic_int         hc_stop;
    char               sticky_cookie[32];
    atomic_long        reconfig_gen;
} proxy_t;

extern proxy_t g_proxy;

int    proxy_init(proxy_t *p, const char *spec, int cb_threshold, int cb_recovery_ms);
int    proxy_reconfigure(proxy_t *p, const char *spec);   /* admin API */
int    proxy_set_lb(proxy_t *p, lb_algo_t algo, const char *cookie);
void   proxy_destroy(proxy_t *p);

int    proxy_do(proxy_t *p, arena_t *a, const char *path,
                const char *peer_ip, const char *cookie,
                char **body_out, size_t *bodylen_out,
                char content_type[static 64],
                uint16_t *status_out);

/* Start/stop active health-check thread */
int    proxy_start_hc(proxy_t *p);
void   proxy_stop_hc(proxy_t *p);

#endif
