/*
 * metrics.h - Prometheus counters/gauges served at /metrics.
 * Stored in a single struct per worker and aggregated via shared memory
 * (or simply per-process counters in prefork model + mmap aggregate).
 */
#ifndef SALUKID_METRICS_H
#define SALUKID_METRICS_H

#include "common.h"
#include <stdatomic.h>

typedef struct {
    atomic_uint_fast64_t requests_total;
    atomic_uint_fast64_t requests_by_status[600];
    atomic_uint_fast64_t bytes_sent;
    atomic_uint_fast64_t bytes_recv;
    atomic_uint_fast64_t connections_accepted;
    atomic_uint_fast64_t connections_active;
    atomic_uint_fast64_t cache_hits;
    atomic_uint_fast64_t cache_misses;
    atomic_uint_fast64_t proxy_requests;
    atomic_uint_fast64_t proxy_errors;
    atomic_uint_fast64_t cb_trips;
    atomic_uint_fast64_t log_drops;
    atomic_uint_fast64_t active_connections;
    atomic_uint_fast64_t uptime_seconds;
    atomic_uint_fast64_t start_time;
} metrics_t;

extern metrics_t *g_metrics;    /* mmap'd shared across workers */

int   metrics_init(void);
void  metrics_shutdown(void);
void  metrics_incr_request(int status, size_t bytes);
void  metrics_incr_conn(int delta);
char *metrics_render_prometheus(size_t *outlen);   /* arena-friendly */

#endif
