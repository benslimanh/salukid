/*
 * metrics.c - Prometheus metrics in mmap'd shared memory (so each prefork
 * worker updates the same counters atomically).
 */
#include "metrics.h"
#include "cache.h"
#include "proxy.h"
#include <sys/mman.h>

metrics_t *g_metrics;
extern cache_t g_cache;
extern proxy_t g_proxy;

int metrics_init(void)
{
    g_metrics = mmap(NULL, sizeof(metrics_t),
                     PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
    if (g_metrics == MAP_FAILED) { g_metrics = NULL; return -1; }
    memset(g_metrics, 0, sizeof *g_metrics);
    g_metrics->start_time = time(NULL);
    return 0;
}

void metrics_shutdown(void)
{
    if (g_metrics) { munmap(g_metrics, sizeof(metrics_t)); g_metrics = NULL; }
}

void metrics_incr_request(int status, size_t bytes)
{
    if (!g_metrics) return;
    g_metrics->requests_total++;
    if (status >= 0 && status < 600) g_metrics->requests_by_status[status]++;
    g_metrics->bytes_sent += bytes;
}

void metrics_incr_conn(int delta)
{
    if (!g_metrics) return;
    if (delta > 0) {
        g_metrics->connections_accepted += (uint64_t)delta;
        g_metrics->active_connections  += (uint64_t)delta;
    } else {
        if (g_metrics->active_connections >= (uint64_t)(-delta))
            g_metrics->active_connections -= (uint64_t)(-delta);
    }
}

char *metrics_render_prometheus(size_t *outlen)
{
    if (!g_metrics) { *outlen = 0; return NULL; }
    size_t cap = 8192;
    char *buf = malloc(cap);
    if (!buf) return NULL;
    uint64_t up = time(NULL) - g_metrics->start_time;
    int n = snprintf(buf, cap,
        "# HELP salukid_requests_total Total requests served\n"
        "# TYPE salukid_requests_total counter\n"
        "salukid_requests_total %llu\n"
        "# HELP salukid_bytes_sent Total bytes sent\n"
        "# TYPE salukid_bytes_sent counter\n"
        "salukid_bytes_sent %llu\n"
        "# HELP salukid_connections_accepted Total connections accepted\n"
        "# TYPE salukid_connections_accepted counter\n"
        "salukid_connections_accepted %llu\n"
        "# HELP salukid_active_connections Current active connections\n"
        "# TYPE salukid_active_connections gauge\n"
        "salukid_active_connections %llu\n"
        "# HELP salukid_cache_hits Cache hits\n"
        "# TYPE salukid_cache_hits counter\n"
        "salukid_cache_hits %llu\n"
        "# HELP salukid_cache_misses Cache misses\n"
        "# TYPE salukid_cache_misses counter\n"
        "salukid_cache_misses %llu\n"
        "# HELP salukid_proxy_requests Proxied requests\n"
        "# TYPE salukid_proxy_requests counter\n"
        "salukid_proxy_requests %llu\n"
        "# HELP salukid_proxy_errors Proxy errors\n"
        "# TYPE salukid_proxy_errors counter\n"
        "salukid_proxy_errors %llu\n"
        "# HELP salukid_circuit_breaker_trips Circuit breaker trips\n"
        "# TYPE salukid_circuit_breaker_trips counter\n"
        "salukid_circuit_breaker_trips %llu\n"
        "# HELP salukid_log_drops Log record drops\n"
        "# TYPE salukid_log_drops counter\n"
        "salukid_log_drops %llu\n"
        "# HELP salukid_uptime_seconds Process uptime\n"
        "# TYPE salukid_uptime_seconds counter\n"
        "salukid_uptime_seconds %llu\n"
        "# HELP salukid_cache_entries Current cache entries\n"
        "# TYPE salukid_cache_entries gauge\n"
        "salukid_cache_entries %zu\n"
        "# HELP salukid_cache_bytes Current cached body bytes\n"
        "# TYPE salukid_cache_bytes gauge\n"
        "salukid_cache_bytes %zu\n"
        "# HELP salukid_upstream_count Configured upstream count\n"
        "# TYPE salukid_upstream_count gauge\n"
        "salukid_upstream_count %zu\n",
        (unsigned long long)g_metrics->requests_total,
        (unsigned long long)g_metrics->bytes_sent,
        (unsigned long long)g_metrics->connections_accepted,
        (unsigned long long)g_metrics->active_connections,
        (unsigned long long)g_metrics->cache_hits,
        (unsigned long long)g_metrics->cache_misses,
        (unsigned long long)g_metrics->proxy_requests,
        (unsigned long long)g_metrics->proxy_errors,
        (unsigned long long)g_metrics->cb_trips,
        (unsigned long long)g_metrics->log_drops,
        (unsigned long long)up,
        g_cache.count, g_cache.total_bytes, g_proxy.nups);
    (void)n;
    *outlen = (size_t)n;
    return buf;
}
