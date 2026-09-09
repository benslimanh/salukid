/*
 * server.c - Entry point for the HTTP/1.1 + HTTP/2 server (./secure_httpd).
 * Parses arguments, initialises subsystems, creates listening sockets,
 * forks worker pool, runs parent until SIGHUP/SIGTERM.
 */
#include "common.h"
#include "tls.h"
#include "arena.h"
#include "cache.h"
#include "metrics.h"
#include "log.h"
#include "module.h"
#include "modapi.h"
#include "proxy.h"
#include "ringbuf.h"
#include "conn.h"
#include "admin.h"
#include <syslog.h>

extern volatile sig_atomic_t g_logrotate;

slab_t            g_conn_slab;
cache_t           g_cache;
proxy_t           g_proxy;
ringbuf_t         g_log_ring;
salukid_module_t *g_modules = NULL;
salukid_modlist_t*g_modlist = NULL;
int               g_lsock_http = -1;
int               g_lsock_https = -1;

extern void worker_fn(int wid, int fd_http, int fd_https);

static void usage(const char *argv0)
{
    fprintf(stderr,
        "Usage: %s [options]\n"
        "  -p <port>       HTTP port (default 8080)\n"
        "  -T <port>       HTTPS port (default 8443, disabled if 0)\n"
        "  -C <cert>       TLS cert file (PEM)\n"
        "  -K <key>        TLS key file (PEM)\n"
        "  -3              TLS 1.3-only (reject TLS 1.2)\n"
        "  -o <ciphers>    TLS cipher list override\n"
        "  -r <dir>        Document root (default ./www)\n"
        "  -u <user>       unprivileged user (default nobody)\n"
        "  -w <n>          worker count (0 = cpu count)\n"
        "  -c              disable TCP_CORK\n"
        "  -m <module.so>  load legacy dlopen module (repeatable)\n"
        "  -M <mod.so[:cfg]> load v1 stable-ABI module (repeatable)\n"
        "  -P <upstreams>  enable reverse proxy with comma-sep upstreams\n"
        "  -l <path>       log file path (for logrotate; SIGUSR1 reopens)\n"
        "  -S              log to syslog (LOG_DAEMON) in addition to stderr/file\n"
        "  -Z              disable gzip\n"
        "  -j              JSON log format\n"
        "  -d              daemonise\n"
        "  -A <token>      admin bearer token (/_admin/*)\n"
        "  -h              this help\n",
        argv0);
}

static salukid_config_t defaults(void)
{
    salukid_config_t c = {
        .http_port    = 8080,
        .https_port   = 8443,
        .www_dir      = SALUKID_DEFAULT_WWW_DIR,
        .user         = SALUKID_DEFAULT_USER,
        .num_workers  = 0,
        .tcp_cork     = true,
        .gzip         = true,
        .enable_cache = true,
        .enable_metrics = true,
        .cb_threshold = 5,
        .cb_recovery_ms = 5000,
        .cache_max_mb = 256,
        .tls13_only   = false,
        .tls_ciphers  = "",
        .tls_ciphersuites = "",
        .log_path     = "",
        .log_syslog   = false,
    };
    return c;
}

int main(int argc, char **argv)
{
    g_cfg = defaults();
    int opt;
    while ((opt = getopt(argc, argv, "p:T:C:K:r:u:w:m:M:P:l:S3o:ZcjhdA:")) != -1) {
        switch (opt) {
            case 'p': g_cfg.http_port  = (uint16_t)atoi(optarg); break;
            case 'T': g_cfg.https_port = (uint16_t)atoi(optarg); break;
            case 'C': snprintf(g_cfg.cert_path, sizeof g_cfg.cert_path, "%s", optarg); break;
            case 'K': snprintf(g_cfg.key_path,  sizeof g_cfg.key_path,  "%s", optarg); break;
            case 'r': snprintf(g_cfg.www_dir,   sizeof g_cfg.www_dir,   "%s", optarg); break;
            case 'u': snprintf(g_cfg.user,      sizeof g_cfg.user,      "%s", optarg); break;
            case 'w': g_cfg.num_workers = atoi(optarg); break;
            case 'c': g_cfg.tcp_cork = false; break;
            case 'Z': g_cfg.gzip = false; break;
            case 'j': log_set_json(true); break;
            case 'd': g_cfg.daemonize = true; break;
            case 'm':
                if (g_cfg.nmodules < 16)
                    snprintf(g_cfg.modules[g_cfg.nmodules++],
                             SALUKID_PATH_MAX, "%s", optarg);
                break;
            case 'M':
                if (g_cfg.nv1modules < 16) {
                    char *colon = strchr(optarg, ':');
                    if (colon) {
                        size_t pl = (size_t)(colon - optarg);
                        snprintf(g_cfg.v1modules[g_cfg.nv1modules], SALUKID_PATH_MAX,
                                 "%.*s", (int)pl, optarg);
                        snprintf(g_cfg.v1modcfg[g_cfg.nv1modules],
                                 sizeof g_cfg.v1modcfg[0], "%s", colon+1);
                    } else {
                        snprintf(g_cfg.v1modules[g_cfg.nv1modules], SALUKID_PATH_MAX, "%s", optarg);
                        g_cfg.v1modcfg[g_cfg.nv1modules][0] = '\0';
                    }
                    g_cfg.nv1modules++;
                }
                break;
            case 'P':
                g_cfg.enable_proxy = true;
                snprintf(g_cfg.proxy_upstream, sizeof g_cfg.proxy_upstream, "%s", optarg);
                break;
            case 'A':
                snprintf(g_cfg.admin_token, sizeof g_cfg.admin_token, "%s", optarg);
                break;
            case 'l':
                snprintf(g_cfg.log_path, sizeof g_cfg.log_path, "%s", optarg);
                break;
            case 'S':
                g_cfg.log_syslog = true;
                break;
            case '3':
                g_cfg.tls13_only = true;
                break;
            case 'o':
                snprintf(g_cfg.tls_ciphers, sizeof g_cfg.tls_ciphers, "%s", optarg);
                break;
            default: usage(argv[0]); return 1;
        }
    }

    salukid_install_signals();

    if (g_cfg.daemonize && daemon(1, 0) < 0) salukid_die("daemon: %s", strerror(errno));

    if (metrics_init() < 0) salukid_die("metrics init failed");
    if (ringbuf_init(&g_log_ring, SALUKID_RING_SZ) < 0) salukid_die("ring init failed");

    /* Configure logging backends */
    if (g_cfg.log_syslog) {
        log_set_syslog("salukid", LOG_DAEMON);
    }
    if (g_cfg.log_path[0]) {
        log_set_file(g_cfg.log_path);
    }
    log_init_async(-1, &g_log_ring);

    if (slab_init(&g_conn_slab, sizeof(conn_t), 128), 0) {}
    /* slab_init returns void; keep call for side-effect */
    slab_init(&g_conn_slab, sizeof(conn_t), 128);

    if (g_cfg.enable_cache &&
        cache_init(&g_cache, SALUKID_CACHE_ENTRIES, g_cfg.cache_max_mb << 20) < 0)
        salukid_die("cache init failed");

    if (g_cfg.enable_proxy &&
        proxy_init(&g_proxy, g_cfg.proxy_upstream, g_cfg.cb_threshold,
                   g_cfg.cb_recovery_ms) < 0)
        salukid_die("proxy init failed");
    if (g_cfg.enable_proxy) proxy_start_hc(&g_proxy);

    admin_init(g_cfg.admin_token[0] ? g_cfg.admin_token : getenv("SALUKID_ADMIN_TOKEN"));

    modapi_shared_init();

    for (int i = 0; i < g_cfg.nmodules; i++) {
        if (module_load(&g_modules, g_cfg.modules[i]) < 0)
            salukid_die("cannot load legacy module %s", g_cfg.modules[i]);
    }
    for (int i = 0; i < g_cfg.nv1modules; i++) {
        if (modapi_load(&g_modlist, g_cfg.v1modules[i],
                        g_cfg.v1modcfg[i], strlen(g_cfg.v1modcfg[i])) < 0)
            salukid_die("cannot load v1 module %s", g_cfg.v1modules[i]);
    }

    if (g_cfg.https_port > 0) {
        if (!g_cfg.cert_path[0] || !g_cfg.key_path[0])
            salukid_die("HTTPS enabled but -C/-K not provided");
        if (tls_init(g_cfg.cert_path, g_cfg.key_path, g_cfg.tls13_only,
                     g_cfg.tls_ciphers[0] ? g_cfg.tls_ciphers : NULL,
                     g_cfg.tls_ciphersuites[0] ? g_cfg.tls_ciphersuites : NULL) < 0)
            salukid_die("TLS init failed");
    }

    /* Listen sockets (one per worker, via SO_REUSEPORT) */
    int nw = g_cfg.num_workers > 0 ? g_cfg.num_workers : (int)sysconf(_SC_NPROCESSORS_ONLN);
    if (nw < 1) nw = 1;
    if (nw > 256) nw = 256;

    /* Drop privileges before listen? Drop *after* bind when port < 1024.
     * We do it before accept in worker children. */
    int ls_http[256], ls_https[256];
    for (int i = 0; i < nw; i++) {
        ls_http[i] = salukid_listen_tcp(g_cfg.http_port, true);
        if (ls_http[i] < 0) salukid_die("listen http: %s", strerror(errno));
        if (g_cfg.https_port > 0) {
            ls_https[i] = salukid_listen_tcp(g_cfg.https_port, true);
            if (ls_https[i] < 0) salukid_die("listen https: %s", strerror(errno));
        } else ls_https[i] = -1;
    }

    salukid_log(LOG_NOTICE, "%s starting (v%s) http=%u https=%u workers=%d root=%s",
                SALUKID_SERVER_NAME, SALUKID_VERSION,
                g_cfg.http_port, g_cfg.https_port, nw, g_cfg.www_dir);

    salukid_drop_privileges(g_cfg.user, g_cfg.chroot_dir[0] ? g_cfg.chroot_dir : NULL);

    /* Prefork workers */
    pid_t children[256];
    int nchildren = 0;
    for (int i = 0; i < nw; i++) {
        pid_t pid = fork();
        if (pid == 0) {
            /* Detach children into their own process group so the parent's
             * signalling never accidentally reaches unrelated processes
             * that share the parent's group (e.g. a shell wrapper). */
            setpgid(0, 0);
            /* child: close all other workers' sockets */
            for (int j = 0; j < nw; j++) {
                if (j != i) { close(ls_http[j]); if (ls_https[j] >= 0) close(ls_https[j]); }
            }
            g_lsock_http = ls_http[i];
            g_lsock_https = ls_https[i];
            worker_fn(i, g_lsock_http, g_lsock_https);
            _exit(0);
        } else if (pid < 0) salukid_die("fork: %s", strerror(errno));
        else children[nchildren++] = pid;
    }
    /* parent: close listener fds, supervise */
    for (int i = 0; i < nw; i++) { close(ls_http[i]); if (ls_https[i] >= 0) close(ls_https[i]); }

    while (!g_shutdown) {
        if (g_reload) {
            g_reload = 0;
            salukid_log(LOG_NOTICE, "parent received SIGHUP; signalling workers");
            for (int i = 0; i < nchildren; i++) {
                if (children[i] > 0) kill(children[i], SIGHUP);
            }
        }
        if (g_logrotate) {
            g_logrotate = 0;
            salukid_log(LOG_NOTICE, "received SIGUSR1; reopening log file");
            if (g_cfg.log_path[0]) log_set_file(g_cfg.log_path);
            for (int i = 0; i < nchildren; i++) {
                if (children[i] > 0) kill(children[i], SIGUSR1);
            }
        }
        int st; pid_t p = waitpid(-1, &st, WNOHANG);
        if (p > 0) {
            /* Find the slot that exited and respawn it. We re-use the
             * listener fds we created at startup? Those were closed by
             * the parent earlier (we close ls_http[i] after fork). We
             * instead keep an extra set of listener fds open for respawn
             * by not closing them - the simpler approach: keep one
             * listener fd per worker indexed in ls_http/ls_https arrays
             * that we retain across the lifetime of the parent.
             *
             * Easiest correct fix: re-bind a fresh listener on the same
             * port (SO_REUSEPORT will distribute load across it). */
            int slot = -1;
            for (int i = 0; i < nchildren; i++) if (children[i] == p) { slot = i; break; }
            if (slot >= 0 && !g_shutdown) {
                salukid_log(LOG_WARN, "worker pid=%d exited unexpectedly; respawning", (int)p);
                int lh = salukid_listen_tcp(g_cfg.http_port, true);
                int lhttps = -1;
                if (g_cfg.https_port > 0)
                    lhttps = salukid_listen_tcp(g_cfg.https_port, true);
                pid_t np = fork();
                if (np == 0) {
                    g_lsock_http = lh;
                    g_lsock_https = lhttps;
                    worker_fn(slot, lh, lhttps);
                    _exit(0);
                } else if (np > 0) {
                    children[slot] = np;
                } else {
                    salukid_log(LOG_ERR, "respawn fork: %s", strerror(errno));
                    if (lh >= 0) close(lh);
                    if (lhttps >= 0) close(lhttps);
                }
            }
        }
        sleep(1);
    }
    /* Terminate direct children only */
    for (int i = 0; i < nchildren; i++) {
        if (children[i] > 0) kill(children[i], SIGTERM);
    }
    for (int i = 0; i < nchildren; i++) {
        if (children[i] > 0) waitpid(children[i], NULL, 0);
    }
    salukid_log(LOG_NOTICE, "shutting down");

    module_unload_all(g_modules);
    modapi_unload_all(g_modlist);
    modapi_shared_shutdown();
    if (g_cfg.enable_cache) cache_destroy(&g_cache);
    if (g_cfg.enable_proxy) proxy_destroy(&g_proxy);
    if (g_cfg.https_port) tls_shutdown();
    ringbuf_destroy(&g_log_ring);
    slab_destroy(&g_conn_slab);
    metrics_shutdown();
    return 0;
}
