/*
 * util.c - Common helpers: logging, networking, error formatting, signals.
 */
#include "common.h"
#include "log.h"

salukid_config_t g_cfg;
volatile sig_atomic_t g_shutdown;
volatile sig_atomic_t g_reload;
volatile sig_atomic_t g_logrotate;

void SALUKID_NORETURN SALUKID_PRINTF(1,2) salukid_die(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "salukid: FATAL: ");
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
    _exit(1);
}

void SALUKID_PRINTF(2,3) salukid_log(int level, const char *fmt, ...)
{
    static const char *lv[] = {
        [LOG_EMERG]="EMERG",[LOG_ALERT]="ALERT",[LOG_CRIT]="CRIT",
        [LOG_ERR]="ERR",[LOG_WARN]="WARN",[LOG_NOTICE]="NOTICE",
        [LOG_INFO]="INFO",[LOG_DEBUG]="DEBUG"
    };
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm;
    localtime_r(&ts.tv_sec, &tm);
    char tbuf[32];
    snprintf(tbuf, sizeof tbuf, "%04d-%02d-%02dT%02d:%02d:%02d.%03ld",
             tm.tm_year+1900, tm.tm_mon+1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec, ts.tv_nsec/1000000);

    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "%s [%s] ", tbuf,
            level >= 0 && level <= LOG_DEBUG ? lv[level] : "?");
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
}

int salukid_set_nonblock(int fd)
{
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0) return -1;
    return fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

void salukid_set_cloexec(int fd)
{
    int fl = fcntl(fd, F_GETFD, 0);
    if (fl >= 0) fcntl(fd, F_SETFD, fl | FD_CLOEXEC);
}

int salukid_listen_tcp(uint16_t port, bool reuseport)
{
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    if (reuseport)
        setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof one);

    /* TCP_CORK off by default; applied per-response */
    struct sockaddr_in sin = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_ANY),
        .sin_port = htons(port),
    };
    if (bind(fd, (struct sockaddr*)&sin, sizeof sin) < 0) {
        close(fd);
        return -1;
    }
    if (listen(fd, SALUKID_LISTEN_BACKLOG) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

int salukid_drop_privileges(const char *user, const char *chroot_dir)
{
    if (getuid() != 0) return SALUKID_OK;   /* not running as root */
    if (chroot_dir && chroot_dir[0]) {
        if (chroot(chroot_dir) < 0) {
            salukid_log(LOG_ERR, "chroot(%s): %s", chroot_dir, strerror(errno));
            return -1;
        }
        if (chdir("/") < 0) return -1;
    }
    struct passwd *pw = getpwnam(user ? user : SALUKID_DEFAULT_USER);
    if (!pw) { salukid_log(LOG_ERR, "getpwnam(%s): %s", user, strerror(errno)); return -1; }
    if (setgroups(0, NULL) < 0 && errno != EPERM) { /* drop supplementary groups */
        salukid_log(LOG_WARN, "setgroups: %s", strerror(errno));
    }
    if (setgid(pw->pw_gid) < 0) { salukid_log(LOG_ERR, "setgid: %s", strerror(errno)); return -1; }
    if (setuid(pw->pw_uid) < 0) { salukid_log(LOG_ERR, "setuid: %s", strerror(errno)); return -1; }
    /* Ensure we cannot regain */
    if (setuid(0) == 0) { salukid_log(LOG_ERR, "privilege drop failed!"); return -1; }
    return SALUKID_OK;
}

static void sig_handler(int sig)
{
    if (sig == SIGINT || sig == SIGTERM) g_shutdown = 1;
    if (sig == SIGHUP) g_reload = 1;
    if (sig == SIGUSR1) g_logrotate = 1;
    if (sig == SIGPIPE) return;
}

void salukid_install_signals(void)
{
    struct sigaction sa = { .sa_handler = sig_handler, .sa_flags = SA_RESTART };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGHUP,  &sa, NULL);
    sigaction(SIGUSR1, &sa, NULL);
    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, NULL);
}

const char *http_status_text(http_status_t s)
{
    switch (s) {
        case HTTP_200: return "OK";
        case HTTP_206: return "Partial Content";
        case HTTP_301: return "Moved Permanently";
        case HTTP_302: return "Found";
        case HTTP_304: return "Not Modified";
        case HTTP_400: return "Bad Request";
        case HTTP_403: return "Forbidden";
        case HTTP_404: return "Not Found";
        case HTTP_405: return "Method Not Allowed";
        case HTTP_409: return "Conflict";
        case HTTP_413: return "Payload Too Large";
        case HTTP_414: return "URI Too Long";
        case HTTP_416: return "Range Not Satisfiable";
        case HTTP_431: return "Request Header Fields Too Large";
        case HTTP_500: return "Internal Server Error";
        case HTTP_501: return "Not Implemented";
        case HTTP_502: return "Bad Gateway";
        case HTTP_503: return "Service Unavailable";
        case HTTP_504: return "Gateway Timeout";
        default:       return "Unknown";
    }
}

const char *http_method_str(http_method_t m)
{
    switch (m) {
        case HTTP_M_GET:     return "GET";
        case HTTP_M_HEAD:    return "HEAD";
        case HTTP_M_POST:    return "POST";
        case HTTP_M_PUT:     return "PUT";
        case HTTP_M_DELETE:  return "DELETE";
        case HTTP_M_OPTIONS: return "OPTIONS";
        default:             return "UNKNOWN";
    }
}

const char *content_type_for(const char *path, size_t plen)
{
    const char *ext = NULL;
    if (plen == 0) return "application/octet-stream";
    for (size_t i = plen; i > 0; i--) {
        if (path[i-1] == '.') { ext = path + i; break; }
        if (path[i-1] == '/') break;
    }
    if (!ext) return "application/octet-stream";
    if (!strcasecmp(ext, "html") || !strcasecmp(ext, "htm")) return "text/html; charset=utf-8";
    if (!strcasecmp(ext, "css"))   return "text/css; charset=utf-8";
    if (!strcasecmp(ext, "js") || !strcasecmp(ext, "mjs"))  return "application/javascript; charset=utf-8";
    if (!strcasecmp(ext, "json"))  return "application/json; charset=utf-8";
    if (!strcasecmp(ext, "txt"))   return "text/plain; charset=utf-8";
    if (!strcasecmp(ext, "md"))    return "text/markdown; charset=utf-8";
    if (!strcasecmp(ext, "xml"))   return "application/xml";
    if (!strcasecmp(ext, "svg"))   return "image/svg+xml";
    if (!strcasecmp(ext, "png"))   return "image/png";
    if (!strcasecmp(ext, "jpg") || !strcasecmp(ext, "jpeg")) return "image/jpeg";
    if (!strcasecmp(ext, "gif"))   return "image/gif";
    if (!strcasecmp(ext, "webp"))  return "image/webp";
    if (!strcasecmp(ext, "ico"))   return "image/x-icon";
    if (!strcasecmp(ext, "woff2")) return "font/woff2";
    if (!strcasecmp(ext, "woff"))  return "font/woff";
    if (!strcasecmp(ext, "ttf"))   return "font/ttf";
    if (!strcasecmp(ext, "pdf"))   return "application/pdf";
    if (!strcasecmp(ext, "wasm"))  return "application/wasm";
    return "application/octet-stream";
}
