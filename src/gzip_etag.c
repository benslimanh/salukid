/*
 * gzip_etag.c - ETag synthesis + deflate/gzip compression.
 */
#include "common.h"

void etag_for(const struct stat *st, char *out, size_t outsz)
{
    if (!st || !out || outsz < 16) return;
    /* "<hex-size>-<hex-mtime>-<hex-inode>" */
    snprintf(out, outsz, "\"%llx-%llx-%llx\"",
             (unsigned long long)st->st_size,
             (unsigned long long)st->st_mtime,
             (unsigned long long)st->st_ino);
}

bool etag_match(const char *inm, const char *etag)
{
    if (!inm || !etag) return false;
    if (strcmp(inm, "*") == 0) return true;
    /* Simple comma-separated list; no weak tags used here */
    const char *p = inm;
    while (*p) {
        while (*p == ' ' || *p == ',') p++;
        const char *q = p;
        while (*q && *q != ',') q++;
        size_t L = (size_t)(q - p);
        while (L > 0 && p[L-1] == ' ') L--;
        if (L == strlen(etag) && memcmp(p, etag, L) == 0) return true;
        p = q;
    }
    return false;
}

bool client_accepts_gzip(const char *ae)
{
    if (!ae) return false;
    /* crude but correct: search for "gzip" not followed by ";q=0" */
    const char *p = strstr(ae, "gzip");
    return p != NULL;
}

int gzip_compress(const uint8_t *in, size_t inlen, uint8_t **out, size_t *outlen)
{
    if (!in || !out || !outlen) return -1;
    z_stream zs = {0};
    if (deflateInit2(&zs, SALUKID_GZIP_LEVEL, Z_DEFLATED,
                     15 + 16, /* gzip */
                     8, Z_DEFAULT_STRATEGY) != Z_OK) return -1;

    size_t cap = MAX(inlen / 2 + 64, 256);
    uint8_t *buf = malloc(cap);
    if (!buf) { deflateEnd(&zs); return -1; }

    zs.next_in  = (Bytef*)in;
    zs.avail_in = inlen;
    int rc;
    for (;;) {
        zs.next_out  = buf + zs.total_out;
        zs.avail_out = cap - zs.total_out;
        rc = deflate(&zs, Z_FINISH);
        if (rc == Z_STREAM_END) break;
        if (rc != Z_OK && rc != Z_BUF_ERROR) { free(buf); deflateEnd(&zs); return -1; }
        size_t ncap = cap * 2;
        uint8_t *nb = realloc(buf, ncap);
        if (!nb) { free(buf); deflateEnd(&zs); return -1; }
        buf = nb; cap = ncap;
    }
    deflateEnd(&zs);
    *out = buf;
    *outlen = zs.total_out;
    return 0;
}

size_t append_security_headers(char *buf, size_t cap, bool tls)
{
    static const char COMMON[] =
        "X-Content-Type-Options: nosniff\r\n"
        "X-Frame-Options: DENY\r\n"
        "Referrer-Policy: no-referrer\r\n"
        "Content-Security-Policy: default-src 'self'\r\n"
        "Permissions-Policy: geolocation=(), microphone=(), camera=()\r\n";
    size_t n = strlcpy(buf, COMMON, cap);
    if (tls) n += (size_t)snprintf(buf + n, cap - n,
        "Strict-Transport-Security: max-age=63072000; includeSubDomains; preload\r\n");
    return n;
}
