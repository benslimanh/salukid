/*
 * parser.c - Bounded, overflow-safe HTTP/1.x request parser (no strcpy,
 * no sprintf, no sscanf). Parses request line and headers into an
 * http_request_t; body handling is omitted for GET/HEAD/OPTIONS and left
 * to the caller for POST/PUT (we don't do chunked requests in v0.1).
 */
#include "common.h"
#include "parser.h"

static http_method_t parse_method(const char *p, const char *end)
{
    size_t L = (size_t)(end - p);
    switch (L) {
        case 3:
            if (memcmp(p, "GET", 3) == 0) return HTTP_M_GET;
            if (memcmp(p, "PUT", 3) == 0) return HTTP_M_PUT;
            break;
        case 4:
            if (memcmp(p, "HEAD", 4) == 0) return HTTP_M_HEAD;
            if (memcmp(p, "POST", 4) == 0) return HTTP_M_POST;
            break;
        case 5:
            break;
        case 6:
            if (memcmp(p, "DELETE", 6) == 0) return HTTP_M_DELETE;
            break;
        case 7:
            if (memcmp(p, "OPTIONS", 7) == 0) return HTTP_M_OPTIONS;
            break;
    }
    return HTTP_M_UNKNOWN;
}

static http_version_t parse_version(const char *p, const char *end)
{
    size_t L = (size_t)(end - p);
    if (L == 8 && memcmp(p, "HTTP/1.0", 8) == 0) return HTTP_VER_10;
    if (L == 8 && memcmp(p, "HTTP/1.1", 8) == 0) return HTTP_VER_11;
    if (L == 8 && memcmp(p, "HTTP/2.0", 8) == 0) return HTTP_VER_20;
    return HTTP_VER_UNKNOWN;
}

static const char *find_crlf(const char *p, const char *end)
{
    for (const char *c = p; c + 1 < end; c++)
        if (c[0] == '\r' && c[1] == '\n') return c;
    return NULL;
}

void http_request_reset(http_request_t *r)
{
    /* Free body buffer (we used realloc, not arena, for flexibility in
     * chunked decoding), then zero the struct. */
    free(r->body);
    memset(r, 0, sizeof *r);
}

int http_request_parse(http_request_t *req, const char *buf, size_t len,
                       size_t *consumed)
{
    /* Locate end of headers (\r\n\r\n) */
    const char *begin = buf;
    const char *end = buf + len;
    const char *end_of_headers = NULL;
    for (const char *p = buf; p + 3 < end; p++) {
        if (p[0]=='\r' && p[1]=='\n' && p[2]=='\r' && p[3]=='\n') {
            end_of_headers = p + 4;
            break;
        }
    }
    if (!end_of_headers) {
        if (len > SALUKID_MAX_HEADER_SZ) return -1; /* 431 */
        return SALUKID_RC_AGAIN;
    }

    const char *line0_end = find_crlf(begin, end_of_headers);
    if (!line0_end) return -1;

    const char *sp1 = memchr(begin, ' ', (size_t)(line0_end - begin));
    if (!sp1) return -1;
    const char *sp2 = memchr(sp1 + 1, ' ', (size_t)(line0_end - (sp1 + 1)));
    if (!sp2) return -1;

    req->method  = parse_method(begin, sp1);
    if (req->method == HTTP_M_UNKNOWN) {
        /* Do NOT rewrite unknown methods to GET -- that would let
         * unsupported verbs (e.g. FOOBAR /admin) silently acquire GET
         * semantics and bypass any method-based policy. Leave the
         * method as UNKNOWN; the caller is responsible for replying
         * 501 Not Implemented. */
    }

    size_t uri_len = (size_t)(sp2 - (sp1 + 1));
    if (uri_len >= SALUKID_MAX_URI) return -1;
    memcpy(req->uri, sp1 + 1, uri_len);
    req->uri[uri_len] = '\0';
    req->uri_len = uri_len;

    req->version = parse_version(sp2 + 1, line0_end);
    if (req->version == HTTP_VER_UNKNOWN) return -1;

    /* Split path / query */
    const char *q = memchr(req->uri, '?', uri_len);
    if (q) {
        req->path = req->uri;
        req->path_len = (size_t)(q - req->uri);
        req->query = q + 1;
        req->query_len = uri_len - (size_t)(q - req->uri) - 1;
        /* Advance q past '?' so length is correct */
    } else {
        req->path = req->uri;
        req->path_len = uri_len;
        req->query = NULL;
        req->query_len = 0;
    }

    /* Headers */
    const char *p = line0_end + 2;
    req->nheaders = 0;
    while (p < end_of_headers - 2) {
        const char *le = find_crlf(p, end_of_headers);
        if (!le) break;
        if (le == p) { /* empty -> end */
            p = le + 2; break;
        }
        const char *colon = memchr(p, ':', (size_t)(le - p));
        if (!colon) { p = le + 2; continue; }
        const char *vstart = colon + 1;
        while (vstart < le && *vstart == ' ') vstart++;
        const char *vend = le;
        while (vend > vstart && vend[-1] == ' ') vend--;
        if (req->nheaders < SALUKID_MAX_HEADERS) {
            http_header_t *h = &req->headers[req->nheaders++];
            h->name = p; h->name_len = (size_t)(colon - p);
            h->value = vstart; h->value_len = (size_t)(vend - vstart);
            /* Capture a few well-known headers */
            if (h->name_len == 4 && strncasecmp(h->name, "Host", 4) == 0) {
                size_t hl = MIN(h->value_len, sizeof req->host - 1);
                memcpy(req->host, h->value, hl); req->host[hl] = '\0';
            } else if (h->name_len == 10 && strncasecmp(h->name, "Connection", 10) == 0) {
                if (h->value_len >= 5 && strncasecmp(h->value, "close", 5) == 0)
                    req->connection_close = true;
                if (h->value_len >= 7 && strncasecmp(h->value, "Upgrade", 7) == 0)
                    req->upgrade_h2c = true;
            } else if (h->name_len == 13 && strncasecmp(h->name, "If-None-Match", 13) == 0) {
                size_t hl = MIN(h->value_len, sizeof req->if_none_match - 1);
                memcpy(req->if_none_match, h->value, hl);
                req->if_none_match[hl] = '\0';
                req->has_if_none_match = true;
            } else if (h->name_len == 5 && strncasecmp(h->name, "Range", 5) == 0) {
                if (h->value_len > 6 && !memcmp(h->value, "bytes=", 6)) {
                    const char *s = h->value + 6;
                    const char *e = h->value + h->value_len;
                    const char *dash = memchr(s, '-', e - s);
                    if (dash) {
                        char tmp[32];
                        size_t sl = (size_t)(dash - s);
                        if (sl > 0 && sl < sizeof tmp) {
                            memcpy(tmp, s, sl); tmp[sl]='\0';
                            req->range_start = strtoll(tmp, NULL, 10);
                        }
                        const char *vs = dash + 1;
                        size_t rl = (size_t)(e - vs);
                        if (rl > 0 && rl < sizeof tmp) {
                            memcpy(tmp, vs, rl); tmp[rl]='\0';
                            req->range_end = strtoll(tmp, NULL, 10);
                        } else req->range_suffix = true;
                        req->has_range = true;
                    }
                }
            } else if (h->name_len == 15 && strncasecmp(h->name, "Accept-Encoding", 15) == 0) {
                size_t hl = MIN(h->value_len, sizeof req->accept_encoding - 1);
                memcpy(req->accept_encoding, h->value, hl);
                req->accept_encoding[hl] = '\0';
            } else if (h->name_len == 7 && strncasecmp(h->name, "Upgrade", 7) == 0) {
                if (h->value_len == 3 && strncasecmp(h->value, "h2c", 3) == 0)
                    req->upgrade_h2c = true;
            } else if (h->name_len == 14 && strncasecmp(h->name, "Content-Length", 14) == 0) {
                /* Parse Content-Length strictly (digits only, no +/-, no leading WS) */
                if (h->value_len > 0 && h->value_len < 20) {
                    size_t cl = 0; bool ok = true;
                    for (size_t k = 0; k < h->value_len; k++) {
                        char d = h->value[k];
                        if (d < '0' || d > '9') { ok = false; break; }
                        size_t ncl = cl * 10 + (size_t)(d - '0');
                        if (ncl < cl) { ok = false; break; } /* overflow */
                        cl = ncl;
                    }
                    if (ok && cl <= SALUKID_MAX_REQ_BODY) {
                        req->content_length = cl;
                        if (req->body_kind != SALUKID_BODY_CHUNKED)
                            req->body_kind = SALUKID_BODY_CL;
                    }
                }
            } else if (h->name_len == 17 && strncasecmp(h->name, "Transfer-Encoding", 17) == 0) {
                /* Look for "chunked" anywhere in value (case-insensitive) */
                if (h->value_len >= 7) {
                    const char *vv = h->value; size_t vvl = h->value_len;
                    for (size_t k = 0; k + 7 <= vvl; k++) {
                        if (!strncasecmp(vv + k, "chunked", 7)) {
                            req->body_kind = SALUKID_BODY_CHUNKED;
                            req->content_length = 0;
                            req->chunk_state = 0;
                            req->chunk_remaining = 0;
                            break;
                        }
                    }
                }
            } else if (h->name_len == 6 && strncasecmp(h->name, "Expect", 6) == 0) {
                if (h->value_len >= 12 &&
                    !strncasecmp(h->value, "100-continue", 12))
                    req->expect_100 = true;
            }
        }
        p = le + 2;
    }

    /* If chunked, ignore Content-Length per RFC 7230 §3.3.3 */
    if (req->body_kind == SALUKID_BODY_CHUNKED) req->content_length = 0;

    *consumed = (size_t)(end_of_headers - begin);
    return SALUKID_OK;
}

/* Append bytes to request body buffer. Grows with bounded cap. Returns 0
 * on success, -1 if the body would exceed SALUKID_MAX_REQ_BODY. */
int http_request_body_append(http_request_t *req, const char *data, size_t n)
{
    if (!n) return 0;
    if (req->body_len + n > SALUKID_MAX_REQ_BODY) return -1;
    if (req->body_len + n + 1 > req->body_cap) {
        size_t nc = req->body_cap ? req->body_cap : 4096;
        while (nc < req->body_len + n + 1) {
            if (nc > SALUKID_MAX_REQ_BODY) return -1;
            if (nc >= SALUKID_MAX_REQ_BODY / 2) { nc = SALUKID_MAX_REQ_BODY + 1; break; }
            nc *= 2;
        }
        if (nc > SALUKID_MAX_REQ_BODY + 1) return -1;
        /* Use malloc (caller is expected to use c->arena if arena-backed).
         * We actually can't reach into arena from here easily, so use
         * realloc; the arena in conn_t resets per request so we hook
         * freeing via http_request_reset -> free. */
        char *nb = (char*)realloc(req->body, nc);
        if (!nb) return -1;
        req->body = nb;
        req->body_cap = nc;
    }
    memcpy(req->body + req->body_len, data, n);
    req->body_len += n;
    req->body[req->body_len] = '\0';
    return 0;
}

/* Decode chunked Transfer-Encoding from [buf..buf+len). Returns number of
 * bytes consumed, fills *got_body=true when the final 0-chunk arrives,
 * and writes decoded body bytes via http_request_body_append. Returns
 * -1 on protocol error.
 *
 * State machine:
 *   0: reading chunk-size line (hex digits, optional ;ext, terminated by \r\n)
 *   1: reading chunk data (chunk_remaining bytes), followed by \r\n
 *   2: trailers (skip until \r\n with empty line)
 */
int http_request_chunked_feed(http_request_t *req, const char *buf, size_t len,
                              size_t *consumed, bool *done)
{
    *consumed = 0;
    *done = false;
    size_t i = 0;
    while (i < len) {
        if (req->chunk_state == 0) {
            /* find CRLF */
            const char *crlf = (const char*)memmem(buf + i, len - i, "\r\n", 2);
            if (!crlf) { (void)SALUKID_CHUNK_BUF; return 0; } /* need more */
            size_t sl = (size_t)(crlf - (buf + i));
            /* parse hex up to ';' or \r */
            size_t cs = 0; bool ok = true;
            for (size_t k = 0; k < sl; k++) {
                char ch = buf[i + k];
                if (ch == ';') break;
                unsigned v = 0;
                if (ch >= '0' && ch <= '9') v = (unsigned)(ch - '0');
                else if (ch >= 'a' && ch <= 'f') v = (unsigned)(ch - 'a' + 10);
                else if (ch >= 'A' && ch <= 'F') v = (unsigned)(ch - 'A' + 10);
                else if (ch == ' ' || ch == '\t') continue;
                else { ok = false; break; }
                if (cs > (SALUKID_MAX_REQ_BODY >> 4)) { ok = false; break; }
                cs = cs * 16 + v;
                if (cs > SALUKID_MAX_REQ_BODY) { ok = false; break; }
            }
            if (!ok) return -1;
            i = (size_t)(crlf - buf) + 2;
            if (cs == 0) {
                req->chunk_state = 2; /* trailers */
                continue;
            }
            req->chunk_remaining = cs;
            req->chunk_state = 1;
        } else if (req->chunk_state == 1) {
            size_t avail = len - i;
            size_t take = (avail < req->chunk_remaining) ? avail : req->chunk_remaining;
            if (take) {
                if (http_request_body_append(req, buf + i, take) < 0) return -1;
                i += take;
                req->chunk_remaining -= take;
            }
            if (req->chunk_remaining == 0) {
                /* Need trailing \r\n */
                if (len - i < 2) return 0;
                if (buf[i] != '\r' || buf[i+1] != '\n') return -1;
                i += 2;
                req->chunk_state = 0;
            }
        } else if (req->chunk_state == 2) {
            /* Trailers: skip all lines until blank \r\n */
            const char *crlf = (const char*)memmem(buf + i, len - i, "\r\n", 2);
            if (!crlf) return 0;
            if (crlf == buf + i) { i += 2; *consumed = i; *done = true; return 0; }
            i = (size_t)(crlf - buf) + 2;
        }
    }
    *consumed = i;
    return 0;
}
