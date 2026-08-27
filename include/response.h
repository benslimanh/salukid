/*
 * response.h - Response builder: headers, file body, chunked, range, gzip.
 * Responses are built into a per-connection "write queue" of slices so we
 * can do vectored sendmsg/TCPCORK zero-copy writes from the file cache.
 */
#ifndef SALUKID_RESPONSE_H
#define SALUKID_RESPONSE_H

#include "common.h"
#include "arena.h"

struct conn;

typedef enum {
    SLICE_BUF,        /* inline buffer owned by response */
    SLICE_FILE,       /* fd + offset + length (sendfile / copy_file_range) */
    SLICE_MMAP        /* mmap'd region */
} slice_kind_t;

typedef struct slice {
    slice_kind_t  kind;
    const void   *base;
    size_t        len;
    int           fd;         /* for SLICE_FILE */
    off_t         file_off;
    struct slice *next;
} slice_t;

typedef struct http_response {
    slice_t      *head;
    slice_t      *tail;
    size_t        total_len;    /* body bytes (set before finalize_headers) */
    size_t        write_total;  /* headers+body set after finalize_headers */
    int           status;
    bool          head_only;
    bool          keepalive;
    bool          gzipped;
    char          content_type[64];
    char          etag[32];
    char          content_range[96];  /* "bytes start-end/total" for 206 */
    bool          has_body;
    size_t        header_len;
    arena_t      *arena;
} http_response_t;

void   response_init(http_response_t *r, arena_t *a, bool head_only, bool keepalive);
void   response_set_status(http_response_t *r, http_status_t s);
void   response_set_content_type(http_response_t *r, const char *ct);
void   response_set_etag(http_response_t *r, const char *etag);
/* Append a bytes slice */
int    response_add_buf(http_response_t *r, const void *buf, size_t len);
/* Append a file slice (zero-copy) */
int    response_add_file(http_response_t *r, int fd, off_t off, size_t len);
/* Append a static C string */
int    response_add_cstr(http_response_t *r, const char *s);

/* File serving with path confinement, range, gzip, ETag/304, dir index */
int    response_serve_file(http_response_t *r, const char *fs_path,
                           const struct stat *st, bool is_dir,
                           const http_request_t *req);

/* Serialize status line + headers to a buffer slice - must be called last */
int    response_finalize_headers(http_response_t *r, bool tls);

/* Error pages */
int    response_error(http_response_t *r, http_status_t s, const char *msg);

#endif
