/*
 * subrequester.h - Async out-of-process HTTP subrequest pool.
 *
 * Each worker process owns N threads that perform blocking HTTP/1.1 calls
 * and post completion tags back through an eventfd. The main worker epoll
 * watches that fd and drains completions inline, so all per-connection
 * state is touched from one thread and we don't need per-conn locking.
 *
 * Memory model: subrequest_t is heap-allocated (malloc) by the submitter
 * so it outlives the per-request arena. The subrequester takes ownership
 * on submit and frees it after the callback fires OR after the connection
 * is cancelled. Callbacks always run on the main epoll thread.
 */
#ifndef SALUKID_SUBREQUESTER_H
#define SALUKID_SUBREQUESTER_H

#include "common.h"
#include "conn.h"
#include <pthread.h>
#include <sys/eventfd.h>
#include <stdatomic.h>

#define SALUKID_SUBREQ_QUEUE_MAX  1024  /* backpressure: 503 when exceeded */
#define SALUKID_SUBREQ_DEFAULT_MS 5000  /* absolute timeout cap */

typedef struct subreq_kv { const char *name; const char *value; } subreq_kv_t;

typedef void (*subreq_cb_t)(conn_t *c, int status,
                            const subreq_kv_t *hdrs, size_t nhdrs,
                            const uint8_t *body, size_t blen,
                            void *module_ctx, void *tag);

typedef struct subrequest {
    char              method[8];
    char              url[1024];
    const uint8_t    *body;        /* points into caller-owned memory (arena) */
    size_t            body_len;
    const subreq_kv_t *headers;
    size_t            nheaders;
    uint32_t          timeout_ms;
    conn_t           *origin;           /* owning connection; weak ref */
    void             *module_ctx;
    void             *tag;
    subreq_cb_t       cb;
    struct subrequest *next;

    /* Cancellation / lifecycle */
    atomic_bool       cancelled;   /* set by conn_destroy to drop the cb */
    bool              in_pool;     /* currently queued or running in workers */
    bool              heap_headers; /* headers[] is heap-allocated (free on completion) */
    bool              heap_body;    /* body is heap-allocated (free on completion) */

    /* completion filled in by worker thread */
    int               result_status;
    uint8_t          *result_body; /* malloc'd body (freed by drain) */
    size_t            result_body_len;
    uint64_t          deadline_ns; /* CLOCK_MONOTONIC deadline */
} subrequest_t;

typedef struct {
    int              efd;
    int              nthreads;
    pthread_t       *threads;
    pthread_mutex_t  mtx;
    pthread_cond_t   cv;
    subrequest_t    *head;
    subrequest_t    *tail;
    atomic_size_t    queued;      /* in-flight + queued */
    atomic_bool      stop;
} subrequester_t;

extern subrequester_t g_subreq;

int  subrequester_init(int threads_per_worker);
void subrequester_shutdown(void);

/* Submit a heap-allocated subrequest. Ownership transfers:
 *   - returns 0 on success
 *   - returns -1 with errno set if queue is full (caller must free sr) */
int  subrequester_submit(subrequest_t *sr);

/* Drain completions and timeouts; called from the main epoll loop.
 * Also walks all pending subrequests to fire 504 for expired ones. */
void subrequester_drain(subrequester_t *sr);

/* Cancel a pending subrequest (called from conn_destroy). The subrequest
 * will be silently dropped when the worker finishes; no callback fires. */
void subrequester_cancel(subrequest_t *sr);

/* Allocate a subrequest on the heap (the only safe lifetime model). */
subrequest_t *subrequest_new(void);
void          subrequest_free(subrequest_t *sr);

#endif
