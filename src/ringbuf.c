/*
 * ringbuf.c - SPSC lock-free byte ring buffer.
 */
#include "ringbuf.h"

int ringbuf_init(ringbuf_t *r, size_t cap)
{
    (void)cap;
    size_t c = 1; while (c < (size_t)SALUKID_RING_SZ) c <<= 1;
    r->buf = mmap(NULL, c, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (r->buf == MAP_FAILED) return -1;
    r->cap = c;
    atomic_init(&r->head, 0);
    atomic_init(&r->tail, 0);
    return 0;
}

void ringbuf_destroy(ringbuf_t *r)
{
    if (r->buf) { munmap(r->buf, r->cap); r->buf = NULL; }
    r->cap = 0;
}

static inline size_t _mask(ringbuf_t *r, size_t v) { return v & (r->cap - 1); }

size_t ringbuf_write(ringbuf_t *r, const void *src, size_t n)
{
    size_t h = atomic_load_explicit(&r->head, memory_order_relaxed);
    size_t t = atomic_load_explicit(&r->tail, memory_order_acquire);
    size_t used = h - t;
    size_t free_ = r->cap - used - 1;
    if (n > free_) n = free_;
    if (n == 0) return 0;
    size_t c1 = r->cap - _mask(r, h);
    size_t f = MIN(n, c1);
    memcpy(r->buf + _mask(r, h), src, f);
    if (n > f) memcpy(r->buf, (const char*)src + f, n - f);
    atomic_store_explicit(&r->head, h + n, memory_order_release);
    return n;
}

size_t ringbuf_read(ringbuf_t *r, void *dst, size_t n)
{
    size_t t = atomic_load_explicit(&r->tail, memory_order_relaxed);
    size_t h = atomic_load_explicit(&r->head, memory_order_acquire);
    size_t used = h - t;
    if (n > used) n = used;
    if (n == 0) return 0;
    size_t c1 = r->cap - _mask(r, t);
    size_t f = MIN(n, c1);
    memcpy(dst, r->buf + _mask(r, t), f);
    if (n > f) memcpy((char*)dst + f, r->buf, n - f);
    atomic_store_explicit(&r->tail, t + n, memory_order_release);
    return n;
}

bool ringbuf_empty(ringbuf_t *r)
{
    return atomic_load_explicit(&r->head, memory_order_acquire) ==
           atomic_load_explicit(&r->tail, memory_order_acquire);
}
