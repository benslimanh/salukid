/*
 * ringbuf.h - Single-producer single-consumer lock-free byte ring buffer,
 * used to decouple worker threads that produce JSON log lines from the
 * single logging thread that writes to stderr/file. On x86_64 the
 * acquire/release semantics are free via volatile stores; we use
 * __atomic builtins for portability.
 */
#ifndef SALUKID_RINGBUF_H
#define SALUKID_RINGBUF_H

#include "common.h"
#include <stdatomic.h>

typedef struct {
    uint8_t        *buf;
    size_t          cap;    /* power of two */
    atomic_size_t   head;   /* producer */
    atomic_size_t   tail;   /* consumer */
} ringbuf_t;

int  ringbuf_init(ringbuf_t *r, size_t cap);
void ringbuf_destroy(ringbuf_t *r);
size_t ringbuf_write(ringbuf_t *r, const void *src, size_t n);   /* returns bytes written */
size_t ringbuf_read(ringbuf_t *r, void *dst, size_t n);          /* returns bytes read */
bool   ringbuf_empty(ringbuf_t *r);

#endif
