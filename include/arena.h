/*
 * arena.h - Bump-pointer arena allocator for per-request lifetimes.
 *
 * Each arena allocates chunks of SALUKID_ARENA_CHUNK and bumps a pointer.
 * No free per-allocation; the entire arena is reset or destroyed at once.
 * This is faster than malloc/free for per-connection request lifetimes
 * and eliminates many classes of leak/UAF in request processing.
 */
#ifndef SALUKID_ARENA_H
#define SALUKID_ARENA_H

#include "common.h"

typedef struct arena_chunk {
    struct arena_chunk *next;
    size_t              used;
    size_t              cap;
    uint8_t             data[];
} arena_chunk_t;

typedef struct {
    arena_chunk_t *first;
    arena_chunk_t *cur;
    size_t         total_allocated;
} arena_t;

void  arena_init(arena_t *a);
void  arena_destroy(arena_t *a);
void  arena_reset(arena_t *a);    /* reuse, don't free chunks */
void *arena_alloc(arena_t *a, size_t sz) SALUKID_MALLOC;
void *arena_calloc(arena_t *a, size_t n, size_t sz) SALUKID_MALLOC;
char *arena_strndup(arena_t *a, const char *s, size_t n);

/* slab allocator for uniform-size objects (connection structs) */
typedef struct slab {
    struct slab     *next;
    size_t           obj_size;
    size_t           n_per_chunk;
    struct slab_obj *free_list;
    size_t           in_use;
} slab_t;

void  slab_init(slab_t *s, size_t obj_size, size_t n_per_chunk);
void  slab_destroy(slab_t *s);
void *slab_alloc(slab_t *s) SALUKID_MALLOC;
void  slab_free(slab_t *s, void *p);

#endif
