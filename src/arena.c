/*
 * arena.c - Bump-pointer arena + uniform-size slab allocator.
 */
#include "arena.h"

static arena_chunk_t *chunk_new(size_t cap)
{
    arena_chunk_t *c = mmap(NULL, sizeof(*c) + cap, PROT_READ|PROT_WRITE,
                            MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (c == MAP_FAILED) return NULL;
    c->next = NULL; c->used = 0; c->cap = cap;
#ifdef MADV_FREE
    madvise(c, sizeof(*c) + cap, MADV_FREE);
#endif
    return c;
}

void arena_init(arena_t *a)
{
    a->first = a->cur = chunk_new(SALUKID_ARENA_CHUNK);
    a->total_allocated = 0;
}

void arena_destroy(arena_t *a)
{
    arena_chunk_t *c = a->first;
    while (c) {
        arena_chunk_t *n = c->next;
        munmap(c, sizeof(*c) + c->cap);
        c = n;
    }
    a->first = a->cur = NULL;
    a->total_allocated = 0;
}

void arena_reset(arena_t *a)
{
    /* Reuse chunks, just reset 'used' */
    arena_chunk_t *c = a->first;
    while (c) {
        c->used = 0;
        c = c->next;
    }
    a->cur = a->first;
    a->total_allocated = 0;
}

void *arena_alloc(arena_t *a, size_t sz)
{
    sz = ALIGN_UP(sz, 16);
    if (!a->cur) {
        a->first = a->cur = chunk_new(MAX(sz, SALUKID_ARENA_CHUNK));
        if (!a->cur) return NULL;
    }
    if (a->cur->used + sz > a->cur->cap) {
        size_t cap = MAX(sz, SALUKID_ARENA_CHUNK);
        arena_chunk_t *c = chunk_new(cap);
        if (!c) return NULL;
        a->cur->next = c;
        a->cur = c;
    }
    void *p = a->cur->data + a->cur->used;
    a->cur->used += sz;
    a->total_allocated += sz;
    return p;
}

void *arena_calloc(arena_t *a, size_t n, size_t sz)
{
    size_t tot;
    if (__builtin_mul_overflow(n, sz, &tot)) return NULL;
    void *p = arena_alloc(a, tot);
    if (p) memset(p, 0, tot);
    return p;
}

char *arena_strndup(arena_t *a, const char *s, size_t n)
{
    char *p = arena_alloc(a, n + 1);
    if (!p) return NULL;
    memcpy(p, s, n);
    p[n] = '\0';
    return p;
}

/* ---------- Slab (uniform-size objects, LIFO free-list) ---------- */
struct slab_obj { struct slab_obj *next; };

void slab_init(slab_t *s, size_t obj_size, size_t n_per_chunk)
{
    if (obj_size < sizeof(struct slab_obj)) obj_size = sizeof(struct slab_obj);
    obj_size = ALIGN_UP(obj_size, 16);
    s->obj_size    = obj_size;
    s->n_per_chunk = n_per_chunk;
    s->free_list   = NULL;
    s->next        = NULL;
    s->in_use      = 0;
}

static int slab_grow(slab_t *s)
{
    size_t bytes = sizeof(slab_t) + s->obj_size * s->n_per_chunk;
    void *mem = mmap(NULL, bytes, PROT_READ|PROT_WRITE,
                     MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) return -1;
    slab_t *chunk = (slab_t*)mem;
    chunk->obj_size   = s->obj_size;
    chunk->n_per_chunk = s->n_per_chunk;
    chunk->in_use     = 0;
    char *p = (char*)mem + sizeof(slab_t);
    for (size_t i = 0; i < s->n_per_chunk; i++) {
        struct slab_obj *o = (struct slab_obj*)(p + i * s->obj_size);
        o->next = s->free_list;
        s->free_list = o;
    }
    chunk->next = s->next;
    s->next = chunk;
    return 0;
}

void *slab_alloc(slab_t *s)
{
    if (!s->free_list && slab_grow(s) < 0) return NULL;
    struct slab_obj *o = s->free_list;
    s->free_list = o->next;
    s->in_use++;
    return o;
}

void slab_free(slab_t *s, void *p)
{
    if (!p) return;
    struct slab_obj *o = p;
    o->next = s->free_list;
    s->free_list = o;
    s->in_use--;
}

void slab_destroy(slab_t *s)
{
    slab_t *c = s->next;
    while (c) {
        slab_t *n = c->next;
        munmap(c, sizeof(slab_t) + c->obj_size * c->n_per_chunk);
        c = n;
    }
    s->free_list = NULL;
    s->next = NULL;
    s->in_use = 0;
}
