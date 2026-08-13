/*
 * cache.h - Bounded LRU response cache with TTL.
 * Keyed by (method, path, accept-encoding). Values carry a body pointer
 * that the cache owns; entries evict on capacity pressure or TTL expiry.
 */
#ifndef SALUKID_CACHE_H
#define SALUKID_CACHE_H

#include "common.h"

typedef struct cache_entry {
    char            key[SALUKID_MAX_URI + 64];
    uint8_t        *body;
    size_t          body_len;
    char            content_type[64];
    char            etag[32];
    bool            gzipped;
    int             status;
    time_t          expires_at;
    struct cache_entry *chain;    /* hash bucket chain */
    struct cache_entry *lru_prev;
    struct cache_entry *lru_next;
} cache_entry_t;

typedef struct {
    cache_entry_t **buckets;
    size_t          nbuckets;
    size_t          count;
    size_t          max_entries;
    size_t          max_bytes;
    size_t          total_bytes;
    cache_entry_t  *lru_head;
    cache_entry_t  *lru_tail;
    pthread_mutex_t mtx;
} cache_t;

int   cache_init(cache_t *c, size_t max_entries, size_t max_bytes);
void  cache_destroy(cache_t *c);
/* Returns cached body pointer (do not free; valid until evict) */
const cache_entry_t *cache_get(cache_t *c, const char *key);
void  cache_put(cache_t *c, const char *key, int status, const char *ct,
                const char *etag, bool gzipped,
                const uint8_t *body, size_t blen, uint32_t ttl_sec);
void  cache_purge(cache_t *c);
int   cache_purge_key(cache_t *c, const char *key);

/* helpers to build a key */
size_t cache_make_key(char *dst, size_t dstcap, const char *method,
                      const char *path, const char *ae);

#endif
