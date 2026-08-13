/*
 * cache.c - Bounded hash + LRU response cache. Every put that would
 * exceed max_bytes evicts LRU entries. TTL expiry is checked at get
 * time (lazy eviction). Thread-safe: a single mutex guards the table.
 * The cache is only accessed from short critical sections in the I/O
 * path, so contention is negligible.
 */
#include "cache.h"

static inline size_t hash_key(const char *s)
{
    /* FNV-1a 64 */
    size_t h = 1469598103934665603ULL;
    while (*s) { h ^= (unsigned char)*s++; h *= 1099511628211ULL; }
    return h;
}

static void lru_detach(cache_t *c, cache_entry_t *e)
{
    if (e->lru_prev) e->lru_prev->lru_next = e->lru_next;
    else c->lru_head = e->lru_next;
    if (e->lru_next) e->lru_next->lru_prev = e->lru_prev;
    else c->lru_tail = e->lru_prev;
    e->lru_prev = e->lru_next = NULL;
}
static void lru_push_front(cache_t *c, cache_entry_t *e)
{
    e->lru_prev = NULL;
    e->lru_next = c->lru_head;
    if (c->lru_head) c->lru_head->lru_prev = e;
    c->lru_head = e;
    if (!c->lru_tail) c->lru_tail = e;
}

int cache_init(cache_t *c, size_t max_entries, size_t max_bytes)
{
    c->nbuckets = 4096;
    c->buckets = calloc(c->nbuckets, sizeof(cache_entry_t*));
    if (!c->buckets) return -1;
    c->count = 0; c->total_bytes = 0;
    c->max_entries = max_entries ? max_entries : SALUKID_CACHE_ENTRIES;
    c->max_bytes   = max_bytes    ? max_bytes    : (256u << 20);
    c->lru_head = c->lru_tail = NULL;
    pthread_mutex_init(&c->mtx, NULL);
    return 0;
}

void cache_destroy(cache_t *c)
{
    if (!c) return;
    cache_entry_t *e = c->lru_head;
    while (e) {
        cache_entry_t *n = e->lru_next;
        free(e->body);
        free(e);
        e = n;
    }
    free(c->buckets);
    pthread_mutex_destroy(&c->mtx);
}

static void evict_one(cache_t *c)
{
    cache_entry_t *e = c->lru_tail;
    if (!e) return;
    lru_detach(c, e);
    size_t b = hash_key(e->key) % c->nbuckets;
    cache_entry_t **pp = &c->buckets[b];
    while (*pp && *pp != e) pp = &(*pp)->chain;
    if (*pp) *pp = e->chain;
    c->total_bytes -= e->body_len;
    c->count--;
    free(e->body);
    free(e);
}

const cache_entry_t *cache_get(cache_t *c, const char *key)
{
    pthread_mutex_lock(&c->mtx);
    size_t b = hash_key(key) % c->nbuckets;
    cache_entry_t *e = c->buckets[b];
    time_t now = time(NULL);
    while (e) {
        if (strcmp(e->key, key) == 0) {
            if (now >= e->expires_at) {
                pthread_mutex_unlock(&c->mtx);
                return NULL;
            }
            /* Move to front */
            lru_detach(c, e);
            lru_push_front(c, e);
            pthread_mutex_unlock(&c->mtx);
            return e;
        }
        e = e->chain;
    }
    pthread_mutex_unlock(&c->mtx);
    return NULL;
}

void cache_put(cache_t *c, const char *key, int status, const char *ct,
               const char *etag, bool gzipped,
               const uint8_t *body, size_t blen, uint32_t ttl_sec)
{
    if (blen > SALUKID_CACHE_MAX_BODY) return;
    pthread_mutex_lock(&c->mtx);
    while (c->count >= c->max_entries || c->total_bytes + blen > c->max_bytes) {
        if (!c->lru_tail) break;
        evict_one(c);
    }
    cache_entry_t *e = calloc(1, sizeof *e);
    if (!e) { pthread_mutex_unlock(&c->mtx); return; }
    size_t kl = strlen(key);
    if (kl >= sizeof e->key) { free(e); pthread_mutex_unlock(&c->mtx); return; }
    memcpy(e->key, key, kl); e->key[kl] = '\0';
    e->body = malloc(blen);
    if (!e->body) { free(e); pthread_mutex_unlock(&c->mtx); return; }
    memcpy(e->body, body, blen);
    e->body_len = blen;
    e->status   = status;
    e->gzipped  = gzipped;
    e->expires_at = time(NULL) + ttl_sec;
    snprintf(e->content_type, sizeof e->content_type, "%s", ct ? ct : "");
    snprintf(e->etag, sizeof e->etag, "%s", etag ? etag : "");

    size_t b = hash_key(key) % c->nbuckets;
    e->chain = c->buckets[b];
    c->buckets[b] = e;
    lru_push_front(c, e);
    c->count++;
    c->total_bytes += blen;
    pthread_mutex_unlock(&c->mtx);
}

size_t cache_make_key(char *dst, size_t dstcap, const char *method,
                      const char *path, const char *ae)
{
    return (size_t)snprintf(dst, dstcap, "%s\x1f%s\x1f%s",
                            method ? method : "GET",
                            path   ? path   : "/",
                            ae     ? ae     : "");
}

void cache_purge(cache_t *c)
{
    pthread_mutex_lock(&c->mtx);
    cache_entry_t *e = c->lru_head;
    while (e) {
        cache_entry_t *n = e->lru_next;
        free(e->body); free(e); e = n;
    }
    memset(c->buckets, 0, c->nbuckets * sizeof(cache_entry_t*));
    c->lru_head = c->lru_tail = NULL;
    c->count = c->total_bytes = 0;
    pthread_mutex_unlock(&c->mtx);
}

int cache_purge_key(cache_t *c, const char *key)
{
    pthread_mutex_lock(&c->mtx);
    size_t b = hash_key(key) % c->nbuckets;
    cache_entry_t **pp = &c->buckets[b];
    while (*pp) {
        if (strcmp((*pp)->key, key) == 0) {
            cache_entry_t *d = *pp;
            *pp = d->chain;
            lru_detach(c, d);
            c->total_bytes -= d->body_len;
            c->count--;
            free(d->body); free(d);
            pthread_mutex_unlock(&c->mtx);
            return 1;
        }
        pp = &(*pp)->chain;
    }
    pthread_mutex_unlock(&c->mtx);
    return 0;
}
