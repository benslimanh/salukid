/*
 * module.c - dlopen dynamic module loading.
 */
#include "module.h"
#include "response.h"
#include <dlfcn.h>

int module_load(salukid_module_t **list, const char *path)
{
    void *h = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (!h) { salukid_log(LOG_ERR, "module: dlopen %s: %s", path, dlerror()); return -1; }
    typedef int  (*mod_init_fn)(void**);
    typedef int  (*mod_req_fn)(void*, struct conn*, struct http_response*);
    typedef const char *(*mod_name_fn)(void);
    mod_init_fn minit = (mod_init_fn)dlsym(h, "salukid_module_init");
    mod_req_fn  mreq  = (mod_req_fn) dlsym(h, "salukid_module_handle");
    mod_name_fn mname = (mod_name_fn)dlsym(h, "salukid_module_name");
    if (!mreq) { dlclose(h); salukid_log(LOG_ERR, "module %s: no handle fn", path); return -1; }
    void *ctx = NULL;
    if (minit && minit(&ctx) != 0) { dlclose(h); return -1; }
    salukid_module_t *m = calloc(1, sizeof *m);
    if (!m) { dlclose(h); return -1; }
    m->handle = h;
    m->on_request = mreq;
    m->ctx = ctx;
    snprintf(m->name, sizeof m->name, "%s", mname ? mname() : path);
    m->next = *list;
    *list = m;
    salukid_log(LOG_INFO, "loaded module %s", m->name);
    return 0;
}

int module_invoke(salukid_module_t *list, struct conn *c, struct http_response *r)
{
    for (salukid_module_t *m = list; m; m = m->next) {
        if (m->on_request(m->ctx, c, r) == 0) return 0; /* handled */
    }
    return -1; /* not handled */
}

void module_unload_all(salukid_module_t *list)
{
    while (list) {
        salukid_module_t *n = list->next;
        typedef void (*mod_fini_fn)(void*);
        mod_fini_fn mf = (mod_fini_fn)dlsym(list->handle, "salukid_module_fini");
        if (mf) mf(list->ctx);
        dlclose(list->handle);
        free(list);
        list = n;
    }
}
