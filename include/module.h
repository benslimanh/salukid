/*
 * module.h - dlopen-based dynamic module system.
 * A module is a .so that exports salukid_module_init (called once at load)
 * and salukid_module_handle (called per request, may serve or filter).
 */
#ifndef SALUKID_MODULE_H
#define SALUKID_MODULE_H

#include "common.h"

struct conn;
struct http_response;

typedef struct salukid_module {
    void *handle;
    char  name[64];
    int   (*on_request)(void *ctx, struct conn *c, struct http_response *r);
    void *ctx;
    struct salukid_module *next;
} salukid_module_t;

int   module_load(salukid_module_t **list, const char *path);
int   module_invoke(salukid_module_t *list, struct conn *c, struct http_response *r);
void  module_unload_all(salukid_module_t *list);

#endif
