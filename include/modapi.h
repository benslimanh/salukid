/*
 * modapi.h - Internal glue between core and the stable module ABI.
 *
 * Translates internal conn_t/http_request_t/http_response_t to the
 * stable salukid_req_t / salukid_resp_t opaque handles exposed in
 * salukid_hooks.h. Core code never sees the module vtable directly.
 */
#ifndef SALUKID_MODAPI_H
#define SALUKID_MODAPI_H

#include "common.h"
#include "salukid_hooks.h"

struct conn;

/* Runtime list of loaded modules */
typedef struct salukid_modlist salukid_modlist_t;

int   modapi_load(salukid_modlist_t **ml, const char *path, const char *cfg,
                  size_t cfglen);
int   modapi_reload_all(salukid_modlist_t *ml);
void  modapi_unload_all(salukid_modlist_t *ml);

/* Invoke a phase across all modules until one HANDLED/DENY */
int   modapi_run_request_headers(salukid_modlist_t *ml, struct conn *c);
int   modapi_run_response_headers(salukid_modlist_t *ml, struct conn *c);

/* Shared dictionary (module_get/set/incr) */
int   modapi_shared_init(void);
void  modapi_shared_shutdown(void);
int64_t modapi_shared_incr(const char *scope, const char *k,
                           int64_t delta, int64_t initial, uint32_t ttl_sec);
int   modapi_shared_get(const char *scope, const char *k, char *out, size_t cap);
int   modapi_shared_set(const char *scope, const char *k, const char *v, uint32_t ttl_sec);

#endif
