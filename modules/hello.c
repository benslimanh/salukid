/*
 * hello.c - Legacy (pre-v1) sample module. Load with -m modules/hello.so
 * Exposes /_hello returning JSON. For new code use the stable v1 ABI.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "../include/common.h"
#include "../include/response.h"
#include "../include/conn.h"
#include "../include/module.h"

static const char *salukid_module_name(void) { return "hello"; }

static int salukid_module_init(void **ctx) { *ctx = NULL; return 0; }

static int salukid_module_handle(void *ctx, struct conn *c, http_response_t *r)
{
    (void)ctx;
    if (!c || !r) return -1;
    if (c->req.path_len != 7) return -1;
    if (memcmp(c->req.path, "/_hello", 7) != 0) return -1;
    static const char body[] = "{\"module\":\"hello\",\"ok\":true}\n";
    response_set_status(r, HTTP_200);
    response_set_content_type(r, "application/json; charset=utf-8");
    if (!r->head_only) response_add_cstr(r, body);
    r->total_len = sizeof body - 1;
    r->has_body = true;
    return 0;
}

static void salukid_module_fini(void *ctx) { (void)ctx; }
