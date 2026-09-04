/*
 * admin.h - Dynamic runtime admin API (no-reload configuration).
 *
 * Exposes JSON endpoints under /_admin/ that allow operators to:
 *   GET  /_admin/config         → current config (upstreams, LB algo, cache)
 *   POST /_admin/upstreams      → replace proxy upstreams (JSON or CSV)
 *   POST /_admin/lb             → set load-balancing algorithm
 *   POST /_admin/cache/purge    → purge full cache
 *   POST /_admin/cache/purge/<key> → purge single entry
 *   GET  /_admin/health         → aggregate upstream health
 *
 * Auth: shared-secret Bearer token via config/env SALUKID_ADMIN_TOKEN
 * (defaults to empty = disabled; production should always set it).
 */
#ifndef SALUKID_ADMIN_H
#define SALUKID_ADMIN_H

#include "common.h"
#include "conn.h"

int  admin_handle_request(conn_t *c, http_request_t *req, http_response_t *resp);
void admin_init(const char *token);

#endif
