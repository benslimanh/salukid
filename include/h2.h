/*
 * h2.h - HTTP/2 (nghttp2) integration.
 */
#ifndef SALUKID_H2_H
#define SALUKID_H2_H

#include "common.h"
#include <nghttp2/nghttp2.h>
#include "conn.h"

int  h2_session_init(conn_t *c);
void h2_session_destroy(conn_t *c);
int  h2_feed(conn_t *c, const uint8_t *data, size_t len);
int  h2_flush(conn_t *c);
int  h2_want_readwrite(conn_t *c, bool *want_read, bool *want_write);

#endif
