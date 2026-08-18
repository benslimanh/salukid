#ifndef SALUKID_PARSER_H
#define SALUKID_PARSER_H
#include "common.h"

int  http_request_parse(http_request_t *req, const char *buf, size_t len, size_t *consumed);
void http_request_reset(http_request_t *r);
int  http_request_body_append(http_request_t *req, const char *data, size_t n);
int  http_request_chunked_feed(http_request_t *req, const char *buf, size_t len,
                               size_t *consumed, bool *done);

#endif
