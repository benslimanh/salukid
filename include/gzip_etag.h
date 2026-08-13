#ifndef SALUKID_GZIP_ETAG_H
#define SALUKID_GZIP_ETAG_H
#include "common.h"

void etag_for(const struct stat *st, char *out, size_t outsz);
bool etag_match(const char *inm, const char *etag);
bool client_accepts_gzip(const char *ae);
int  gzip_compress(const uint8_t *in, size_t inlen, uint8_t **out, size_t *outlen);
size_t append_security_headers(char *buf, size_t cap, bool tls);

#endif