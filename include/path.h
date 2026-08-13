#ifndef SALUKID_PATH_H
#define SALUKID_PATH_H
#include "common.h"
int safe_resolve_path(const char *root, const char *uri_path, size_t uri_plen,
                      char *out, size_t out_sz, struct stat *st_out, bool *is_dir);
#endif
