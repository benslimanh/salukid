/*
 * tls.h - mbedTLS initialisation and ALPN negotiation helpers.
 */
#ifndef SALUKID_TLS_H
#define SALUKID_TLS_H

#include "common.h"
#include "conn.h"

extern mbedtls_x509_crt       g_srvcert;
extern mbedtls_pk_context     g_srvkey;
extern mbedtls_ctr_drbg_context g_ctr_drbg;
extern mbedtls_entropy_context  g_entropy;
extern mbedtls_ssl_config    g_ssl_conf;

int  tls_init(const char *cert, const char *key, bool tls13_only,
              const char *ciphers, const char *ciphersuites);
int  tls_worker_init(void);
void tls_shutdown(void);
int  tls_handshake(conn_t *c);    /* SALUKID_OK / AGAIN / ERR */

#endif
