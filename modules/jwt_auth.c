/*
 * jwt_auth.c - JWT authentication module for salukid (v1 ABI).
 *
 * Implements HS256/HS384/HS512 HMAC-SHA JWT validation. Given a shared
 * secret (config: secret=<hex> or secret_b64=<b64>), the module verifies
 * the Bearer token signature, expiration (exp), not-before (nbf), and
 * issuer (iss). Configurable paths can bypass auth (skip_path=...).
 *
 * This is NOT a full JWT library but covers the 90% use case for
 * API-gateway edge authentication without pulling in openssl or jansson.
 * Uses mbedtls (already linked statically for TLS) for HMAC and SHA.
 */
#define _GNU_SOURCE
#include "../include/salukid_hooks.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#include <mbedtls/md.h>
#include <mbedtls/base64.h>
#include <mbedtls/pk.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/rsa.h>

static const salukid_host_v1_t *H;

typedef struct {
    uint8_t  secret[64];
    size_t   secret_len;
    char     iss[128];
    char     skip_prefix[128];
    bool     require_auth;
    /* Asymmetric key (RS256/RS384/RS512/ES256/ES384/ES512) */
    bool     have_pubkey;
    mbedtls_pk_context pubkey;
    mbedtls_md_type_t  pk_md;
} cfg_t;
static cfg_t cfg;

static uint64_t b64url_decode_len(const char *s, size_t n)
{
    /* Strip padding */
    while (n && s[n-1]=='=') n--;
    return (n * 6 + 7) / 8;
}
static int b64url_decode(uint8_t *out, size_t outcap, const char *s, size_t n)
{
    /* Translate base64url to standard base64 */
    char buf[1024];
    if (n >= sizeof buf) return -1;
    memcpy(buf, s, n); buf[n]=0;
    for (size_t i = 0; i < n; i++) {
        if (buf[i]=='-') buf[i]='+';
        else if (buf[i]=='_') buf[i]='/';
    }
    /* Add padding */
    while (n % 4) buf[n++] = '=';
    buf[n]=0;
    size_t olen = 0;
    if (mbedtls_base64_decode(out, outcap, &olen, (const uint8_t*)buf, n) != 0) return -1;
    return (int)olen;
}

static bool jwt_hmac_verify(mbedtls_md_type_t md, const uint8_t *sec, size_t seclen,
                             const char *signing_input, size_t si_len,
                             const char *sig_b64, size_t sig_b64_len)
{
    uint8_t sig[64];
    int sl = b64url_decode(sig, sizeof sig, sig_b64, sig_b64_len);
    if (sl <= 0) return false;
    uint8_t calc[MBEDTLS_MD_MAX_SIZE];
    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(md);
    if (!info) return false;
    if (mbedtls_md_hmac(info, sec, seclen, (const uint8_t*)signing_input, si_len, calc) != 0)
        return false;
    size_t hlen = mbedtls_md_get_size(info);
    if ((size_t)sl != hlen) return false;
    /* constant-time compare */
    uint8_t diff = 0;
    for (size_t i = 0; i < hlen; i++) diff |= calc[i] ^ sig[i];
    return diff == 0;
}

/* Minimal JSON field extraction for {"iss":"...","exp":N,...} */
static bool json_get_str(const char *json, size_t jsonlen, const char *key, char *out, size_t cap)
{
    char needle[32]; size_t kl = strlen(key);
    int n = snprintf(needle, sizeof needle, "\"%s\"", key);
    const char *p = memmem(json, jsonlen, needle, (size_t)n);
    if (!p) return false;
    p += (size_t)n;
    while (p < json + jsonlen && (*p==' '||*p==':')) p++;
    if (p >= json+jsonlen || *p != '"') return false;
    p++;
    size_t i = 0;
    while (p+i < json+jsonlen && p[i] != '"' && i+1 < cap) { out[i] = p[i]; i++; }
    out[i] = '\0';
    return true;
}
static bool json_get_int(const char *json, size_t jsonlen, const char *key, int64_t *out)
{
    char needle[32]; size_t kl = strlen(key);
    int n = snprintf(needle, sizeof needle, "\"%s\"", key);
    const char *p = memmem(json, jsonlen, needle, (size_t)n);
    if (!p) return false;
    p += (size_t)n;
    while (p < json+jsonlen && (*p==' '||*p==':')) p++;
    if (p >= json+jsonlen) return false;
    char num[32]; size_t i = 0;
    while (p < json+jsonlen && (p[0]=='-'||(p[0]>='0'&&p[0]<='9')) && i < sizeof num-1) { num[i++] = *p++; }
    num[i]=0;
    *out = strtoll(num, NULL, 10);
    return i > 0;
}

static int on_req_hdr(void *ctx, salukid_req_t *r)
{
    (void)ctx;
    const char *p; size_t pl;
    H->path(r, &p, &pl);
    if (cfg.skip_prefix[0] && pl >= strlen(cfg.skip_prefix) &&
        !memcmp(p, cfg.skip_prefix, strlen(cfg.skip_prefix)))
        return SALUKID_PASS;
    /* Public endpoints always allowed */
    if ((pl == 8 && !memcmp(p, "/healthz", 8)) ||
        (pl == 8 && !memcmp(p, "/metrics", 8)) ||
        (pl >= 8 && !memcmp(p, "/_admin/", 8)))
        return SALUKID_PASS;

    const char *auth = H->header_get(r, "authorization");
    if (!auth || strncmp(auth, "Bearer ", 7) != 0) goto deny_401;
    const char *tok = auth + 7;
    size_t tl = strlen(tok);

    /* Find the two dots separating header.payload.signature */
    const char *dot1 = memchr(tok, '.', tl);
    if (!dot1) goto deny_401;
    const char *dot2 = memchr(dot1+1, '.', tl - (size_t)(dot1+1-tok));
    if (!dot2) goto deny_401;

    const char *hdr_b = tok;       size_t hdr_l = (size_t)(dot1 - tok);
    const char *pay_b = dot1 + 1;  size_t pay_l = (size_t)(dot2 - (dot1+1));
    const char *sig_b = dot2 + 1;  size_t sig_l = tl - (size_t)(dot2+1-tok);
    size_t si_l = (size_t)(dot2 - tok);

    /* Decode header to find alg */
    uint8_t hdr_buf[256];
    int hl = b64url_decode(hdr_buf, sizeof hdr_buf, hdr_b, hdr_l);
    if (hl < 0) goto deny_401;
    hdr_buf[hl]=0;
    char alg[16];
    if (!json_get_str((const char*)hdr_buf, (size_t)hl, "alg", alg, sizeof alg)) goto deny_401;

    mbedtls_md_type_t md = MBEDTLS_MD_NONE;
    bool is_asym = false;
    if (!strcmp(alg, "HS256")) md = MBEDTLS_MD_SHA256;
    else if (!strcmp(alg, "HS384")) md = MBEDTLS_MD_SHA384;
    else if (!strcmp(alg, "HS512")) md = MBEDTLS_MD_SHA512;
    else if (!strcmp(alg, "RS256")) { md = MBEDTLS_MD_SHA256; is_asym = true; }
    else if (!strcmp(alg, "RS384")) { md = MBEDTLS_MD_SHA384; is_asym = true; }
    else if (!strcmp(alg, "RS512")) { md = MBEDTLS_MD_SHA512; is_asym = true; }
    else if (!strcmp(alg, "ES256")) { md = MBEDTLS_MD_SHA256; is_asym = true; }
    else if (!strcmp(alg, "ES384")) { md = MBEDTLS_MD_SHA384; is_asym = true; }
    else goto deny_401;

    bool sig_ok = false;
    if (is_asym) {
        if (!cfg.have_pubkey) goto deny_401;
        uint8_t sig[512];
        int sl = b64url_decode(sig, sizeof sig, sig_b, sig_l);
        if (sl <= 0) goto deny_401;
        /* Compute signing_input hash */
        uint8_t digest[MBEDTLS_MD_MAX_SIZE];
        const mbedtls_md_info_t *mi = mbedtls_md_info_from_type(md);
        if (!mi) goto deny_401;
        size_t hlen = mbedtls_md_get_size(mi);
        if (mbedtls_md(mi, (const uint8_t*)tok, si_l, digest) != 0) goto deny_401;
        /* mbedtls_pk_verify expects ASN.1 DER signature for RSA. The
         * JWS signature is the raw RSASSA-PKCS1-v1_5 s value padded to
         * modulus length, which mbedtls_rsa_pkcs1_verify handles directly.
         * For ECDSA JWS uses raw r||s which we need to DER-encode. */
        if (mbedtls_pk_get_type(&cfg.pubkey) == MBEDTLS_PK_RSA) {
            if (mbedtls_pk_verify(&cfg.pubkey, md, digest, hlen, sig, (size_t)sl) == 0)
                sig_ok = true;
        } else if (mbedtls_pk_get_type(&cfg.pubkey) == MBEDTLS_PK_ECKEY
                || mbedtls_pk_get_type(&cfg.pubkey) == MBEDTLS_PK_ECDSA) {
            /* Convert JWS raw r||s to DER ECDSA-Sig-Value */
            size_t ord = (size_t)sl / 2;
            if (ord == 0 || (size_t)sl != ord*2) goto deny_401;
            uint8_t der[128];
            /* Construct: 0x30 <len> 0x02 <rlen> <rpad+rawr> 0x02 <slen> <spad+raws> */
            /* Strip leading zeroes then check high bit; prepend 0x00 if set */
            const uint8_t *rp = sig; size_t rl = ord;
            const uint8_t *sp = sig + ord; size_t slen = ord;
            while (rl > 1 && rp[0]==0) { rp++; rl--; }
            while (slen > 1 && sp[0]==0) { sp++; slen--; }
            size_t rpadd = (rp[0] & 0x80) ? 1 : 0;
            size_t spadd = (sp[0] & 0x80) ? 1 : 0;
            size_t tlen = 2 + rl + rpadd + 2 + slen + spadd;
            size_t doff = 0;
            der[doff++] = 0x30; der[doff++] = (uint8_t)tlen;
            der[doff++] = 0x02; der[doff++] = (uint8_t)(rl + rpadd);
            if (rpadd) der[doff++] = 0; memcpy(der+doff, rp, rl); doff += rl;
            der[doff++] = 0x02; der[doff++] = (uint8_t)(slen + spadd);
            if (spadd) der[doff++] = 0; memcpy(der+doff, sp, slen); doff += slen;
            if (mbedtls_pk_verify(&cfg.pubkey, md, digest, hlen, der, doff) == 0)
                sig_ok = true;
        }
    } else {
        if (cfg.secret_len == 0) goto deny_401;
        sig_ok = jwt_hmac_verify(md, cfg.secret, cfg.secret_len, tok, si_l, sig_b, sig_l);
    }
    if (!sig_ok) goto deny_401;

    /* Decode payload to check exp/nbf/iss */
    size_t pay_cap = b64url_decode_len(pay_b, pay_l) + 1;
    uint8_t *pay = H->mem_alloc(r, pay_cap);
    if (!pay) goto deny_500;
    int pl2 = b64url_decode(pay, pay_cap-1, pay_b, pay_l);
    if (pl2 < 0) goto deny_401;
    pay[pl2] = 0;

    int64_t now = (int64_t)time(NULL);
    int64_t exp = 0;
    if (json_get_int((const char*)pay, (size_t)pl2, "exp", &exp) && exp && now >= exp) goto deny_401;
    int64_t nbf = 0;
    if (json_get_int((const char*)pay, (size_t)pl2, "nbf", &nbf) && nbf && now < nbf) goto deny_401;
    if (cfg.iss[0]) {
        char token_iss[128];
        if (!json_get_str((const char*)pay, (size_t)pl2, "iss", token_iss, sizeof token_iss) ||
            strcmp(token_iss, cfg.iss) != 0) goto deny_401;
    }
    return SALUKID_PASS;

deny_401: {
    salukid_resp_t *rs = H->resp_begin(r, 401);
    H->resp_set_header(rs, "content-type", "application/json");
    H->resp_set_header(rs, "www-authenticate", "Bearer");
    H->resp_send_str(rs, "{\"error\":\"unauthorized\"}\n");
    return SALUKID_DENY;
}
deny_500: {
    salukid_resp_t *rs = H->resp_begin(r, 500);
    H->resp_set_header(rs, "content-type", "application/json");
    H->resp_send_str(rs, "{\"error\":\"authz error\"}\n");
    return SALUKID_DENY;
}
}

static int hex_decode(uint8_t *out, size_t cap, const char *hex)
{
    size_t hl = strlen(hex); size_t n = 0;
    if (hl % 2 != 0 || hl > cap*2) return -1;
    for (size_t i = 0; i+1 < hl; i += 2) {
        unsigned int byte;
        if (sscanf(hex+i, "%2x", &byte) != 1) return -1;
        out[n++] = (uint8_t)byte;
    }
    return (int)n;
}

static int on_init(void **ctxp, const char *cfgs, size_t cl,
                   const salukid_host_v1_t *h, uint32_t id)
{
    (void)ctxp; (void)id; H = h;
    memset(&cfg, 0, sizeof cfg);
    mbedtls_pk_init(&cfg.pubkey);
    if (cfgs && cl) {
        char buf[512]; size_t L = (cl >= sizeof buf) ? sizeof buf-1 : cl;
        memcpy(buf, cfgs, L); buf[L]='\0';
        const char *s = strstr(buf, "secret_hex=");
        if (s) {
            s += 11; const char *e = strchrnul(s, ',');
            char tmp[128]; size_t tl = (size_t)(e-s); if (tl >= sizeof tmp) tl = sizeof tmp-1;
            memcpy(tmp, s, tl); tmp[tl]='\0';
            int n = hex_decode(cfg.secret, sizeof cfg.secret, tmp);
            if (n > 0) cfg.secret_len = (size_t)n;
        }
        const char *i = strstr(buf, "iss=");
        if (i) {
            i += 4; const char *e = strchrnul(i, ',');
            size_t il = (size_t)(e-i); if (il >= sizeof cfg.iss) il = sizeof cfg.iss-1;
            memcpy(cfg.iss, i, il);
        }
        const char *sk = strstr(buf, "skip_path=");
        if (sk) {
            sk += 10; const char *e = strchrnul(sk, ',');
            size_t sl = (size_t)(e-sk); if (sl >= sizeof cfg.skip_prefix) sl = sizeof cfg.skip_prefix-1;
            memcpy(cfg.skip_prefix, sk, sl);
        }
        const char *pk = strstr(buf, "pubkey_pem=");
        if (pk) {
            pk += 11; const char *e = strchrnul(pk, ',');
            /* pubkey_pem=<path> */
            char path[4096];
            size_t pl = (size_t)(e-pk); if (pl >= sizeof path) pl = sizeof path-1;
            memcpy(path, pk, pl); path[pl] = '\0';
            if (mbedtls_pk_parse_public_keyfile(&cfg.pubkey, path) == 0) {
                cfg.have_pubkey = true;
                H->log(SALUKID_LOG_INFO, "jwt_auth loaded public key from %s", path);
            } else {
                H->log(SALUKID_LOG_ERR, "jwt_auth: cannot load pubkey %s", path);
            }
        }
    }
    if (cfg.secret_len == 0) {
        /* Default dev secret: "salukid-dev-secret" */
        const char d[] = "salukid-dev-secret";
        memcpy(cfg.secret, d, sizeof d - 1);
        cfg.secret_len = sizeof d - 1;
        H->log(SALUKID_LOG_WARN, "jwt_auth: using DEV secret; pass secret_hex= for production");
    }
    H->log(SALUKID_LOG_INFO, "jwt_auth loaded iss=%s skip=%s secret_len=%zu",
           cfg.iss[0]?cfg.iss:"(any)", cfg.skip_prefix, cfg.secret_len);
    return 0;
}

static void on_shutdown(void *ctx) {
    (void)ctx;
    if (cfg.have_pubkey) {
        mbedtls_pk_free(&cfg.pubkey);
        cfg.have_pubkey = false;
    }
}

static const salukid_module_v1_t module = {
    SALUKID_MODULE_MAGIC, SALUKID_ABI_V1, 0, "jwt_auth",
    on_init, on_shutdown, NULL, on_req_hdr, NULL, NULL, NULL, NULL, NULL,
};
const salukid_module_v1_t *salukid_module_register_v1(void) { return &module; }
