/*
 * modsec_real.cpp - Real ModSecurity (libmodsecurity v3) WAF module for salukid.
 *
 * Compiled as C++ and linked against -lmodsecurity. Load rules from a file
 * via cfg (path after ':' in -M flag). Every request is fed to
 * ModSecurity::Transaction; if an intervention is triggered (disruptive),
 * we deny with the configured status (default 403) and log the rule msg.
 *
 * Build: added to Makefile as modules/modsec_real.so -> g++ -fPIC -shared.
 *
 * Config examples:
 *   -M modules/modsec_real.so                         # built-in minimal rules
 *   -M modules/modsec_real.so:/etc/modsec/crs.conf    # load rules from file
 */
#define _GNU_SOURCE
#include "../include/salukid_hooks.h"

#include <modsecurity/modsecurity.h>
#include <modsecurity/rules_set.h>
#include <modsecurity/transaction.h>
#include <modsecurity/intervention.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <new>

using modsecurity::ModSecurity;
using modsecurity::RulesSet;
using modsecurity::Transaction;
using modsecurity::ModSecurityIntervention;

static const salukid_host_v1_t *H = nullptr;
static ModSecurity           *g_ms  = nullptr;
static RulesSet              *g_rules = nullptr;

extern "C" {

/* Built-in minimal Core Rule Set replacement: block obvious SQLi/XSS probes.
 * This lets the module run with zero config out of the box. */
static const char *BUILTIN_RULES =
    "SecRuleEngine On\n"
    "SecRule ARGS \"(?i:union.*select|select.*from|or 1=1|drop table|insert into|delete from|--|;|/\\*|xp_cmdshell)\" \"id:1001,phase:1,deny,status:403,msg:'SQLi detected'\"\n"
    "SecRule ARGS|REQUEST_HEADERS|REQUEST_URI \"(?i:<script|javascript:|onerror=|onload=|alert\\(|<iframe|<svg)\" \"id:1002,phase:1,deny,status:403,msg:'XSS detected'\"\n"
    "SecRule REQUEST_URI \"(?i:\\.\\./|/etc/passwd|/proc/self|cmd\\.exe|\\.\\.\\\\\\)\" \"id:1003,phase:1,deny,status:403,msg:'Path traversal'\"\n"
    "SecRule REQUEST_METHOD \"^(CONNECT|TRACE|TRACK)$\" \"id:1004,phase:1,deny,status:405,msg:'Method not allowed'\"\n";

static int on_req_hdr(void *ctx, salukid_req_t *r)
{
    (void)ctx;
    if (!g_ms || !g_rules) return SALUKID_PASS;

    const char *client_ip = H->remote_addr(r);
    uint16_t    cport     = H->remote_port(r);
    const char *method    = H->method(r);
    const char *uri_p; size_t uri_l;
    H->path(r, &uri_p, &uri_l);
    std::string uri(uri_p, uri_l);
    /* Append query if present */
    const char *q; size_t ql;
    if (H->query(r, &q, &ql) == 0 && ql > 0) {
        uri.push_back('?');
        uri.append(q, ql);
    }
    const char *ver;
    /* We only support HTTP/1.0 and 1.1 in v1; h2 uses a different codepath. */
    ver = "HTTP/1.1";

    Transaction t(g_ms, g_rules, nullptr);
    t.processConnection(client_ip, (int)cport, "127.0.0.1", 0 /*server port set later if needed*/);
    /* URI takes (uri, method, http_version) */
    t.processURI(uri.c_str(), method, ver);

    /* Feed request headers */
    size_t nh = H->header_count(r);
    for (size_t i = 0; i < nh; i++) {
        const salukid_kv_t *kv = H->header_idx(r, i);
        if (!kv) continue;
        std::string k(kv->name, kv->nlen ? kv->nlen : strlen(kv->name));
        std::string v(kv->val, kv->vlen ? kv->vlen : strlen(kv->val));
        t.addRequestHeader(k, v);
    }

    t.processRequestHeaders();

    ModSecurityIntervention it;
    modsecurity::intervention::reset(&it);
    bool blocked = t.intervention(&it);
    if (blocked && it.disruptive) {
        int st = it.status ? it.status : 403;
        const char *msg = "forbidden by WAF";
        /* it.log is a malloc'd C string from ModSecurity */
        (void)msg;
        salukid_resp_t *rs = H->resp_begin(r, st);
        H->resp_set_header(rs, "content-type", "application/json");
        char body[512];
        int n = snprintf(body, sizeof body,
                         "{\"error\":\"blocked by WAF\",\"status\":%d%s%s}\n",
                         st,
                         it.log ? ",\"message\":" : "",
                         it.log ? it.log : "");
        H->resp_send(rs, body, (size_t)(n > 0 ? n : 0));
        if (it.log) { H->log(SALUKID_LOG_WARN, "modsec: %s", it.log); }
        if (it.log)  { /* free Malloc'd strings from intervention */ free(it.log); it.log = nullptr; }
        if (it.url)  { free(it.url); it.url = nullptr; }
        return SALUKID_DENY;
    }
    if (it.log) free(it.log);
    if (it.url) free(it.url);
    return SALUKID_PASS;
}

static int on_init(void **ctxp, const char *cfg, size_t cl,
                   const salukid_host_v1_t *h, uint32_t id)
{
    (void)ctxp; (void)id;
    H = h;

    g_ms = new (std::nothrow) ModSecurity();
    if (!g_ms) { H->log(SALUKID_LOG_ERR, "modsec: alloc failed"); return -1; }
    g_ms->setConnectorInformation("salukid-modsec/0.1");

    g_rules = new (std::nothrow) RulesSet();
    if (!g_rules) { H->log(SALUKID_LOG_ERR, "modsec: rules alloc failed"); return -1; }

    /* Load rules from file if specified; otherwise use builtin set. */
    const char *err = nullptr;
    bool loaded_ok = false;
    std::string rule_path;
    if (cfg && cl > 0) {
        /* cfg may have whitespace/newline; treat as file path */
        size_t L = cl;
        while (L && (cfg[L-1] == ',' || cfg[L-1] == ' ' || cfg[L-1] == '\n')) L--;
        if (L > 0) rule_path.assign(cfg, L);
    }
    if (!rule_path.empty()) {
        if (modsecurity::msc_rules_add_file(g_rules, rule_path.c_str(), &err) > 0) {
            loaded_ok = true;
            H->log(SALUKID_LOG_INFO, "modsec: loaded rules from %s", rule_path.c_str());
        } else {
            H->log(SALUKID_LOG_ERR, "modsec: failed to load %s: %s",
                   rule_path.c_str(), err ? err : "(unknown)");
        }
    }
    if (!loaded_ok) {
        const char *er2 = nullptr;
        if (modsecurity::msc_rules_add(g_rules, BUILTIN_RULES, &er2) < 0) {
            H->log(SALUKID_LOG_ERR, "modsec: failed to load builtin rules: %s",
                   er2 ? er2 : "(unknown)");
            return -1;
        }
        H->log(SALUKID_LOG_INFO, "modsec: loaded builtin rules (ids 1001-1004)");
    }
    return 0;
}

static void on_shutdown(void *ctx)
{
    (void)ctx;
    if (g_rules) { modsecurity::msc_rules_cleanup(g_rules); g_rules = nullptr; }
    delete g_ms; g_ms = nullptr;
}

static const salukid_module_v1_t module = {
    SALUKID_MODULE_MAGIC,
    SALUKID_ABI_V1,
    0,
    "modsec_real",
    on_init,
    on_shutdown,
    nullptr,                  /* reload */
    on_req_hdr,
    nullptr,                  /* on_request_body */
    nullptr,                  /* on_response_headers */
    nullptr,                  /* on_response_body */
    nullptr,                  /* on_log */
    nullptr,                  /* on_wakeup */
};

const salukid_module_v1_t *salukid_module_register_v1(void) { return &module; }

} /* extern "C" */
