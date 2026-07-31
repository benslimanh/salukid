# salukid Makefile - hardened build with reproducibility, fuzzing, static, sbom targets.
#
# Prerequisites (Debian/Ubuntu):
#   sudo apt-get install -y build-essential zlib1g-dev libnghttp2-dev libnghttp3-dev libssl-dev
# Vendor mbedTLS in-tree (recommended for fully static / pinned TLS):
#   git clone --depth 1 --recurse-submodules --shallow-submodules -b v3.6.2 \
#       https://github.com/Mbed-TLS/mbedtls.git mbedtls
#   make -C mbedtls CFLAGS="-O2 -fPIC" lib
#
CC       ?= gcc
CSTD     ?= -std=c11
WARN     := -Wall -Wextra -Wshadow -Wpointer-arith -Wcast-align \
            -Wstrict-prototypes -Wwrite-strings -Wredundant-decls \
            -Wmissing-declarations -Wformat=2 -Wformat-truncation=2 \
            -Wformat-overflow=2 -Wnull-dereference -Wimplicit-fallthrough \
            -Wno-unused-parameter -Wno-unused-function
OPT      ?= -O2 -fno-plt -fstack-protector-strong
HARDEN   := -D_FORTIFY_SOURCE=3 -fstack-clash-protection -fcf-protection=full
ARCH_HARDEN := $(shell echo "int main(){}" | $(CC) -x c -mcet -mshstk - -o /dev/null 2>/dev/null && echo "-mcet -mshstk" || true)
HARDEN   += $(ARCH_HARDEN)
PIE      := -fPIE -pie
RELRO    := -Wl,-z,relro,-z,now -Wl,-z,noexecstack -Wl,-z,separate-code
LDFLAGS  ?= $(RELRO) -rdynamic
INC      := -Iinclude -I./mbedtls/include
CFLAGS   ?= $(CSTD) $(WARN) $(OPT) $(HARDEN) $(PIE) $(INC) -D_GNU_SOURCE
LDLIBS   := -lnghttp2 -lssl -lmbedtls -lmbedx509 -lmbedcrypto -lz -ldl -lpthread

# When using vendored mbedTLS, pick up its build tree
ifneq ($(wildcard mbedtls/library/libmbedtls.a),)
    MBED_LIBDIR := $(CURDIR)/mbedtls/library
    LDFLAGS += -L$(MBED_LIBDIR)
    CFLAGS  += -I$(CURDIR)/mbedtls/include
    # Static link vendored libs
    LDLIBS := $(MBED_LIBDIR)/libmbedtls.a $(MBED_LIBDIR)/libmbedx509.a \
              $(MBED_LIBDIR)/libmbedcrypto.a -lnghttp2 -lssl -lcrypto -lz -ldl -lpthread
endif

# QUIC / HTTP/3: ngtcp2 + GnuTLS crypto + nghttp3 (all from distro packages)
QUIC_CFLAGS := $(shell PKG_CONFIG_PATH=/usr/lib/x86_64-linux-gnu/pkgconfig pkg-config --cflags gnutls libngtcp2 libngtcp2_crypto_gnutls libnghttp3 2>/dev/null)
QUIC_LDLIBS := $(shell PKG_CONFIG_PATH=/usr/lib/x86_64-linux-gnu/pkgconfig pkg-config --libs gnutls libngtcp2 libngtcp2_crypto_gnutls libnghttp3 2>/dev/null) -lz -ldl -lpthread

SRCS := src/util.c src/path.c src/arena.c src/ringbuf.c src/log.c \
        src/metrics.c src/cache.c src/gzip_etag.c src/parser.c \
        src/response.c src/tls.c src/h2.c src/proxy.c src/module.c \
        src/modapi.c src/subrequester.c src/conn.c src/worker.c src/server.c \
        src/admin.c
OBJS := $(SRCS:.c=.o)
DEPS := $(SRCS:.c=.d)

QUIC_SRCS := quic_server.c
QUIC_OBJS := $(QUIC_SRCS:.c=.o)

BIN       := secure_httpd
QUIC_BIN  := secure_httpd_quic
TEST_BIN  := tests/parser_test
FUZZ_BIN  := fuzz/parser_fuzz
MODULE_SO := modules/hello.so modules/modsec_real.so modules/jwt_auth.so

.PHONY: all quic test fuzz repro static sbom mod hardening-check clean install run-demo certs
all: $(BIN)

$(BIN): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

quic: CFLAGS += -Wno-missing-declarations
quic: $(QUIC_BIN)

$(QUIC_BIN): $(QUIC_OBJS) src/util.o src/path.o src/gzip_etag.o
	$(CC) $(CFLAGS) $(LDFLAGS) -Iinclude -I./mbedtls/include $(QUIC_CFLAGS) -o $@ $^ $(QUIC_LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

-include $(DEPS)

# ---------- Test ----------
test: $(TEST_BIN)
	./$(TEST_BIN)

$(TEST_BIN): tests/parser_test.o src/parser.o src/util.o src/path.o src/gzip_etag.o src/metrics.o src/log.o src/ringbuf.o src/arena.o src/cache.o
	$(CC) $(CSTD) $(WARN) -O0 -g -Iinclude -I./mbedtls/include -D_GNU_SOURCE -o $@ $^ -lz -lpthread -ldl $(MBED_LIBDIR)/libmbedtls.a $(MBED_LIBDIR)/libmbedx509.a $(MBED_LIBDIR)/libmbedcrypto.a -lssl -lcrypto 2>/dev/null || \
	$(CC) $(CSTD) $(WARN) -O0 -g -Iinclude -I./mbedtls/include -D_GNU_SOURCE -o $@ $^ -lz -lpthread -ldl -lmbedtls -lmbedx509 -lmbedcrypto -lnghttp2 -lssl -lcrypto

# ---------- Fuzz ----------
fuzz: CC=clang
fuzz: CFLAGS += -fsanitize=address,fuzzer,undefined -fno-sanitize-recover=all
fuzz: $(FUZZ_BIN)

$(FUZZ_BIN): fuzz/parser_fuzz.c src/parser.c src/util.c
	$(CC) $(CSTD) -O1 -g -Iinclude -D_GNU_SOURCE -fsanitize=address,fuzzer,undefined \
	      -o $@ $^ -lz

# ---------- Module ----------
mod: $(MODULE_SO) modules/modsec_stub.so modules/extauthz_opa.so modules/proxy_wasm.so

modules/hello.so: modules/hello.c
	$(CC) $(CSTD) $(OPT) -fPIC -shared -Iinclude -I./mbedtls/include -o $@ $< -ldl

modules/extauthz_opa.so: modules/extauthz_opa.c
	$(CC) $(CSTD) $(OPT) -fPIC -shared -Iinclude -I./mbedtls/include -o $@ $< -ldl

modules/modsec_stub.so: modules/modsec_stub.c
	$(CC) $(CSTD) $(OPT) -fPIC -shared -Iinclude -I./mbedtls/include -o $@ $< -ldl

# Real ModSecurity WAF: C++ linkage against libmodsecurity
CXX      ?= g++
CXXSTD   ?= -std=c++17
CXXFLAGS_MOD := $(OPT) -fPIC -shared -fno-plt -fstack-protector-strong \
                -D_FORTIFY_SOURCE=3 -fstack-clash-protection \
                -Iinclude -I./mbedtls/include
MODSEC_LDLIBS := $(shell pkg-config --libs modsecurity 2>/dev/null || echo "-lmodsecurity") -lstdc++
modules/modsec_real.so: modules/modsec_real.cpp
	$(CXX) $(CXXSTD) $(CXXFLAGS_MOD) -o $@ $< $(MODSEC_LDLIBS)

modules/jwt_auth.so: modules/jwt_auth.c
	$(CC) $(CSTD) $(OPT) -fPIC -shared -Iinclude -I./mbedtls/include -o $@ $< $(MBED_LIBDIR)/libmbedtls.a $(MBED_LIBDIR)/libmbedx509.a $(MBED_LIBDIR)/libmbedcrypto.a -ldl

# proxy-wasm module: needs WAMR. If WASMRT is set, builds with full support;
# otherwise builds a stub that fails at load time with a helpful message.
ifneq ($(WASMRT),)
  WASM_CFLAGS  := -DHAS_WAMR=1 -I$(WASMRT)/core/iwasm/include -I$(WASMRT)/core/shared/utils
  WASM_LDFLAGS := -L$(WASMRT)/build -lvmlib -luv -lpthread -lm
endif
modules/proxy_wasm.so: modules/proxy_wasm.c
	$(CC) $(CSTD) $(OPT) -fPIC -shared -Iinclude -I./mbedtls/include $(WASM_CFLAGS) -o $@ $< -ldl $(WASM_LDFLAGS)

# ---------- Static / distroless binary ----------
static: CFLAGS  += -static
static: LDFLAGS := -Wl,-z,relro,-z,now -Wl,-z,noexecstack
static: LDLIBS   := -Wl,-Bstatic $(MBED_LIBDIR)/libmbedtls.a $(MBED_LIBDIR)/libmbedx509.a \
                    $(MBED_LIBDIR)/libmbedcrypto.a -lnghttp2 -lz -ldl -lpthread -l:libssl.a -l:libcrypto.a -Wl,-Bdynamic
static: clean $(BIN)

# ---------- Reproducibility ----------
repro:
	$(eval T1 := $(shell SOURCE_DATE_EPOCH=1700000000 make clean all 2>&1 >/dev/null; sha256sum $(BIN)))
	@sleep 1
	$(eval T2 := $(shell SOURCE_DATE_EPOCH=1700000000 make clean all 2>&1 >/dev/null; sha256sum $(BIN)))
	@echo "build1: $(T1)"; echo "build2: $(T2)"; \
		test "$$(echo $(T1)|awk '{print $$1}')" = "$$(echo $(T2)|awk '{print $$1}')" \
		&& echo "REPRODUCIBLE: OK" || (echo "REPRODUCIBLE: FAIL"; exit 1)

# ---------- SBOM (SPDX) ----------
sbom:
	@echo "Generating SPDX SBOM to salukid.spdx ..."
	@./scripts/generate_sbom.sh > salukid.spdx 2>/dev/null || \
	{ echo "SPDXVersion: SPDX-2.3" > salukid.spdx; \
	  echo "DataLicense: CC0-1.0" >> salukid.spdx; \
	  echo "SPDXID: SPDXRef-DOCUMENT" >> salukid.spdx; \
	  echo "PackageName: salukid" >> salukid.spdx; \
	  echo "PackageVersion: $(shell grep -oP 'SALUKID_VERSION\s+"\K[^"]+' include/common.h)" >> salukid.spdx; \
	  echo "PackageLicenseConcluded: MIT" >> salukid.spdx; \
	  echo "## auto-generated stub" >> salukid.spdx; \
	  echo "SBOM stub written to salukid.spdx"; }

# ---------- Hardening verification ----------
hardening-check: $(BIN)
	@echo "== ELF hardening checks =="
	@type hardening-check >/dev/null 2>&1 && hardening-check $(BIN) $(QUIC_BIN) || { \
	  echo "(hardening-check not installed; running manual checks)"; \
	  file $(BIN); \
	  readelf -d $(BIN) | grep -E '(BIND_NOW|FLAGS_1|RELRO)' ; \
	  readelf -h $(BIN) | grep 'Type:'; \
	  echo "NX: "; readelf -l $(BIN) | grep -E 'GNU_STACK.*RW' && echo "NX ok (no eXec)" || echo "NX?"; \
	}
	@echo "== GOT-PLT relro / PIE / stack-protector symbols =="
	@readelf -sW $(BIN) | grep -E '(__stack_chk_fail|_FORTIFY)' || true
	@nm -D $(BIN) | grep -E ' U (strcpy|strcat|sprintf|gets)$$' && echo "FAIL: unsafe functions linked" || echo "OK: no unsafe str*/sprintf/gets linked"

# ---------- Demo cert ----------
certs/cert.pem certs/key.pem: certs
	openssl req -x509 -newkey rsa:2048 -sha256 -days 365 -nodes \
	    -keyout certs/key.pem -out certs/cert.pem \
	    -subj "/C=MA/ST=TTA/L=Tangier/O=salukid/CN=localhost" \
	    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

certs:
	mkdir -p certs

run-demo: certs/cert.pem all
	./$(BIN) -p 8080 -T 8443 -C certs/cert.pem -K certs/key.pem -r ./www -w 0

clean:
	rm -f $(OBJS) $(QUIC_OBJS) $(DEPS) $(BIN) $(QUIC_BIN) $(TEST_BIN) $(FUZZ_BIN) $(MODULE_SO)

install: $(BIN)
	install -m 0755 $(BIN) /usr/local/bin/$(BIN)
