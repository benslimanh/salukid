/*
 * parser_fuzz.c - libFuzzer harness for the HTTP/1.x parser.
 * Builds: make fuzz   (uses clang + -fsanitize=address,fuzzer,undefined)
 */
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "../src/parser.c"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    http_request_t req;
    http_request_reset(&req);
    size_t consumed = 0;
    http_request_parse(&req, (const char*)data, size, &consumed);
    return 0;
}
