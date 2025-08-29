#include <stddef.h> // size_t
#define _GNU_SOURCE // for memmem on glibc
#include <string.h>
#include "ruleset.h"

int ruleset_init(const char* path) {
    (void)path;
    return 0;
}

int ruleset_match(const unsigned char* buf, uint32_t len, int* out_rule_id) {
    if (!buf || len == 0) return 0;
    static const char needle[] = "BLOCKME"; // IM A HACKER
    if (memmem(buf, (size_t)len, needle, sizeof(needle)-1) != NULL) {
        if (out_rule_id) *out_rule_id = 100;
        return 1;
    }
    return 0;
}
