#pragma once
#include <stdint.h>

int ruleset_init(const char* path);
int ruleset_match(const unsigned char* buf, uint32_t len, int* out_rule_id);
