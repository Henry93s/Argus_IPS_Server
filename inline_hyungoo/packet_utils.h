#pragma once
#include <stdint.h>

typedef struct {
    char    src[16];
    char    dst[16];
    uint16_t sport;
    uint16_t dport;
    uint8_t  proto;
} ip4_tuple_t;

int parse_ipv4_tuple(const unsigned char* buf, uint32_t len, ip4_tuple_t* out);
