#define _DEFAULT_SOURCE
#include "packet_utils.h"
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string.h>

int parse_ipv4_tuple(const unsigned char* buf, uint32_t len, ip4_tuple_t* o) {
    if (!buf || !o || len < sizeof(struct iphdr)) return -1;
    const struct iphdr* ip = (const struct iphdr*)buf;
    if (ip->version != 4) return -1;

    uint32_t ihl = ip->ihl * 4u;
    if (ihl < sizeof(struct iphdr) || ihl > len) return -1;

    struct in_addr s= { .s_addr = ip->saddr };
    struct in_addr d= { .s_addr = ip->daddr };

    if (!inet_ntop(AF_INET, &s, o->src, sizeof(o->src))) return -1;
    if (!inet_ntop(AF_INET, &d, o->dst, sizeof(o->dst))) return -1;

    o->proto = (uint8_t)ip->protocol;
    o->sport = 0;
    o->dport = 0;

    if (ip->protocol == IPPROTO_TCP) {
        if (len < ihl + sizeof(struct tcphdr)) return 0; // not enough for ports
        const struct tcphdr* th = (const struct tcphdr*)(buf + ihl);
        o->sport = (uint16_t)ntohs(th->source);
        o->dport = (uint16_t)ntohs(th->dest);
    }
    return 0;
}
