#include "nfq_iface.h"
#include "packet_utils.h"
#include "ruleset.h"
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>
#include <linux/netfilter.h> // NF_ACCEPT/NF_DROP

static int cb(struct nfq_q_handle* qh, struct nfgenmsg* nfmsg,
              struct nfq_data* nfa, void* data) {
    (void)nfmsg; (void)data;

    struct nfqnl_msg_packet_hdr* ph = nfq_get_msg_packet_hdr(nfa);
    if (!ph) return 0;
    uint32_t id = ntohl(ph->packet_id);

    unsigned char* payload = NULL;
    int plen = nfq_get_payload(nfa, &payload);
    if (plen < 0) plen = 0;

    ip4_tuple_t t = {0};
    (void)parse_ipv4_tuple(payload, (uint32_t)plen, &t);

    int rid = -1;
    const int matched = ruleset_match(payload, (uint32_t)plen, &rid);

    if (matched) {
        printf("[NFQ] id=%u %s:%u -> %s:%u  verdict=DROP rule=%d\n", id, t.src, t.sport, t.dst, t.dport, rid);
        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
    } else {
        printf("[NFQ] id=%u %s:%u -> %s:%u  verdict=ACCEPT\n", id, t.src, t.sport, t.dst, t.dport);
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }
}

struct nfq_handle* nfq_setup(struct nfq_q_handle** out_qh, uint16_t qnum) {
    struct nfq_handle* h = nfq_open();
    if (!h) { perror("nfq_open"); return NULL; }

    // 바인딩 (중복 바인딩 에러는 무시해도 됨)
    nfq_unbind_pf(h, AF_INET);
    if (nfq_bind_pf(h, AF_INET) < 0) {
        perror("nfq_bind_pf"); goto fail_h;
    }

    struct nfq_q_handle* qh = nfq_create_queue(h, qnum, &cb, NULL);
    if (!qh) { perror("nfq_create_queue"); goto fail_h; }

    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        perror("nfq_set_mode");
        nfq_destroy_queue(qh); goto fail_h;
    }

    *out_qh = qh;
    return h;

fail_h:
    nfq_close(h);
    return NULL;
}

void nfq_teardown(struct nfq_handle* h, struct nfq_q_handle* qh) {
    if (qh) nfq_destroy_queue(qh);
    if (h) nfq_close(h);
}
