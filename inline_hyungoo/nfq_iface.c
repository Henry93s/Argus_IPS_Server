#include "nfq_iface.h"
#include "packet_utils.h"
#include "ruleset.h"
#include "shm_ipc.h"
#include "ips_event.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <signal.h> // g_run extern type
#include <sys/socket.h> // recv()
#include <arpa/inet.h>
#include <linux/netfilter.h> // NF_ACCEPT/NF_DROP

#include <semaphore.h> // sem_post
#include <linux/netlink.h>

// post-accept 이중 미러를 사용할 때 1로 설정하면,
// ACCEPT verdict에 skb mark 0x1을 세팅
#ifndef USE_POST_ACCEPT_MARK
#define USE_POST_ACCEPT_MARK 0
#endif

extern shm_ipc_t g_ipc; // main_nfq.c에서 생성된 SHM 핸들 사용
extern volatile sig_atomic_t g_run;

// === runtime tuning knobs defaults ===
static uint16_t g_queue_num = 0; // default Q 0
static unsigned g_copy_bytes = 1600; // NFQNL_COPY_PACKET range
static unsigned g_queue_maxlen = 4096; // 4096 ~ 65535
static unsigned g_rcvbuf_mb = 8; // netlink socket RCVBUF[MiB]

// setting
void nfq_cfg_set_qnum(uint16_t qnum){ g_queue_num = qnum; }
void nfq_cfg_set_copy(unsigned bytes){ if(bytes) g_copy_bytes = bytes; }
void nfq_cfg_set_qlen(unsigned qlen){ if(qlen) g_queue_maxlen = qlen; }
void nfq_cfg_set_rcvbuf_mb(unsigned mb){ if(mb) g_rcvbuf_mb = mb; }

static inline uint64_t now_ns(){
    struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec*1000000000ull + ts.tv_nsec;
}

static int cb(struct nfq_q_handle* qh, struct nfgenmsg* nfmsg,
              struct nfq_data* nfa, void* data) {
    (void)nfmsg; (void)data;

    struct nfqnl_msg_packet_hdr* ph = nfq_get_msg_packet_hdr(nfa);
    if (!ph) return 0;
    uint32_t id = ntohl(ph->packet_id);

    unsigned char* payload = NULL;
    int plen = nfq_get_payload(nfa, &payload);
    if (plen < 0) plen = 0;

    ip4_tuple_t t = (ip4_tuple_t){0};
    (void)parse_ipv4_tuple(payload, (uint32_t)plen, &t); // t.src,t.dst(char*), t.sport,t.dport, t.proto 채움

    int rid = -1;
    const int matched = ruleset_match(payload, (uint32_t)plen, &rid);
    const int drop = matched ? 1 : 0;

    if (drop) {
        printf("[NFQ] id=%u %s:%u -> %s:%u  verdict=DROP rule=%d\n", id, t.src, t.sport, t.dst, t.dport, rid);
        nfq_set_verdict2(qh, id, NF_DROP, 0x0, 0, NULL);
    } else {
        printf("[NFQ] id=%u %s:%u -> %s:%u  verdict=ACCEPT\n", id, t.src, t.sport, t.dst, t.dport);
        uint32_t mark = USE_POST_ACCEPT_MARK ? 0x1 : 0x0;
        nfq_set_verdict2(qh, id, NF_ACCEPT, mark, 0, NULL);
    }

    // ---- SHM 이벤트 (단방향 텔레메트리) ----
    ips_event_t ev; memset(&ev, 0, sizeof(ev));
    ev.ts_ns      = now_ns();
    ev.verdict    = (uint8_t)(drop ? 1 : 0);
    ev.rule_id    = (uint16_t)(rid >= 0 ? rid : 0);
    ev.risk_score = 0;               // 필요 시 ruleset 확장
    ev.proto      = t.proto;

    struct in_addr sa = {0}, da = {0};
    if (inet_pton(AF_INET, t.src, &sa) == 1) ev.saddr = sa.s_addr;
    if (inet_pton(AF_INET, t.dst, &da) == 1) ev.daddr = da.s_addr;
    ev.sport = t.sport;
    ev.dport = t.dport;

    // flow hash (packet_utils에 구현)
    five_tuple ft;
    if (ip4_tuple_to_five_tuple(&t, &ft) == 0) {
        ev.flow_hash = flow_hash_v4(&ft); // Or, flow_hash64_v4(&ft)
    } else {
        ev.flow_hash = 1;
    }

    if (plen > 0) {
        ev.tot_len=(uint16_t)plen;
        ev.caplen = (uint16_t)((plen < IPS_EVENT_SNAPLEN) ? plen : IPS_EVENT_SNAPLEN);
        memcpy(ev.data, payload, ev.caplen);
    }
    if (g_ipc.ring) {
        if (ips_ring_push(g_ipc.ring, &ev) && g_ipc.sem) {
            sem_post(g_ipc.sem);
        }
    }
    return 0;
}

struct nfq_handle* nfq_setup(struct nfq_q_handle** out_qh, uint16_t qnum) {
    struct nfq_handle* h = nfq_open();
    if (!h) { perror("nfq_open"); return NULL; }

    nfq_unbind_pf(h, AF_INET);
    if (nfq_bind_pf(h, AF_INET) < 0) {
        perror("nfq_bind_pf"); goto fail_h;
    }

    struct nfq_q_handle* qh = nfq_create_queue(h, qnum, &cb, NULL);
    if (!qh) { perror("nfq_create_queue"); goto fail_h; }

    // 헤더+조금만 복사 (성능/부하 균형)
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, g_copy_bytes) < 0) {
        perror("nfq_set_mode");
        nfq_destroy_queue(qh); goto fail_h;
    }

    // Queue len increase
    if(nfq_set_queue_maxlen(qh, g_queue_maxlen)<0) {
        perror("nfq_set_queue_maxlen");
    }

    // netlink socket tuning
    int fd=nfq_fd(h);
    int one=1;
    if (setsockopt(fd, SOL_NETLINK, NETLINK_NO_ENOBUFS, &one, sizeof(one)) < 0) {
        perror("setsockopt(NETLINK_NO_ENOBUFS)");
    }
    int rcv = (int)g_rcvbuf_mb * 1024 * 1024;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcv, sizeof(rcv)) < 0) {
        perror("setsockopt(SO_RCVBUF)");
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
// NFQueue main loop
int run_nfq(uint16_t qnum) {
    struct nfq_q_handle* qh=NULL;
    struct nfq_handle* h=nfq_setup(&qh, qnum); // queue 0 <= ;
    if (!h) return 1;

    const int fd = nfq_fd(h);
    char buf[65536];

    printf("[NFQ] listening on queue %u (Ctrl+C to stop)\n", (unsigned)qnum);

    while (g_run) {
        int r=recv(fd, buf, sizeof(buf), 0);
        if (r>=0){
            nfq_handle_packet(h,buf,r);
            continue;
        }
        if(errno==EINTR || errno==EAGAIN) {
            if(!g_run) break; // signal -> termination
            continue; // pause -> continue
        }
        perror("recv");
        break;
    }
    nfq_teardown(h,qh);
    printf("[NFQ] bye\n");
    return 0;
}
