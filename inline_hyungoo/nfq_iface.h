#pragma once
#include <stdint.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

struct nfq_handle* nfq_setup(struct nfq_q_handle** out_qh, uint16_t qnum);
void nfq_teardown(struct nfq_handle* h, struct nfq_q_handle* qh);
