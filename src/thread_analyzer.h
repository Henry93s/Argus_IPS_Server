#ifndef THREAD_ANALYZER_H
#define THREAD_ANALYZER_H
#include "common.h"
#include "rules_parser.h"

void* analyzer_thread_main(void* args);
void print_payload_hex(const unsigned char *payload, int len);
int decode_dns_qname(const unsigned char* qname_start, int payload_len, char* out_str, int out_max_len);
bool match_header_fields(const Rule* rule, const AnalyzingData* data);
bool match_payload_fields(const Rule* rule, const char* content_to_search, int content_len);
bool analyze_dns_payload(const Rule* rule, const AnalyzingData* data);
bool analyze_generic_payload(const Rule* rule, const AnalyzingData* data);
int decode_http_request(const unsigned char* payload, int len,
                               const char** method, int* method_len,
                               const char** uri, int* uri_len, 
                               const char** headers, int* headers_len,
                               const char** body, int* body_len);
bool analyze_http_payload(const Rule* rule, const AnalyzingData* data);
int hex_to_int(char c);
int url_decode(const char* src, int src_len, char* dst, int dst_max_len);

#endif