// thread_analyzer.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <ctype.h> // isprint() 함수 사용
#include "common.h"
#include "ts_analyzing_queue.h"
#include "ts_alert_queue.h"
#include "thread_analyzer.h"
#include "sessionManager.h"

// 고속 검색 알고리즘 (Aho-Corasick) 대신, memmem으로 대체
const char* find_content(const unsigned char* payload, int payload_len, const char* content) {
    if (!payload || !content) return NULL;
    return (const char*)memmem(payload, payload_len, content, strlen(content));
}

// 페이로드를 16진수와 ASCII 문자로 출력하는 디버깅 함수
void print_payload_hex(const unsigned char *payload, int len) {
    if (payload == NULL || len == 0) {
        printf("  (Payload is empty)\n");
        return;
    }

    int i;
    for (i = 0; i < len; i++) {
        if (i % 16 == 0) printf("  %04x: ", i);
        printf("%02x ", payload[i]);
        if ((i + 1) % 16 == 0 || i == len - 1) {
            int j;
            // 패딩 처리
            if ((i + 1) % 16 != 0) {
                for (j = 0; j < 16 - ((i + 1) % 16); j++) {
                    printf("   ");
                }
            }
            printf("| ");
            // ASCII 문자 출력
            for (j = i - (i % 16); j <= i; j++) {
                if (isprint(payload[j])) {
                    printf("%c", payload[j]);
                } else {
                    printf(".");
                }
            }
            printf("\n");
        }
    }
}

// DNS QNAME 형식 (e.g., \x06google\x03com\x00)을 일반 문자열("google.com")로 변환하는 함수
// 반환값: 변환된 문자열의 길이, 실패 시 -1
int decode_dns_qname(const unsigned char* qname_start, int payload_len, char* out_str, int out_max_len) {
    if (!qname_start || !out_str || payload_len <= 0) return -1;

    const unsigned char* p = qname_start;
    int out_idx = 0;
    
    // DNS 헤더 12바이트를 건너뛴 위치에서 시작
    if (payload_len < 12) return -1;
    p += 12; // Skip DNS Header

    int len_rem = payload_len - 12;

    while (*p != 0 && len_rem > 0) {
        uint8_t label_len = *p;
        p++;
        len_rem--;

        if (label_len > len_rem || (out_idx + label_len) >= out_max_len -1) {
            return -1; // 버퍼 오버플로우 또는 잘못된 길이
        }
        
        memcpy(out_str + out_idx, p, label_len);
        p += label_len;
        len_rem -= label_len;
        out_idx += label_len;

        if (*p != 0 && len_rem > 0) {
             if (out_idx >= out_max_len - 1) return -1;
             out_str[out_idx] = '.';
             out_idx++;
        }
    }
    
    out_str[out_idx] = '\0';
    return out_idx;
}

// HTTP 페이로드(Request, Header, Body) 파싱
int decode_http_request(const unsigned char* payload, int len,
                               const char** method, int* method_len, 
                               const char** uri, int* uri_len, 
                               const char** headers, int* headers_len,
                               const char** body, int* body_len) {
    if (!payload || len < 16) return 0; // 최소한의 HTTP 요청 길이 체크

    // 1. 요청 라인(Request Line) 의 끝("\r\n") 을 찾는다
    const char* req_line_end = memmem(payload, len, "\r\n", 2);
    if (!req_line_end) return 0;
    int req_line_len = req_line_end - (const char*)payload;

    // 2. 메서드(GET, POST 등)의 끝을 찾는다. (메서드 추출)
    const char* method_start = (const char*)payload;
    const char* method_end = memchr(method_start, ' ', req_line_len);
    if (!method_end) return 0;
    *method = method_start;
    *method_len = method_end - method_start;

    // 3. URI 의 끝을 찾는다. (URI 추출, 요청 라인의 '마지막' 공백)
    const char* uri_start = method_end + 1;
    const char* uri_end = NULL;
    // req_line_end 바로 앞에서부터 왼쪽으로 이동하며 공백을 검색
    for (const char* p = req_line_end - 1; p > uri_start; --p) {
        if (*p == ' ') {
            uri_end = p;
            break;
        }
    }
    // 마지막 공백을 찾지 못했다면 비정상적인 요청 라인
    if (!uri_end) {
        return 0;
    }
    *uri = uri_start;
    *uri_len = uri_end - uri_start;

    // 4. 헤더 블록과 바디 분리
    const char* headers_start = req_line_end + 2;
    const char* body_start_marker = memmem(headers_start, len - (headers_start - (const char*)payload), "\r\n\r\n", 4);

    if (body_start_marker) {
        *headers = headers_start;
        *headers_len = body_start_marker - headers_start;
        *body = body_start_marker + 4;
        *body_len = len - (*body - (const char*)payload);
    } else { // 바디가 없는 요청 (e.g., GET)
        *headers = headers_start;
        *headers_len = len - (headers_start - (const char*)payload);
        *body = NULL;
        *body_len = 0;
    }
    
    return 1;
}

// 16진수 문자(0-9, a-f)를 정수로 변환
int hex_to_int(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// URL 인코딩된 문자열을 디코딩
int url_decode(const char* src, int src_len, char* dst, int dst_max_len) {
    int dst_len = 0;
    for (int i = 0; i < src_len && dst_len < dst_max_len - 1; i++) {
        if (src[i] == '%' && i + 2 < src_len) {
            int high = hex_to_int(src[i+1]);
            int low = hex_to_int(src[i+2]);
            if (high != -1 && low != -1) {
                dst[dst_len++] = (char)(high * 16 + low);
                i += 2;
            } else {
                dst[dst_len++] = src[i];
            }
        } else if (src[i] == '+') {
            dst[dst_len++] = ' ';
        } else {
            dst[dst_len++] = src[i];
        }
    }
    dst[dst_len] = '\0';
    return dst_len;
}

// 프로토콜별 분석 함수 - Start
// 헤더 필드 매칭 함수 (공통 로직)
bool match_header_fields(const Rule* rule, const AnalyzingData* data) {
    // 프로토콜 검사
    if (rule->protocol != 0 && rule->protocol != data->ipHeader.protocol) {
        return false;
    }
    
    // IP 및 포트 검사
    uint32_t srcIpInt = *(uint32_t*)data->ipHeader.srcIP;
    uint32_t dstIpInt = *(uint32_t*)data->ipHeader.dstIP;

    if (rule->src_ip != 0 && rule->src_ip != srcIpInt) return false;
    if (rule->dst_ip != 0 && rule->dst_ip != dstIpInt) return false;

    if (data->ipHeader.protocol == IPPROTO_TCP || data->ipHeader.protocol == IPPROTO_UDP) {
        if (rule->src_port != 0 && rule->src_port != data->tcpHeader.srcPort) return false;
        if (rule->dst_port != 0 && rule->dst_port != data->tcpHeader.dstPort) return false;
    }
    
    // 3. TCP 플래그 검사
    if (rule->protocol == IPPROTO_TCP) {
        // NULL Scan (flags:0)은 플래그가 정확히 0일 때만 탐지하는 특별 케이스
        if (strcmp(rule->msg, "Potential NULL Scan Detected") == 0) {
            return (data->tcpHeader.flags == 0);
        }

        // 그 외 모든 플래그 룰
        if (rule->flags != 0) {
            // 룰에 지정된 모든 플래그가 패킷에 포함되어 있는지 확인
            // (packet_flags & rule_flags) == rule_flags
            if ((data->tcpHeader.flags & rule->flags) != rule->flags) {
                return false;
            }
        }
    }
   
    return true;
}

// 페이로드 매칭 함수 (공통 로직)
bool match_payload_fields(const Rule* rule, const char* content_to_search, int content_len) {
    bool content_match = false;
    if (rule->content) {
        if (memmem(content_to_search, content_len, rule->content, strlen(rule->content)) != NULL) {
            content_match = true;
        }
    }

    bool pcre_match = false;
    if (rule->has_pcre) {
        if (regexec(&rule->pcre, content_to_search, 0, NULL, 0) == 0) {
            pcre_match = true;
        }
    }

    // 룰에 content나 pcre 옵션이 하나라도 있는데, 둘 다 매칭되지 않으면 최종 실패
    if ((rule->content || rule->has_pcre) && !(content_match || pcre_match)) {
        return false;
    }
    
    return true;
}

// DNS 페이로드 분석 함수
bool analyze_dns_payload(const Rule* rule, const AnalyzingData* data) {
    // 1. 헤더 필드가 룰과 일치하는지 먼저 확인
    if (!match_header_fields(rule, data)) {
        return false;
    }

    // 2. 페이로드 기반 룰인 경우, DNS 파싱 후 내용 비교
    if (rule->type == RULE_TYPE_PAYLOAD) {
        if (data->data == NULL || data->len == 0) return false;
        
        char decoded_name[256];
        if (decode_dns_qname(data->data, data->len, decoded_name, sizeof(decoded_name)) > 0) {
            printf("[Analyzer DEBUG] Rule ID %d, Decoded DNS QNAME: %s\n", rule->id, decoded_name);
            return match_payload_fields(rule, decoded_name, strlen(decoded_name));
        }
        return false; // 디코딩 실패 시 매칭 실패
    }

    return true; // 헤더 기반 룰이고, 헤더 매칭이 성공했으므로 최종 성공
}

// 일반 (평문 기반) 페이로드 분석 함수
bool analyze_generic_payload(const Rule* rule, const AnalyzingData* data) {
    // 1. 헤더 필드가 룰과 일치하는지 먼저 확인
    if (!match_header_fields(rule, data)) {
        return false;
    }
    
    // 2. 페이로드 기반 룰인 경우, 단순 내용 비교
    if (rule->type == RULE_TYPE_PAYLOAD) {
        if (data->data == NULL || data->len == 0) return false;

        printf("[Analyzer DEBUG] Rule ID %d, Generic Content Check: rule content='%s'\n", rule->id, rule->content ? rule->content : "");
        printf("[Analyzer DEBUG] Packet payload (len=%d):\n", data->len);
        print_payload_hex(data->data, data->len);
        
        return match_payload_fields(rule, (const char*)data->data, data->len);
    }

    return true; // 헤더 기반 룰이고, 헤더 매칭이 성공했으므로 최종 성공
}

// HTTP 페이로드 파싱 후 룰의 content나 pcre를 파싱된 각 영역(URI, 헤더, 바디)과 비교하여 매칭 여부를 결정하는 분석 함수
bool analyze_http_payload(const Rule* rule, const AnalyzingData* data) {
    if (!match_header_fields(rule, data)) {
        return false;
    }
    if (rule->type == RULE_TYPE_HEADER) {
        return true; // 헤더 기반 룰은 통과
    }
    if (data->data == NULL || data->len == 0) {
        return false;
    }

    const char *method, *uri, *headers, *body;
    int method_len, uri_len, headers_len, body_len;

    // HTTP 요청 파싱 시도
    if (decode_http_request(data->data, data->len, &method, &method_len, &uri, &uri_len, &headers, &headers_len, &body, &body_len)) {
        // 1. 메소드와 룰 비교
        // 'GET ' 이나 'POST ' 같은 룰을 위해 메소드 뒤에 공백을 붙여서 비교
        char method_with_space[32];
        if (method_len < sizeof(method_with_space) - 1) {
            memcpy(method_with_space, method, method_len);
            method_with_space[method_len] = ' ';
            method_with_space[method_len + 1] = '\0';
            
            if (match_payload_fields(rule, method_with_space, method_len + 1)) {
                return true;
            }
        }
        
        // 2. URI 디코딩 및 비교
        char decoded_uri[4096]; // 일반적인 URI 최대 길이를 고려
        int decoded_uri_len = 0;
        if (uri) {
            decoded_uri_len = url_decode(uri, uri_len, decoded_uri, sizeof(decoded_uri));
            printf("[Analyzer DEBUG] Rule ID %d, HTTP Decoded URI: %s\n", rule->id, decoded_uri);
        }

        // 3-1. 디코딩된 URI와 룰 비교
        if (decoded_uri_len > 0 && match_payload_fields(rule, decoded_uri, decoded_uri_len)) {
            return true;
        }
        
        // 3-2. 헤더와 룰 비교
        if (headers && match_payload_fields(rule, headers, headers_len)) {
            return true;
        }

        // 4-3. 바디와 룰 비교
        if (body && match_payload_fields(rule, body, body_len)) {
            return true;
        }
    } else {
        // 파싱에 실패하면 (ex. HTTP 응답, 변형된 요청 등), 일반 분석기 callback
        printf("[Analyzer DEBUG] Rule ID %d, HTTP parsing failed, falling back to generic scan.\n", rule->id);
        return analyze_generic_payload(rule, data);
    }

    return false; // 모든 영역에서 매칭 실패
}
// 프로토콜별 분석 함수 - End

void* analyzer_thread_main(void* args) {
    ThreadArgs* thread_args = (ThreadArgs*)args;
    AnalyzingDataQueue* analyzingQueue = thread_args->analyzingQueue;
    // AlertQueue* alertQueue = thread_args->alertQueue;
    volatile sig_atomic_t* isRunning = thread_args->isRunning;

    RuleSet ruleSet;
    rulesetInit(&ruleSet, "../IDS_rules/IDS_rules.conf"); // 룰 로딩
    // 룰 로딩 확인 - start
    Rule* rule = ruleSet.head;
    int rule_count = 0;
    printf("=== Loaded Rules ===\n");
    while (rule != NULL) {
        rule_count++;
        printf("Rule ID: %d, Type: %s, Msg: %s, Content: %s, PCRE: %s\n",
            rule->id,
            (rule->type == RULE_TYPE_HEADER) ? "HEADER" :
            (rule->type == RULE_TYPE_PAYLOAD) ? "PAYLOAD" : "UNKNOWN",
            rule->msg ? rule->msg : "",
            rule->content ? rule->content : "(null)",
            rule->has_pcre ? rule->pcre_str : "(null)");
            rule = rule->next;
    }
    printf("=== Total Rules Loaded: %d ===\n", rule_count);
    // 룰 로딩 확인 완료 - end


    printf(" -> [OK] 위협 분석 스레드가 동작을 시작합니다.\n");

    while (1) {
        AnalyzingData* data = tsAnalyzingqPop(analyzingQueue);
        if (data == NULL) {
            if (!(*isRunning)) break;
            continue;
        }
        
        // 1. 룰 매칭
        Rule* rule = ruleSet.head;
        while (rule != NULL) {
            // 프로토콜이 다르면 이 룰은 검사할 필요가 없으므로 건너뛴다.
            if (rule->protocol != 0 && rule->protocol != data->ipHeader.protocol) {
                rule = rule->next;
                continue;
            }

            bool matched = false;

            uint8_t proto = data->ipHeader.protocol;
            // ICMP는 포트가 없으므로 dport를 0으로 처리
            uint16_t dport = (proto == IPPROTO_TCP || proto == IPPROTO_UDP) ? ntohs(data->tcpHeader.dstPort) : 0;
            uint16_t sport = (proto == IPPROTO_TCP || proto == IPPROTO_UDP) ? ntohs(data->tcpHeader.srcPort) : 0;
            
            // 프로토콜 별 분석
            // 패킷의 프로토콜/포트에 따라 적절한 분석 함수를 호출한다.
            // 서버 포트(dport)와 클라이언트 포트(sport)를 모두 고려하여 HTTP 트래픽 식별
            if (proto == IPPROTO_UDP && (dport == 53 || sport == 53)) {
                // 패킷이 DNS 요청이면, DNS 분석기를 사용
                matched = analyze_dns_payload(rule, data);
            } else if (proto == IPPROTO_TCP && (dport == 80 || sport == 80 || dport == 8080 || sport == 8080)) {
                // HTTP 요청/응답 트래픽 모두 HTTP 분석기로 처리
                matched = analyze_http_payload(rule, data);
            } else if (proto == IPPROTO_ICMP) {
                // 패킷이 ICMP이면, 일반 분석기를 사용 (ICMP는 평문 기반에 가까움)
                matched = analyze_generic_payload(rule, data);
            } else {
                // 그 외 모든 TCP, UDP 패킷은 일반 분석기로 처리
                matched = analyze_generic_payload(rule, data);
            } // http_payload 추가 필요함

            // --- 최종 매칭 결과 처리 ---
            if (matched) {
                printf("[Analyzer Thread] MATCHED! Rule ID: %d, Msg: %s\n", rule->id, rule->msg);
                AlertData* new_alert = (AlertData*)malloc(sizeof(AlertData));
                if (new_alert) {

                    strncpy(new_alert->msg, rule->msg, sizeof(new_alert->msg) - 1);
                    // ... new_alert에 IP, Port 등 상세 정보 채우기 ...
                    // tsAlertqPush(alertQueue, new_alert);
                }
            }
            rule = rule->next;
        }
        
        // 2. 사용한 데이터 메모리 해제
        if (data->data != NULL) {
            free(data->data); // 페이로드 해제
        }
        free(data); // analyzingData 자체 해제
    }

    rulesetDestroy(&ruleSet);
    printf("위협 분석 스레드가 종료됩니다.\n");
    return NULL;
}