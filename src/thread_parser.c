// thread_parser.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <signal.h>
#include <time.h>
#include "common.h"
#include "ts_packet_queue.h"
#include "sessionManager.h"
#include "thread_parser.h"
#include "ts_analyzing_queue.h"

// START : test print
void print_ip_header(const IPHeader* ip) {
    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];

    // IP 주소 문자열로 변환
    snprintf(src, INET_ADDRSTRLEN, "%u.%u.%u.%u",
             ip->srcIP[0], ip->srcIP[1], ip->srcIP[2], ip->srcIP[3]);
    snprintf(dst, INET_ADDRSTRLEN, "%u.%u.%u.%u",
             ip->dstIP[0], ip->dstIP[1], ip->dstIP[2], ip->dstIP[3]);

    printf("=== IP Header ===\n");
    printf("Version/IHL: 0x%02x\n", ip->verIHL);
    printf("TOS: 0x%02x\n", ip->tos);
    printf("Total Length: %u\n", ntohs(ip->length));
    printf("ID: %u\n", ntohs(ip->id));
    printf("Fragment Offset: 0x%04x\n", ntohs(ip->fragOffset));
    printf("TTL: %u\n", ip->TTL);
    printf("Protocol: %u\n", ip->protocol);
    printf("Checksum: 0x%04x\n", ntohs(ip->checksum));
    printf("Source IP: %s\n", src);
    printf("Destination IP: %s\n", dst);
}

void print_tcp_header(const TCPHeader* tcp) {
    printf("=== TCP Header ===\n");
    printf("Source Port: %u\n", ntohs(tcp->srcPort));
    printf("Destination Port: %u\n", ntohs(tcp->dstPort));
    printf("Sequence Number: %u\n", ntohl(tcp->seq));
    printf("ACK Number: %u\n", ntohl(tcp->ack));
    printf("Data Offset/Reserved: 0x%02x\n", tcp->data);
    printf("Flags: 0x%02x\n", tcp->flags);
    printf("Window Size: %u\n", ntohs(tcp->windowSize));
    printf("Checksum: 0x%04x\n", ntohs(tcp->checksum));
    printf("Urgent Pointer: %u\n", ntohs(tcp->urgent));
}
// END

// 파싱/분류 스레드 메인 함수
void* parser_thread_main(void* args) {
    ThreadArgs* thread_args = (ThreadArgs*)args;
    PacketQueue* packetQueue = thread_args->packetQueue;
    // AlertQueue* alertQueue = thread_args->alertQueue; // 나중에 분석 스레드로 넘길 때 필요
    volatile sig_atomic_t* isRunning = thread_args->isRunning;
    AnalyzingDataQueue* analyzingQueue = thread_args->analyzingQueue;

    // 파싱된 정보를 담을 임시 구조체 포인터
    EtherHeader* eth_header;
    IPHeader* ip_header;
    TCPHeader* tcp_header;
    UDPHeader* udp_header; // udp 추가
    ICMPHeader* icmp_header; // icmp 추가
    unsigned char* payload;
    unsigned int payload_len;

    // [3주차 목표] 세션 매니저 초기화
    SessionManager sessionManager;
    smInit(&sessionManager);
    thread_args->sessionManager = &sessionManager; // sessionManager 포인터 연결

    printf(" -> [OK] 파싱/분류 스레드가 동작을 시작합니다.\n");

    // 타임아웃 정리를 위한 시간 변수
    time_t last_cleanup_time = time(NULL);
    const int cleanup_interval = 60; // 60초마다 타임아웃 세션 정리함수 실행

    while (1) {
        // 1. PacketQueue에서 RawPacket을 꺼낸다 (블로킹)
        RawPacket* raw_packet = tsPacketqPop(packetQueue);
        if (raw_packet == NULL) {
            // if (*isRunning == 0) break; // 정상 종료
            // continue;
            break;
        }
        // if(*isRunning == 0) break;

        // printf("[Parser Thread DEBUG] Popped a packet, len: %u\n", raw_packet->len);

        // --- 2. L2 (Ethernet) 헤더 파싱 ---
        // => NFQUEUE 특성상 일반적으로 Ethernet 헤더는 없으므로 IP 헤더부터 파싱하도록 코드 변경 작업
        /*
        if (raw_packet->len < sizeof(EtherHeader)) {
            printf("[Parser Thread] Warning: 기본 Ethernet 헤더 크기보다 패킷 크기가 작음\n");
            // free(raw_packet->data);
            free(raw_packet);
            continue;
        }
        eth_header = (EtherHeader*)raw_packet->data;

         printf("[DEBUG] eth_header->type(raw): 0x%04x, ntohs: 0x%04x\n",
eth_header->type, ntohs(eth_header->type));

        // IP 패킷이 아니면 무시 (IPv4 타입: 0x0800)
        if (ntohs(eth_header->type) != 0x0800) {
            // free(raw_packet->data);
            free(raw_packet);
            continue;
        }
       */
       
        // --- 3. L3 (IP) 헤더 파싱 ---
        // => NFQUEUE 특성상 일반적으로 Ethernet 헤더는 없으므로 IP 헤더부터 파싱하도록 코드 변경 작업
        // ip_header = (IPHeader*)(raw_packet->data + sizeof(EtherHeader));
        
        // 남은 길이를 추적하는 변수
        unsigned int remaining_len = raw_packet->len;
        unsigned char* current_ptr = raw_packet->data;
        
        ip_header = (IPHeader*)current_ptr;
        if(remaining_len < sizeof(IPHeader)){ // 20
            fprintf(stderr, "[Parser Thread] Warning: 남은 패킷 길이가 IP 최소 헤더 길이(20)보다 작음 \n");
            free(raw_packet);
            continue;
        }

        unsigned int ip_header_len = (ip_header->verIHL & 0x0F) * 4;
        if (ip_header_len < 20 || remaining_len < ip_header_len) { // IP 헤더 최소 길이 체크
            fprintf(stderr, "[Parser Thread] Warning: 남은 데이터가 TCP 헤더 길이보다 짧음 \n");
            free(raw_packet);
            continue;
        }

        // test print code
        /*
        print_ip_header(ip_header);
        unsigned int ip_header_lens = (ip_header->verIHL & 0x0F) * 4;
        TCPHeader* tcp_headers = (TCPHeader*)((uint8_t*)ip_header + ip_header_lens);
        print_tcp_header(tcp_headers);
        */

        // 포인터와 남은 길이 업데이트
        current_ptr += ip_header_len;
        remaining_len -= ip_header_len;

        // --- 4-1. L4 (TCP) 헤더 파싱 ---
        if(ip_header->protocol == 6) { // TCP
            if (remaining_len < sizeof(TCPHeader)) { // 20
                fprintf(stderr, "[Parser Thread] Warning: 남은 패킷 길이가 TCP 최소 헤더 길이(20)보다 작음 \n");
                free(raw_packet);
                continue;
            }
            tcp_header = (TCPHeader*)current_ptr;
            unsigned int tcp_header_len = (tcp_header->data >> 4) * 4;
            if (tcp_header_len < 20 || remaining_len < tcp_header_len) {
                fprintf(stderr, "[Parser Thread] Warning: 남은 데이터가 TCP 헤더 길이보다 짧음 \n");
                free(raw_packet);
                continue;
            }

            // printf("[Parser DEBUG] TCP Packet 감지함! TCP header 파싱...\n");

            payload = current_ptr + tcp_header_len;
            payload_len = ntohs(ip_header->length) - ip_header_len - tcp_header_len;

            int reassembled_len = 0;
            unsigned char* reassembled_data = smHandlePacket(&sessionManager, ip_header, tcp_header, payload, &reassembled_len);

            AnalyzingData* newData = (AnalyzingData*)calloc(1, sizeof(AnalyzingData));
            if (newData) {
                memcpy(&newData->ipHeader, ip_header, sizeof(IPHeader));
                memcpy(&newData->tcpHeader, tcp_header, sizeof(TCPHeader));

                if(reassembled_data != NULL) {
                    newData->data = reassembled_data;
                    newData->len = reassembled_len;
                } else if (payload_len > 0){
                    newData->data = (unsigned char*)malloc(payload_len);
                    if(newData->data){
                        memcpy(newData->data, payload, payload_len);
                        newData->len = payload_len;
                    }
                }
                tsAnalyzingqPush(analyzingQueue, newData);
            } else {
                if (reassembled_data) free(reassembled_data);
            }
        // --- 4-2. L4 (UDP) 헤더 파싱 ---
        } else if (ip_header->protocol == 17) { // UDP
            if (remaining_len < sizeof(UDPHeader)) {
                fprintf(stderr, "[Parser Thread] Warning: 남은 패킷 길이가 UDP 최소 헤더 길이(8)보다 작음 \n");
                free(raw_packet);
                continue;
            }

            // printf("[Parser DEBUG] UDP Packet 감지함! UDP header 파싱...\n");

            udp_header = (UDPHeader*)current_ptr;
            unsigned int udp_header_len = sizeof(UDPHeader);
            
            payload = current_ptr + udp_header_len;
            payload_len = ntohs(udp_header->length) - udp_header_len;

            // printf("[Parser Thread] Parsed: UDP %u -> %u\n", ntohs(udp_header->srcPort), ntohs(udp_header->dstPort));

            AnalyzingData* newData = (AnalyzingData*)calloc(1, sizeof(AnalyzingData));
            if (newData) {
                memcpy(&newData->ipHeader, ip_header, sizeof(IPHeader));
                // AnalyzingData의 TCPHeader 구조체를 재활용하여 포트 정보 저장
                newData->tcpHeader.srcPort = udp_header->srcPort;
                newData->tcpHeader.dstPort = udp_header->dstPort;

                if (payload_len > 0) {
                    newData->data = (unsigned char*)malloc(payload_len);
                    if (newData->data) {
                        memcpy(newData->data, payload, payload_len);
                        newData->len = payload_len;
                    }
                }
                tsAnalyzingqPush(analyzingQueue, newData);
            }
        // --- 4-3. L3 (ICMP) 헤더 파싱 ---
        } else if (ip_header->protocol == 1) { // ICMP
            if (remaining_len < 4) { // ICMP 기본 헤더 4바이트
                fprintf(stderr, "[Parser Thread] Warning: 남은 패킷 길이가 ICMP 최소 헤더 길이(4)보다 작음 \n");
                free(raw_packet);
                continue;
            }

            // printf("[Parser DEBUG] ICMP Packet 감지함! ICMP header 파싱...\n");

            icmp_header = (ICMPHeader*)current_ptr;
            unsigned int icmp_header_len = 8; // Type 8/0 은 8바이트, 다른 경우는 다를 수 있으나 일반적으로 8로 계산
            if (remaining_len < icmp_header_len) icmp_header_len = 4;

            payload = current_ptr + icmp_header_len;
            payload_len = remaining_len - icmp_header_len;

            // printf("[Parser Thread] Parsed: ICMP Type=%u, Code=%u\n", icmp_header->type, icmp_header->code);

            AnalyzingData* newData = (AnalyzingData*)calloc(1, sizeof(AnalyzingData));
            if (newData) {
                memcpy(&newData->ipHeader, ip_header, sizeof(IPHeader));
                // ICMP는 포트가 없으므로 0으로 초기화
                newData->tcpHeader.srcPort = 0;
                newData->tcpHeader.dstPort = 0;

                if (payload_len > 0) {
                    newData->data = (unsigned char*)malloc(payload_len);
                    if (newData->data) {
                        memcpy(newData->data, payload, payload_len);
                        newData->len = payload_len;
                    }
                }
                tsAnalyzingqPush(analyzingQueue, newData);
            }

        } else { // 기타 프로토콜은 무시
            free(raw_packet);
            continue;
        }

        // --- 7. 원본 RawPacket 메모리 해제 ---
        // free(raw_packet->data);
        free(raw_packet);

        // 주기적인 타임아웃 세션 정리
        time_t current_time = time(NULL);
        if (difftime(current_time, last_cleanup_time) > cleanup_interval) {
            printf("[Parser Thread] Running session 정리...\n");
            smCleanupTimeout(&sessionManager);
            last_cleanup_time = current_time; // 마지막 정리 시간 갱신
            printf("[Parser Thread] Session 정리 완료. Active sessions: %ld\n", sessionManager.activeSessions);
        }
    }

    // 종료 전 세션 매니저 리소스 해제
    smDestroy(&sessionManager);
    printf("파싱/분류 스레드가 종료됩니다.\n");
    return NULL;
}