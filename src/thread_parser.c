// thread_parser.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <signal.h>
#include "common.h"
#include "ts_packet_queue.h"
#include "sessionManager.h"
#include "thread_parser.h"

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

    // 파싱된 정보를 담을 임시 구조체 포인터
    EtherHeader* eth_header;
    IPHeader* ip_header;
    TCPHeader* tcp_header;
    unsigned char* payload;
    unsigned int payload_len;

    // [3주차 목표] 세션 매니저 초기화
    SessionManager sessionManager;
    smInit(&sessionManager);

    printf(" -> [OK] 파싱/분류 스레드가 동작을 시작합니다.\n");

    while (1) {
        // 1. PacketQueue에서 RawPacket을 꺼낸다 (블로킹)
        RawPacket* raw_packet = tsPacketqPop(packetQueue);
        if (raw_packet == NULL) {
            // if (*isRunning == 0) break; // 정상 종료
            // continue;
            break;
        }
        // if(*isRunning == 0) break;

        printf("[Parser Thread DEBUG] Popped a packet, len: %u\n", raw_packet->len);

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
        ip_header = (IPHeader*)(raw_packet->data);
        unsigned int ip_header_len = (ip_header->verIHL & 0x0F) * 4;
        if (ip_header_len < 20) { // IP 헤더 최소 길이 체크
             printf("[Parser Thread] Warning: IP header 길이가 최소 길이(20) 보다 작음\n");
             // free(raw_packet->data);
             free(raw_packet);
             continue;
        }

        // TCP 패킷이 아니면 무시 (Protocol 타입: 6)
        if (ip_header->protocol != 6) {
             // free(raw_packet->data);
             free(raw_packet);
             continue;
        }

        print_ip_header(ip_header);
        unsigned int ip_header_lens = (ip_header->verIHL & 0x0F) * 4;
        TCPHeader* tcp_headers = (TCPHeader*)((uint8_t*)ip_header + ip_header_lens);
        print_tcp_header(tcp_headers);

        printf("[Parser DEBUG] TCP Packet 감지함! TCP header 파싱...\n");

        // --- 4. L4 (TCP) 헤더 파싱 ---
        tcp_header = (TCPHeader*)((unsigned char*)ip_header + ip_header_len);
        unsigned int tcp_header_len = (tcp_header->data >> 4) * 4;
        if (tcp_header_len < 20) { // TCP 헤더 최소 길이 체크
            printf("[Parser Thread] Warning: TCP header length 가 최소 길이보다 작음(20)\n");
            // free(raw_packet->data);
            free(raw_packet);
            continue;
        }
        
        // --- 5. L7 (Payload) 분리 ---
        payload = (unsigned char*)tcp_header + tcp_header_len;
        payload_len = ntohs(ip_header->length) - ip_header_len - tcp_header_len;

        printf("[Parser Thread] Parsed Packet: TCP %u -> %u\n", ntohs(tcp_header->srcPort), ntohs(tcp_header->dstPort));

        // [추가된 출력] 파싱된 정보 출력
        char srcIpStr[INET_ADDRSTRLEN], dstIpStr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, ip_header->srcIP, srcIpStr, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, ip_header->dstIP, dstIpStr, INET_ADDRSTRLEN);
        printf("[Parser Thread] Parsed: %s:%u -> %s:%u\n", 
               srcIpStr, ntohs(tcp_header->srcPort), 
               dstIpStr, ntohs(tcp_header->dstPort));

        // --- 6. 세션 매니저를 통해 세션 관리 및 스트림 재조합 ---
        int reassembled_len = 0;
        unsigned char* reassembled_data = smHandlePacket(&sessionManager, ip_header, tcp_header, payload, &reassembled_len);

        // [추가된 출력] 세션 매니저 상태 출력
        printf("[Parser Thread] Active sessions: %ld\n", sessionManager.activeSessions);

        if (reassembled_data != NULL) {
            printf("[Parser Thread] 스트림 재조합. Length: %d\n", reassembled_len);
            
            // TODO: 여기서 재조합된 데이터를 '분석 스레드'로 넘겨줘야 함.
            // (예: 새로운 큐를 사용하거나, 파싱된 정보 구조체를 만들어서 전달)
            
            free(reassembled_data); // 임시로 여기서 해제
        }

        // --- 7. 원본 RawPacket 메모리 해제 ---
        // free(raw_packet->data);
        free(raw_packet);
    }
    
    // 종료 전 세션 매니저 리소스 해제
    smDestroy(&sessionManager);
    printf("파싱/분류 스레드가 종료됩니다.\n");
    return NULL;
}