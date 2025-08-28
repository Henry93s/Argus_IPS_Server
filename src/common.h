#ifndef COMMON_H
#define COMMON_H

// rawpacket 구조체 정의
typedef struct {
    unsigned char* data;
    unsigned int len;
} RawPacket;

// 큐의 각 노드를 나타내는 구조체
typedef struct PacketNode {
    // 실제 패킷 데이터 포인터
    RawPacket* packet;
    // 다음 노드 (linkedlist)
    struct PacketNode* next;
} PacketNode;

// 스레드-안전 패킷 큐 중 PacketQueue 구조체
typedef struct {
    // 큐의 시작 (데이터를 꺼내는 곳)
    PacketNode* head;
    // 큐의 끝 (데이터를 넣는 곳)
    PacketNode* tail;
    int count;                      
    pthread_mutex_t lock;
    // 큐가 비어있거나 데이터가 추가될 때 대기/알림을 위한 조건 변수
    pthread_cond_t cond;
    // 프로그램 종료 신호를 받기 위한 포인터
    volatile sig_atomic_t* isRunning;
} PacketQueue;

// 각 스레드에 필요한 자원들의 포인터를 담는 구조체
typedef struct {
    PacketQueue* packetQueue;
    // AlertQueue* alertQueue;
    volatile sig_atomic_t* isRunning;
} ThreadArgs;

#pragma pack(push, 1)
typedef struct EtherHeader{
    unsigned char dstMac[6];
    unsigned char srcMac[6];
    unsigned short type;
} EtherHeader;

typedef struct IPHeader
{
    unsigned char verIHL;
    unsigned char tos;
    unsigned short length;
    unsigned short id;
    unsigned short fragOffset;
    unsigned char TTL;
    unsigned char protocol;
    unsigned short checksum;
    unsigned char srcIP[4];
    unsigned char dstIP[4];
} IPHeader;

// TCP Header 구조체 정의
typedef struct TCPHeader
{
    unsigned short srcPort;
    unsigned short dstPort;
    unsigned int seq;
    unsigned int ack;
    // data 필드에서 option 유무에 대해서 알아야
    // TCP 헤더의 정확한 offset 을 알 수 있음
    unsigned char data;
    unsigned char flags;
    unsigned short windowSize;
    unsigned short checksum;
    unsigned short urgent;
} TCPHeader;
#pragma pack(pop)

#endif // COMMON_H