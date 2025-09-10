#ifndef COMMON_H
#define COMMON_H
#include "rawPacket.h"
#include "shm_ipc.h"
#include <signal.h>

// Header 구조체 정의들
#pragma pack(push, 1)
typedef struct EtherHeader{
    uint8_t dstMac[6];
    uint8_t srcMac[6];
    uint16_t type;
} EtherHeader;

// IP Header 구조체 정의
typedef struct {
    uint8_t verIHL;
    uint8_t tos;
    uint16_t length;
    uint16_t id;
    uint16_t fragOffset;
    uint8_t TTL;
    uint8_t protocol;
    uint16_t checksum;
    uint8_t srcIP[4];
    uint8_t dstIP[4];
} IPHeader;

// TCP Header 구조체 정의
typedef struct {
    uint16_t srcPort;
    uint16_t dstPort;
    uint32_t seq;
    uint32_t ack;
    // data 필드에서 option 유무에 대해서 알아야
    // TCP 헤더의 정확한 offset 을 알 수 있음
    uint8_t data;   // Data offset & reserved bits
    uint8_t flags;
    uint16_t windowSize;
    uint16_t checksum;
    uint16_t urgent;
} TCPHeader;

// UDP Header 구조체 정의
typedef struct {
    uint16_t srcPort;
    uint16_t dstPort;
    uint16_t length;
    uint16_t checksum;
} UDPHeader;

// ICMP Header 구조체 정의
typedef struct {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint32_t rest_of_header;
} ICMPHeader;
#pragma pack(pop)


// packetQueue.h - start

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
// packetQueue.h - end

// sessionManager.h - Start
#define HASH_TABLE_SIZE 65536
typedef enum {
    TCP_STATE_NONE,
    TCP_SYN_SENT,
    TCP_ESTABLISHED,
    TCP_FIN_WAIT,
    TCP_CLOSED
} TcpState;
typedef struct TCPFragment {
    uint32_t seq;
    uint32_t len;
    unsigned char* data;
    struct TCPFragment* next;
} TCPFragment;
typedef struct SessionInfo {
    uint32_t srcIp;
    uint32_t dstIp;
    uint16_t srcPort;
    uint16_t dstPort;
    TcpState state;
    time_t startTime;
    time_t lastActiveTime;
    long fwdPacketCount;
    long bwdPacketCount;
    long fwdTotalBytes;
    long bwdTotalBytes;
    uint32_t nextFwdSeq;
    uint32_t nextBwdSeq;
    TCPFragment* fwdFragments;
    TCPFragment* bwdFragments;
    struct SessionInfo* next;
} SessionInfo;
typedef struct SessionManager {
    SessionInfo* buckets[HASH_TABLE_SIZE];
    pthread_mutex_t lock;
    long activeSessions;
} SessionManager;

// sessionManager.h -- End

// analyzingDataQueue -- start
// 파싱/분류 스레드 -> 분석 스레드로 넘겨줄 데이터 구조체
typedef struct {
    // 세션 식별을 위한 4-tuple 정보
    uint32_t srcIp;
    uint32_t dstIp;
    uint16_t srcPort;
    uint16_t dstPort;

    // 분석에 필요한 헤더 정보
    IPHeader ipHeader;
    TCPHeader tcpHeader;
    
    unsigned char* data; // 재조합된 페이로드 데이터
    unsigned len; // 재조합된 페이로드 길이
} AnalyzingData;

// (임시용) 분석 결과를 담을 Alert 구조체
typedef struct {
    char msg[512];
    // 기타 경고 데이터들...
} AlertData;

// 큐의 각 노드를 나타내는 구조체
typedef struct AnalyzingNode {
    // 실제 패킷 데이터 포인터
    AnalyzingData* analyzingData;
    // 다음 노드 (linkedlist)
    struct AnalyzingNode* next;
} AnalyzingNode;

// 스레드-안전 패킷 큐 중 AnalyzingDataQueue 구조체
typedef struct {
    // 큐의 시작 (데이터를 꺼내는 곳)
    AnalyzingNode* head;
    // 큐의 끝 (데이터를 넣는 곳)
    AnalyzingNode* tail;
    int count;                      
    pthread_mutex_t lock;
    // 큐가 비어있거나 데이터가 추가될 때 대기/알림을 위한 조건 변수
    pthread_cond_t cond;
    // 프로그램 종료 신호를 받기 위한 포인터
    volatile sig_atomic_t* isRunning;
} AnalyzingDataQueue;
// analyzingDataQueue -- end

// 각 스레드에 필요한 자원들의 포인터를 담는 구조체
typedef struct {
    PacketQueue* packetQueue;
    // AlertQueue* alertQueue;
    SessionManager* sessionManager;
    volatile sig_atomic_t* isRunning;
    AnalyzingDataQueue* analyzingQueue;
    SharedPacketBuffer* sharedBuffer; // 
} ThreadArgs;

#endif // COMMON_H
