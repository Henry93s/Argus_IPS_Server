#ifndef COMMON_H
#define COMMON_H

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