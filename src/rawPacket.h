// rawpacket 구조체 정의
#include <stdint.h>
#ifndef RAWPACKET_H
#define RAWPACKET_H

#define MAX_PACKET_SIZE 1600

typedef struct {
    uint8_t data[MAX_PACKET_SIZE];
    uint16_t len;
} RawPacket;

#endif // RAWPACKET_H