#pragma once

#include <stdint.h>

struct ETH{
    uint8_t D_Mac[6];
    uint8_t S_Mac[6];
    uint8_t EType[2];
    uint8_t hardwareType[2];
    uint8_t protocolType[2];
    uint8_t hardwareSize;
    uint8_t protocolSize;
    uint8_t opCode[2];
    uint8_t senderMac[6];
    uint8_t senderIp[4];
    uint8_t targetMac[6];
    uint8_t targetIp[4];

}__attribute__((packed));
