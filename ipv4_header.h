#pragma once
#include "init.h"

#define ipv4_protocol_TCP 0x06
#define ipv4_protocol_UDP 0x11
#define ipv4_protocol_ICMP 0x01
#define ipv4_addr_len 4

struct IPv4_HEADER{
    uint8_t   ver_and_hlen;  // header length and version
    uint8_t   tos;           // type of service
    uint16_t  tot_len;       // total length
    uint16_t  id;            // identification
    uint16_t  fragmentation; // fragmentation
    uint8_t   ttl;           // time to live
    uint8_t   protocol;      // protocol
    uint16_t  hdr_checksum;  // checksum
    uint8_t src_addr[ipv4_addr_len];       // source address
    uint8_t dst_addr[ipv4_addr_len];       // destination address
};
