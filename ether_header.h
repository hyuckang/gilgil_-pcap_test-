#pragma once
#include "init.h"

#define ether_type_IPv4 0x0800
#define ether_type_ARP 0x0806
#define ETHER_ADDR_LEN  6   /* MAC Address Size */


/* Ethernet format */
struct ETHER_HEADER{
    uint8_t dst_addr[ETHER_ADDR_LEN]; /* Destination hardware address */
    uint8_t src_addr[ETHER_ADDR_LEN];  /* Source hardware address */
    uint16_t ether_type;   /* ehter type */
};
