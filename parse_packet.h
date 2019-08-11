#pragma once
#include "init.h"

void parse_packet(const u_char* packet_data);

void parse_pakcet(const u_char* packet_data){

    ETHER_HEADER ether_hdr;
    IPv4_HEADER ipv4_hdr;
    TCP_HEADER tcp_hdr;
    u_char tcp_data[10];

    /* L2 header parse and L2 Info print */
    memcpy(&ether_hdr, packet_data, sizeof(ether_hdr));
    printf("=== L2 Info ===\n");
    print_MAC_addr("Dst", ether_hdr.dst_addr);
    print_MAC_addr("Src", ether_hdr.src_addr);


    /* L3 header parse and L3 Info print */
    if(ntohs(ether_hdr.ether_type) == ether_type_IPv4){
        memcpy(&ipv4_hdr, packet_data + sizeof (ether_hdr), sizeof(ipv4_hdr));
        printf("=== L3 Info ===\n");
        print_IPv4_addr("Src",ipv4_hdr.src_addr);
        print_IPv4_addr("Dst",ipv4_hdr.dst_addr);
    }else{
        printf("Do not use IPv4\n");
        return;
    }

    /* Calculate ip header size */
    uint8_t ipv4_hdr_size = (ipv4_hdr.ver_and_hlen & 0x0F) * 4;

    /* TCP header parse and L4 Info print */
    if(ipv4_hdr.protocol == ipv4_protocol_TCP){
        memcpy(&tcp_hdr, packet_data + sizeof(ether_hdr) + ipv4_hdr_size, sizeof(TCP_HEADER));
        printf("IPv4 hedar size : %d\n", ipv4_hdr_size);
        printf("=== L4 Info===\n");
        print_port_num("Src",tcp_hdr.src_port);
        print_port_num("Dst",tcp_hdr.dst_port);
    }else{
        printf("Do not use TCP\n");
        return;
    }


    /* Calculate TCP header size and TCP data size */
    uint16_t tcp_hdr_size = (((ntohs(tcp_hdr.hdr_len_and_flags))>>12))*4;
    uint16_t tcp_data_size = ntohs(ipv4_hdr.tot_len) - ipv4_hdr_size - tcp_hdr_size;
    printf("Tcp_hdr_size : %2d\n",tcp_hdr_size);
    printf("Tcp_data_size : %d\n",tcp_data_size);


    /* TCP data parse and TCP data print */
    if(tcp_data_size > 10) tcp_data_size = 10;
    memcpy(&tcp_data, packet_data + sizeof(ether_hdr) + ipv4_hdr_size + tcp_hdr_size, tcp_data_size);
    if(tcp_data_size ==0 ){
        printf("Do not hava TCP data\n");
    }
    else{
        printf("TCP data %d bytes\n",tcp_data_size);
        print_tcp_data(tcp_data, tcp_data_size);
    }
    printf("\n");

}
