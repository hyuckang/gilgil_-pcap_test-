#pragma once
#include "init.h"

void print_MAC_addr(char* str, uint8_t* mac_addr);
void print_IPv4_addr(char* str, uint8_t* ip_addr);
void print_port_num(char* str, uint16_t* port);
void print_tcp_data(u_char* tcp_data);

void print_MAC_addr(const char* str, uint8_t* mac_addr){
    printf("ether %s addr : %2x:%2x:%2x:%2x:%2x:%2x\n",str, *(mac_addr), *(mac_addr+1),*(mac_addr+2),*(mac_addr+3), *(mac_addr+4), *(mac_addr+5));
}

void print_IPv4_addr(const char* str, uint8_t* ip_addr){
    printf("IPv4 %s addr : %3d.%3d.%3d.%3d\n", str, *(ip_addr+0), *(ip_addr+1),*(ip_addr+2),*(ip_addr+3));
    //printf("IPv4 %s addr : %2x.%2x.%2x.%2x\n", str, *(ip_addr+0), *(ip_addr+1),*(ip_addr+2),*(ip_addr+3));
}

void print_port_num(const char* str, u_int16_t port){
    printf("%s port num : %5d\n",str,ntohs(port));
    //printf("%x\n\n",port);
}

void print_tcp_data(u_char* tcp_data, uint16_t data_size){
    for(size_t i=0; i<data_size; i++){
        printf("%2x ",*(tcp_data+i));
    }
}
