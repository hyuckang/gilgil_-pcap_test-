#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

struct MyPacketData{
    // Ether Info
    const u_char* DstMac;
    const u_char* SrcMac;
    const u_char* EtherType;
    // IP Info
    const uint8_t* IPH_len;
    const u_char* IPtot_len;    // 2byte
    const u_char* L4_Protocol;
    const u_char* SrcIP;
    const u_char* DstIP;
    // L4 Info
    const u_char* SrcPort;
    const u_char* DstPort;
    const u_char* L4H_len;
    // TCP Data
    const u_char* dataStart;

};
void print_MAC(const u_char* MAC,const char* str){
    printf("%s : %2x:%2x:%2x:%2x:%2x:%2x\n",str,*MAC,*(MAC+1),*(MAC+2),*(MAC+3),*(MAC+4),*(MAC+5));
    return;
}
void print_IP(const u_char* IP, const char* str){
    printf("%s : %3d:%3d:%3d:%3d\n",str,*IP,*(IP+1),*(IP+2),*(IP+3));
    return;
}
void print_Port(const u_char* Port,const char* str){
    printf("%s : %d\n",str,((*Port)<<8) | *(Port+1));
    return;
}
void print_TCPdata(const u_char* TCPstart,const u_char* IPtot_len,const u_char* IPH_len, const u_char* L4H_len){
    // TCP data length = IP total length - IP Header length - TCP Header length
    uint16_t IPtot = ((*IPtot_len)<<8 | *(IPtot_len+1));
    uint8_t IPH = ((*IPH_len)&0x0F)*4;
    uint8_t L4H = (((*L4H_len) & 0xF0)>>4) *4;
    uint16_t TCP_data_LEN = IPtot-IPH-L4H;

    printf("IP Total Length : %5d      IP Header len : %5d\n",IPtot,IPH);
    printf("TCP Header length : %4d    TCP data len : %5d\n",L4H,TCP_data_LEN);

    if(TCP_data_LEN == 0x0000){
        printf("Do not have TCP data.\n\n");
        return;
    }else if(TCP_data_LEN > 0x000A){
        for(int i=0;i<10;i++){
            printf("%2x ",*TCPstart);
            TCPstart = TCPstart+1;
        }
    }
    else {
        for(uint16_t i=0x0000;i<TCP_data_LEN;i++){
            printf("%2x ",*TCPstart);
            TCPstart = TCPstart+1;
        }
    }
    printf("\n\n");
    return;
}
void PrintData(struct MyPacketData* MPD){
    printf("=== L2 INFO ===\n");
    print_MAC(MPD->DstMac,"DstMac");
    print_MAC(MPD->SrcMac,"SrcMac");
    if(*(MPD->EtherType)==0x08 && *(MPD->EtherType+1)==0x00){
        printf("ETher Type : IPv4\n");
    }else{
        printf("Do Not Use IPv4\n");
        return;
    }

    printf("=== L3 INFO ===\n");
    printf("IP Header LEN : %d\n",(*MPD->IPH_len& 0x0F)*4);
    print_IP(MPD->SrcIP,"SrcIP");
    print_IP(MPD->DstIP,"DstIP");

    printf("=== L4 INFO ===\n");
    print_Port(MPD->SrcPort,"SrcPort");
    print_Port(MPD->DstPort,"DstPort");
    if(*(MPD->L4_Protocol)==(0x06)){
        printf("L4 Protocol : TCP\n");
    }
    else if(*(MPD->L4_Protocol)==(0x11)){
        printf("L4 Protocol : UDP\n");
        return;
    }
    printf("TCP Header LEN : %d\n",((*MPD->L4H_len & 0xF0)>>4)*4);

    printf("=== TCP data ===\n");
    print_TCPdata(MPD->dataStart,MPD->IPtot_len,MPD->IPH_len,MPD->L4H_len);

    return;
}
void MY_Data(const u_char* packet_data){
    struct MyPacketData MPD;
    MPD.DstMac = packet_data;
    MPD.SrcMac = packet_data+6;
    MPD.EtherType = packet_data+12;

    MPD.IPH_len = packet_data+14;
    MPD.IPtot_len = packet_data+16;
    MPD.L4_Protocol = packet_data+23;
    MPD.SrcIP = packet_data+26;
    MPD.DstIP = packet_data+30;
    MPD.SrcPort = packet_data+34;
    MPD.DstPort = packet_data+36;

    MPD.L4H_len = packet_data+46;
    MPD.dataStart = packet_data+54;

    // Calculate IP Hedaer Length
    for(uint8_t i=0x05; i<((*MPD.IPH_len) & 0x0F); i++){
            MPD.SrcPort = MPD.SrcPort+4;
            MPD.DstPort = MPD.DstPort+4;
            MPD.L4H_len = MPD.L4H_len+4;
            MPD.dataStart = MPD.dataStart+4;
    }

    // Calculate TCP Header Length
    for(uint8_t i=0x05; i<(((*MPD.L4H_len)&0xF0)>>4); i++){
            MPD.dataStart = MPD.dataStart+4;
    }

    PrintData(&MPD);
    return;
}

int main(int argc, char* argv[]) {
    char track[] = "개발";
    char name[] = "강동혁";
    printf("[bob8][%s]pcap_test[%s]\n\n", track, name);

    if (argc != 2) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }

     while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;
        printf("\n%u bytes captured\n", header->caplen);
        MY_Data(packet);
    }

    pcap_close(handle);
    return 0;
}
