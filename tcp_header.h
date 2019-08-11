#pragma once
#include "init.h"

struct TCP_HEADER{
    u_int16_t src_port;
    u_int16_t dst_port;
    u_int32_t seq_num;
    u_int32_t ack_num;
    u_int16_t hdr_len_and_flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_ptr;
};
