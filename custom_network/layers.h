//
//  layers.h
//  custom_network
//
//  Created by Peera Yoodee on 10/6/15.
//  Copyright (c) 2015 Peera Yoodee. All rights reserved.
//

#ifndef custom_network_layers_h
#define custom_network_layers_h

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

typedef unsigned char uchar_t;

// Addressing
#define SOURCE_ADDR_LEN 2
struct layer2 {
    uint16_t saddr;
};

// Routing
#define MAX_HOPS	2
struct layer3 {
    uint8_t  ttl;
    uint8_t  source_routing[MAX_HOPS];
};

// Transport
struct layer4_icmp {
    uint16_t type;          // 0=Ping_Request 1=Ping_Reply
    uint16_t seq;
};

#define ID_LEN		3
#define MAX_LENGTH	1450
struct layer4 {
    uint8_t  port;          // sport & dport
    uchar_t  id[ID_LEN];
    uint16_t len;
};

#define GET_SPORT(a) 0x0f&(a >> 4)
#define GET_DPORT(a) 0x0f&a

#endif
