//
//  main.c
//  custom_network
//
//  Created by Peera Yoodee on 10/9/15.
//  Copyright (c) 2015 Peera Yoodee. All rights reserved.
//

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include <pcap.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>

#include "../layers.h"
#include "../interface.h"

#define _VERBOSE

void print_usage();

int main(int argc, const char * argv[]) {
    
    int i = 0, sockfd, packetsize, datasize;
    char *dup, *token;
    
    struct interface output_interface;
    
    uchar_t *packet;
    struct layer2 *l2;
    struct layer3 *l3;
    struct layer4_udp *l4;
    struct iperf  *iperf;
    
    struct sockaddr_ll sa_in;
    ssize_t len;

    struct timespec spec, sleep;
    long double time_start, time_now;
    
    if (argc <= 8) {
        print_usage();
        exit(1);
    }
    
    // Read Packet Size
    if (strcmp("-packetsize", argv[7]) == 0) {
        packetsize = atoi(argv[8]);
        datasize = packetsize - (sizeof(struct layer2) + sizeof(struct layer3) + sizeof(struct layer4_udp));
        if (datasize <= 0) {
            packetsize = (sizeof(struct layer2) + sizeof(struct layer3) + sizeof(struct layer4_udp)) + 4;
            datasize = 4;
        }
        
        printf("Datasize = %d\n", datasize);
        packet = (uchar_t *) malloc(sizeof(struct layer2) + sizeof(struct layer3) + sizeof(struct layer4_udp) + datasize);
        memset(packet, 0x00, sizeof(struct layer2) + sizeof(struct layer3) + sizeof(struct layer4_udp));
        memset(packet + sizeof(struct layer2) + sizeof(struct layer3) + sizeof(struct layer4_udp), 0xff, datasize);
        
        l2 = (struct layer2 *) packet;
        l3 = (struct layer3 *) (packet + sizeof(struct layer2));
        l4 = (struct layer4_udp *) (packet + sizeof(struct layer2) + sizeof(struct layer3));
        iperf = (struct iperf *) (packet + sizeof(struct layer2) + sizeof(struct layer3) + sizeof(struct layer4_udp));
    }
    else {
        print_usage();
        exit(1);
    }
    
    // Read Source
    if (strcmp("-src", argv[1]) == 0) {
        l2->original_source_addr = htons((uint16_t) atoi(argv[2]));
    }
    else {
        print_usage();
        exit(1);
    }
    
    // Read Path
    if (strcmp("-path", argv[3]) == 0) {
        
        dup = strdup(argv[4]);
        while ((token = strtok(dup, ",")) != NULL) {
            
            l3->source_routing[i] = atoi(token);
            
            i++;
            dup = NULL;
            
            if (i > MAX_HOPS-1) break;
        }
        
        free(dup);
    }
    else {
        print_usage();
        exit(1);
    }
    
    // Read Interface Name
    if (strcmp("-dev", argv[5]) == 0) {
        strcpy(output_interface.interface_name, argv[6]);
        fill_interface_info(&output_interface);
    }
    else {
        print_usage();
        exit(1);
    }
    
    
    l3->type = TYPE_UDP;
    l3->ttl = 0;
    l4->dport = 255;
    l4->sport = 16;
    l4->len = htons(datasize);
    iperf->id = htonl(12);
    
    for (i = 0; i<packetsize; i++) {
        printf("%.2x ", packet[i]);
    }
    printf("\n");
    
    // Open socket for outgoing interface
    sa_in.sll_family = PF_PACKET;
    sa_in.sll_ifindex = output_interface.interface_index;
    sa_in.sll_halen = 0;
    sa_in.sll_protocol = htons(ETH_P_ALL);
    sa_in.sll_hatype = 0;
    sa_in.sll_pkttype = 0;
    
    sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd == -1) {
        fprintf(stderr, "Cannot create raw socket for outgoing interface\n");
        fprintf(stderr, "%s\n", strerror(errno));
    }
    if (bind(sockfd, (struct sockaddr *)&sa_in, sizeof(sa_in)) != 0) {
        fprintf(stderr, "Cannot bind to raw socket for outgoing interface\n");
    }
    
    clock_gettime(CLOCK_REALTIME, &spec);
    time_start = spec.tv_sec + spec.tv_nsec / 1.0e9;
    time_now = time_start;
    
    sleep.tv_sec = 0;
    sleep.tv_nsec = 10000;
    
    for (i=1; time_now-time_start<10; i++) {
        
        iperf->id = htonl(i);
        
        send(sockfd, packet, packetsize, 0);
        
        clock_gettime(CLOCK_REALTIME, &spec);
        time_now = spec.tv_sec + spec.tv_nsec / 1.0e9;
        
        if (i%4 == 0) {
            nanosleep(&sleep, NULL);
        }
        
    }
    
    iperf->id = 0xffffffff;
    for (i = 0; i<20; i++) {
        send(sockfd, packet, packetsize, 0);
    }
    
    return 0;
    
}

void print_usage() {
    fprintf(stderr, "Error: invalid options\n");
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "  iperf_send -src [saddr] -path [routing_path] -dev [interface_name] -packetsize \n");
    fprintf(stderr, "Example:\n");
    fprintf(stderr, "  iperf_send -src 1 -path 2,3 -dev eth0 -packetsize 1400\n");
}