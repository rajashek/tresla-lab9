//
//  main.c
//  custom_network
//
//  Created by Peera Yoodee on 10/6/15.
//  Copyright (c) 2015 Peera Yoodee. All rights reserved.
//

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>

#include "../layers.h"
#include "../interface.h"

#define _VERBOSE

#define SNAP_LEN 1518

void print_usage();

int main(int argc, const char * argv[]) {
    
    int i = 0, sockfd;
    char *dup, *token;
    
    struct interface output_interface;
    
    uchar_t packet[sizeof(struct layer2) + sizeof(struct layer3)];
    memset(packet, 0, sizeof(packet));
    struct layer2 *l2 = (struct layer2 *) packet;
    struct layer3 *l3 = (struct layer3 *) (packet + sizeof(struct layer2));
    
    struct sockaddr_ll sa_in;
    
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    if (argc <= 6) {
        print_usage();
        exit(1);
    }
    
    // Read Source
    if (strcmp("-src", argv[1]) == 0) {
        l2->saddr = htons((uint16_t) atoi(argv[2]));
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
    
    
    /* open capture device */
    handle = pcap_open_live(output_interface.interface_name, SNAP_LEN, 1, 0, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", output_interface.interface_name, errbuf);
        exit(EXIT_FAILURE);
    }
    
    /* make sure we're capturing on an Ethernet device */
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "%s is not an Ethernet\n", output_interface.interface_name);
        exit(EXIT_FAILURE);
    }

    struct pcap_pkthdr header;
    const u_char *sniff_packet;
    
    struct layer2 *sniff_l2;
    struct layer4_icmp *sniff_icmp;
    
    while (1) {
        
        sniff_packet = pcap_next(handle, &header);
        
        if (header.len >= (sizeof(struct layer2) + sizeof(struct layer3) + sizeof(struct layer4_icmp))) {
            
            sniff_l2 = (struct layer2 *) sniff_packet;
            sniff_icmp = (struct layer4_icmp *) (sniff_packet + sizeof(struct layer2) + sizeof(struct layer3));
            
            if (ntohs(sniff_l2->saddr) != ntohs(l2->saddr)) { // Source Address is not me
                if (ntohs(sniff_icmp->type) == 0) {
                    
                    printf("Ping from %d seq=%d\n", ntohs(sniff_l2->saddr), ntohs(sniff_icmp->seq));
                    
                    memcpy((u_char *) sniff_packet, packet, sizeof(struct layer2) + sizeof(struct layer3));
                    sniff_icmp->type = htons(1);
                    
                    send(sockfd, sniff_packet, header.len, 0);
                }
            }
            
        }
        
    }
    
    return 0;
}

void print_usage() {
    fprintf(stderr, "Error: invalid options\n");
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "  pong -src [saddr] -path [routing_path] -dev [interface_name]\n");
    fprintf(stderr, "Example:\n");
    fprintf(stderr, "  pong -src 1 -path 2,3 -dev eth0\n");
}