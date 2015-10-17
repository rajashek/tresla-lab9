//
//  main.c
//  custom_network
//
//  Created by Peera Yoodee on 10/9/15.
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

#define SNAP_LEN 1518

void print_usage();

int main(int argc, const char * argv[]) {
    
    int i;
    
    uint16_t from;
    
    struct interface output_interface;
    
    short first = 1;
    uint32_t recv_max = 1, loss = 0;
    uint64_t recv_bytes = 0;
    
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    struct timespec spec;
    long double time_start, time_end;
    
    uchar_t *track;
    track = (uchar_t *) malloc(0x1000000);
    memset(track, 0, 0x1000000);
    
    if (argc <= 4) {
        print_usage();
        exit(1);
    }
    
    // Read From
    if (strcmp("-from", argv[1]) == 0) {
        from = (uint16_t) atoi(argv[2]);
    }
    else {
        print_usage();
        exit(1);
    }
    
    // Read Interface Name
    if (strcmp("-dev", argv[3]) == 0) {
        strcpy(output_interface.interface_name, argv[4]);
        fill_interface_info(&output_interface);
    }
    else {
        print_usage();
        exit(1);
    }
    
    /* open capture device */
    handle = pcap_open_live(output_interface.interface_name, SNAP_LEN, 1, 1000000, errbuf);
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
    struct layer3 *sniff_l3;
    struct layer4_udp *sniff_l4_udp;
    struct iperf *sniff_iperf;
    
    while (1) {
        
        sniff_packet = pcap_next(handle, &header);
        
        if (header.len < sizeof(struct layer2) + sizeof(struct layer3) + sizeof(struct layer4_udp) + sizeof(struct iperf)) {
            continue;
        }
        
        if (first) {
            clock_gettime(CLOCK_REALTIME, &spec);
            time_start = spec.tv_sec + spec.tv_nsec / 1.0e9;
            printf("Received the first packet\n");
            first = 0;
        }
        sniff_l2 = (struct layer2 *) sniff_packet;
        
        if (ntohs(sniff_l2->original_source_addr) == from) {
            sniff_l3 = (struct layer3 *) (sniff_packet + sizeof(struct layer2));
            
            if (sniff_l3->type == TYPE_UDP) {
                sniff_l4_udp = (struct layer4_udp *) (sniff_packet + sizeof(struct layer2) + sizeof(struct layer3));
                
                if (sniff_l4_udp->dport == 255) {
                    sniff_iperf = (struct iperf *) (sniff_packet + sizeof(struct layer2) + sizeof(struct layer3) + sizeof(struct layer4_udp));
                    
                    recv_bytes += ntohs(sniff_l4_udp->len);

                    
                    if (sniff_iperf->id == 0xffffffff) {
                        
                        clock_gettime(CLOCK_REALTIME, &spec);
                        time_end = spec.tv_sec + spec.tv_nsec / 1.0e9;
                        
                        printf("Received the last packet\n");
                        break;
                    }
                    else {
                    
                        *(track + ntohl(sniff_iperf->id)) = 1;
                        
                        if (ntohl(sniff_iperf->id) > recv_max) {
                            recv_max = ntohl(sniff_iperf->id);
                        }
                        
                    }

                    
                }
                
            }
        }
            
    }
    
    for (i=1; i<= recv_max; i++) {
        if (*(track+i) != 1) {
            printf(" loss: %.8x\n", i);
            loss ++;
        }
    }
    
    printf("%u (%.8x) max packet ID\n", recv_max, recv_max);
    printf("%d packets loss\n", loss);
    printf("%lu bytes received\n", recv_bytes);
    printf("%Lf seconds elapsed\n", time_end-time_start);
    printf("%Lf Mbit/sec\n", 8*recv_bytes/(time_end-time_start)/1e6);
    
    return 0;
    
}

void print_usage() {
    fprintf(stderr, "Error: invalid options\n");
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "  iperf_recv -from [saddr] -dev [interface_name]\n");
    fprintf(stderr, "Example:\n");
    fprintf(stderr, "  iperf_recv -from 1 -dev eth0\n");
}