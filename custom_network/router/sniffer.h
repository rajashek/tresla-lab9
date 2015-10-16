//
//  sniffer.h
//  router
//
//  Created by Peera Yoodee on 9/30/15.
//

#ifndef __router__sniffer__
#define __router__sniffer__

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include <pcap.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <net/route.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <netinet/ip_icmp.h>

#include <pthread.h>

#include "../interface.h"
#include "../layers.h"

#define SNAP_LEN 1518

//#define _VERBOSE

#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)


struct sniffer_thread_parameter {
    struct interface **interfaces;
    int num_interfaces;
    int sniff_interface;
};

struct got_packet_parameter {
    int max_interface_index;
    int **sockfd;
};

void *sniffer_thread(void *params);
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

#endif /* defined(__router__sniffer__) */
