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

#include "interface.h"
#include "route.h"
//#include "arp.h"
#include "utils.h"

#define SNAP_LEN 1518
#define SIZE_ETHERNET 2
#define SIZE_ICMP 8

//#define _VERBOSE

struct sniff_ethernet {
    u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
    u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
    u_short ether_type;                     /* IP? ARP? RARP? etc */
};

struct sniff_ip {
    uint8_t type; 
    uint8_t  ttl;
    uint8_t  source_routing[MAX_HOPS];
};    
//#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

struct icmpheader
{
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint32_t rest;
};

struct sniffer_thread_parameter {
    struct interface *sniff_interface;
    struct route **routes;
    int num_ifs;
};

struct got_packet_parameter {
    struct interface *sniff_interface;
    struct route **routes;
    int num_ifs;
};

void *sniffer_thread(void *params);
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
short num_prefix_match(uint32_t ip_destination, uint32_t route_destination, uint32_t route_netmask);
u_short ip_checksum(u_short *ptr, int nbytes);

#endif /* defined(__router__sniffer__) */
