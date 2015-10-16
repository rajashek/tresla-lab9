//
//  sniffer.c
//  router
//
//  Modified by Peera Yoodee on 9/30/15.
//  Original code from http://www.tcpdump.org/sniffex.c
//

#include "sniffer.h"

void *sniffer_thread(void *params) {
    
    struct sniffer_thread_parameter *p = (struct sniffer_thread_parameter *) params;
    struct interface *interfaces = *p->interfaces;
    int num_interfaces = p->num_interfaces;
    int sniff_interface = p->sniff_interface;
    int max_interface_index = -1;

    char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
    pcap_t *handle;                     /* packet capture handle */
    
    int i, *sockfd;
    struct sockaddr_ll sa_out[num_interfaces];
    
    struct got_packet_parameter got_packet_param;

    // Open Capture Device
    handle = pcap_open_live(interfaces[sniff_interface].interface_name, SNAP_LEN, 1, 0, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", interfaces[sniff_interface].interface_name, errbuf);
        exit(EXIT_FAILURE);
    }

    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "%s is not an Ethernet\n", interfaces[sniff_interface].interface_name);
        exit(EXIT_FAILURE);
    }

    if (pcap_setdirection(handle,PCAP_D_IN)!=0) {
        fprintf(stderr, "error in setting direction for %s\n", interfaces[sniff_interface].interface_name);
        exit(EXIT_FAILURE);
    }

    // Prepare socket for all output interface
    for (i=0; i<num_interfaces; i++) {
        sa_out[i].sll_family = PF_PACKET;
        sa_out[i].sll_ifindex = interfaces[i].interface_index;
        sa_out[i].sll_halen = 0;
        sa_out[i].sll_protocol = htons(ETH_P_ALL);
        sa_out[i].sll_hatype = 0;
        sa_out[i].sll_pkttype = 0;
        
        if (max_interface_index < interfaces[i].interface_index) {
            max_interface_index = interfaces[i].interface_index;
        }
    }
    
    // Allocate socket array to use as a key-value data structure
    sockfd = (int *) malloc(sizeof(int) * (max_interface_index + 1));
    memset(sockfd, 0xff, sizeof(int) * (max_interface_index + 1));

    // Open Socket for all output interfaces
    for (i=0; i<num_interfaces; i++) {
        
        if ((sockfd[interfaces[i].interface_index] = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
            fprintf(stderr, "Error: cannot create raw socket in sniffer_thread()\n");
            exit(1);
        }
        
        if(bind(sockfd[interfaces[i].interface_index] ,(struct sockaddr *) &sa_out[i], sizeof(sa_out[i])) <0) {
            fprintf(stderr, "Error bind raw socket failed in sniffer_thread()\n");
            exit(3);
        }

    }
    
    got_packet_param.max_interface_index = max_interface_index;
    got_packet_param.sockfd = &sockfd;
    
    pcap_loop(handle, -1, got_packet, (u_char *) &got_packet_param);

    // Clean up
    pcap_close(handle);
    
    return 0;
    
}


void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

    struct got_packet_parameter *got_packet_param = (struct got_packet_parameter *) args;
    int max_interface_index = got_packet_param->max_interface_index;
    int *sockfd = *got_packet_param->sockfd;
    int next_interface_index;
    
    struct layer3 *packet_l3 = (struct layer3 *)(packet + sizeof(struct layer2));
    
    if (unlikely(packet_l3->ttl >= MAX_HOPS)) {
        return;
    }
    
    // Get the port number to route to the next hop
    next_interface_index = packet_l3->source_routing[packet_l3->ttl];
    
    // Drop the packet if this is the invalid port number for sure
    if (unlikely(next_interface_index > max_interface_index)) {
        return;
    }
    
    packet_l3->ttl = packet_l3->ttl + 1;
    
    // Drop the packet because the port number is invalid
    if (unlikely(sockfd[next_interface_index] == -1)) {
        return;
    }

    
    // Forward the packet
    if(unlikely(send(sockfd[next_interface_index], packet, header->len, 0) < 0)) {
        fprintf(stderr, "Cannot forward packet !\n");
    }
    
    
    return;
    
}
    
