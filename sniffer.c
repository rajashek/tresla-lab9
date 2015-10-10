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
    struct interface *sniff_interface = p->sniff_interface; //i/p interface
    struct route **routes = p->routes; //o/p interface
    
    char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
    pcap_t *handle;                     /* packet capture handle */
    
   //char filter_exp[64];                /* filter expression [3] */
   //strcpy(filter_exp,"ip");
   // sprintf(filter_exp, "ip and ether dst %.2x:%.2x:%.2x:%.2x:%.2x:%.2x", PRINT_MAC(sniff_interface->interface_macaddress));
    
  // struct bpf_program fp;             /* compiled filter program (expression) */
    
    struct got_packet_parameter got_packet_param;
    struct sockaddr_ll sa_in, sa_out[3];
    
    int i;

    /* open capture device */
    handle = pcap_open_live(sniff_interface->interface_name, SNAP_LEN, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", sniff_interface->interface_name, errbuf);
        exit(EXIT_FAILURE);
    }

    /* make sure we're capturing on an Ethernet device [2] */
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "%s is not an Ethernet\n", sniff_interface->interface_name);
        exit(EXIT_FAILURE);
    }

    if (pcap_setdirection(handle,PCAP_D_IN)!=0) {
        fprintf(stderr, "error in setting direction for %s\n", sniff_interface->interface_name);
        exit(EXIT_FAILURE);
    }

    /* compile the filter expression */
  /*if (pcap_compile(handle, &fp, filter_exp, 0, sniff_interface->interface_netaddress) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }*/
    
    /* apply the compiled filter */
   /*if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }*/
    
    // Open socket for sniffing interface
    sa_in.sll_family = PF_PACKET;
    sa_in.sll_ifindex = sniff_interface->interface_index;
    sa_in.sll_halen = ETHER_ADDR_LEN;
    sa_in.sll_protocol = htons(ETH_P_ALL);
    sa_in.sll_hatype = 0;
    sa_in.sll_pkttype = 0;
    memcpy(sa_in.sll_addr, sniff_interface->interface_macaddress, ETHER_ADDR_LEN);
    sniff_interface->sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    //printf(" sniff socket %d \n",sniff_interface->sockfd);
    if (sniff_interface->sockfd == -1) {
        fprintf(stderr, "Cannot create raw socket for sniffing interface in sniffer_thread\n");
        fprintf(stderr, "%s\n", strerror(errno));
	exit(-1);
    }
    else{
    	if (bind(sniff_interface->sockfd, (struct sockaddr *)&sa_in, sizeof(sa_in)) != 0){  //WARNING
        	fprintf(stderr, "Cannot bind to raw socket for sniffing interface in sniffer_thread\n");
	 	fprintf(stderr, "%s\n", strerror(errno));
    	}

    
    // Open socket for all output interface
    for (i=0; i<p->num_ifs; i++) {
        
        sa_out[i].sll_family = PF_PACKET;
        sa_out[i].sll_ifindex = (*routes)[i].interface.interface_index;
        //sa_out[i].sll_ifindex = 4;
        //printf(" opened socket ifindex %d \n",sa_out[i].sll_ifindex);
	sa_out[i].sll_halen = ETHER_ADDR_LEN;
        sa_out[i].sll_protocol = htons(ETH_P_ALL);
        sa_out[i].sll_hatype = 0;
        sa_out[i].sll_pkttype = 0;
        memcpy(sa_out[i].sll_addr, (*routes)[i].interface.interface_macaddress, ETHER_ADDR_LEN);
       	//printf("opened socket ifname %s \n",(*routes)[i].interface.interface_name); 
        (*routes)[i].interface.sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if ((*routes)[i].interface.sockfd == -1) {
            fprintf(stderr, "Cannot create raw socket for output interface in sniffer_thread\n");
            fprintf(stderr, "%s\n", strerror(errno));
            exit(-1);
	}
    	else{
       		//printf("opened socket  %d \n",(*routes)[i].interface.sockfd); 
        	if (bind((*routes)[i].interface.sockfd, (struct sockaddr *)&sa_out[i], sizeof(sa_out[i])) != 0){  //WARNING
       		     	fprintf(stderr, "Cannot bind to raw socket for output interface in sniffer_thread\n");
        	}
        }
    }
    }
    // Parse information to got_packet handler
    got_packet_param.sniff_interface = sniff_interface;
    //got_packet_param.num_routes = num_routes;
    got_packet_param.routes = routes;
    got_packet_param.num_ifs = p->num_ifs;
    //got_packet_param.arp_table_root = arp_table_root;


    pcap_loop(handle, -1, got_packet, (u_char *) &got_packet_param);

    
    /* cleanup */
   //pcap_freecode(&fp);
    pcap_close(handle);

    fprintf(stderr, "\nCapture complete.\n");
    
    return 0;
    
}


void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    
    // declare pointers to packet headers
    struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
    struct sniff_ip *ip;              /* The IP header */
    struct ifreq ifr;
    struct got_packet_parameter *got_packet_param;
    
    struct route *routes;
    
    int i;
    
    uint8_t op_interface;    
    // Note: header-> len is size of a whole ethernet frame
    
    got_packet_param = (struct got_packet_parameter *) args;
    int num_ifs = got_packet_param->num_ifs;
    routes = *got_packet_param->routes;

    // define ethernet header
    ethernet = (struct sniff_ethernet*) packet;
    
    // define/compute ip header offset
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    
    /*size_ip_header = IP_HL(ip)*4;
    if (unlikely(size_ip_header < 20)) {
        fprintf(stderr, "   * Invalid IP header length: %u bytes\n", size_ip_header);
        return;
    }*/
    
        memset(&ifr, 0, sizeof(struct ifreq));
        op_interface = ip->source_routing[ip->ttl];
        ifr.ifr_ifindex =(int) op_interface;
	ip->ttl++ ;
        //packet is not destined to router need to check the value of ttl and based on this
        // set the interface through which the packet needs to be pushed out
        struct sockaddr_ll addr={0};
        addr.sll_family=PF_PACKET;
        addr.sll_ifindex=ifr.ifr_ifindex;
        //addr.sll_ifindex=3;
        addr.sll_halen=ETHER_ADDR_LEN;
        addr.sll_protocol=htons(ETH_P_ALL);
        addr.sll_hatype = 0;
        addr.sll_pkttype = 0;
        memcpy(addr.sll_addr, ethernet->ether_shost, ETHER_ADDR_LEN);
        
        //print_payload(packet, header->caplen);
        int n;
	int snd_sock=-1;
	for(i=0;i<num_ifs;i++){
		if(routes[i].interface.interface_index==ifr.ifr_ifindex)
			snd_sock = routes[i].interface.sockfd;
	}
	if (snd_sock!=-1){
        	if( (n=send(snd_sock,packet, header->len, 0) < 0)) {
          		printf("%s",strerror(errno));
        	}
	}
        //printf("The packet was sent successfully. Size of packet= %d\n", header->len);
        return;
        
}
    

    // Decrease TTL
        
    /*if (unlikely(ip->ip_ttl == 0)) {
        // Send time exceeded icmp to the source
        icmp = (struct icmpheader *)(packet + SIZE_ETHERNET + size_ip_header);
        memcpy(((u_char *)icmp) + SIZE_ICMP, ip, size_ip_header+8);
        
        ip->ip_dst = ip->ip_src;       // Send to the source
        ip->ip_src = *((struct in_addr *) &sniff_interface->interface_ipaddress);
        ip->ip_p = 0x01;               // ICMP protocol
        ip->ip_tos = 0xc0;
        ip->ip_ttl = 64;
        
        icmp->type = ICMP_TIME_EXCEEDED;
        icmp->code = ICMP_NET_UNREACH;
        icmp->rest = 0x00;
        icmp->checksum = 0;
        icmp->checksum = ip_checksum((u_short *)(packet + SIZE_ETHERNET + size_ip_header), SIZE_ICMP + size_ip_header + 8);
        
        ip->ip_len = htons(size_ip_header + (SIZE_ICMP + size_ip_header + 8));
        ip->ip_sum = 0;
        ip->ip_sum = ip_checksum((u_short *) (packet + SIZE_ETHERNET), size_ip_header + (SIZE_ICMP + size_ip_header + 8));
        
        memcpy(ethernet->ether_dhost, ethernet->ether_shost, ETHER_ADDR_LEN);
        memcpy(ethernet->ether_shost, sniff_interface->interface_macaddress, ETHER_ADDR_LEN);
        
        if (unlikely((len = send(sniff_interface->sockfd, packet, SIZE_ETHERNET + size_ip_header + (SIZE_ICMP + size_ip_header + 8), 0)) < 0)) {
            fprintf(stderr, "Error: Cannot send ICMP time exceeded via %s to %s\n\n", sniff_interface->interface_name, ip_to_string(ip->ip_dst.s_addr));
            return;
        }
        
        return;
        
    }*/



/*short num_prefix_match(uint32_t ip_destination, uint32_t route_destination, uint32_t route_netmask) {
    short i;
    uint32_t prefix_match = ntohl(~(route_destination ^ ip_destination) & route_netmask);
    for(i=0; i<32; i++) {
        if (unlikely((0x80000000 & prefix_match) == 0)) break;
        prefix_match <<= 1;
    }
    return i;
}
u_short ip_checksum(u_short *ptr, int nbytes) {
    // Create Checksum of IP header (Modified version)
    // original: http://www.binarytides.com/raw-udp-sockets-c-linux/
    //
    long sum;
    u_short oddbyte = 0;
    
    sum=0;
    while(nbytes>1) {
        sum+=ntohs(*ptr++);
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }
    
    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    return htons((u_short)~sum);
}*/
