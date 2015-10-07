#include "sniffer.h"
#include <assert.h>
#define SIZE_ETHERNET 14
#define SIZE_TRESLA_LAYER3 sizeof(struct tresla_layer3)
#define ETHER_TYPE_DEFAULT 0x0001
int main(int argc, char **argv){
	char *interface = (char *)malloc(6*sizeof(char));
	struct ethernet *eth_head;
	struct tresla_layer3 *tlayer3_head;
	void* snd_buffer = NULL;
        snd_buffer = (void*)malloc(BUF_SIZE);
	assert(interface!=NULL);
	struct sockaddr_ll sa;
	int sockfd=-1;
	struct ifreq ifr;
	memset(snd_buffer, 0, BUF_SIZE);
	if(argc > 1){
		memcpy(interface,argv[1],strlen(argv[1]));
		printf("output interface %s \n",interface);
	}
	sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_802_3));	
	if(sockfd == -1) {
        fprintf(stderr, "Cannot create raw socket for sending data\n");
        fprintf(stderr, "%s\n", strerror(errno));
    	}
	strcpy(ifr.ifr_name, interface);
        if (ioctl(sockfd, SIOCGIFINDEX, &ifr) == -1) {
                close(sockfd);
                perror("SIOCGIFINDEX");
                exit(1);
        }
	sa.sll_family = PF_PACKET;
        sa.sll_ifindex = ifr.ifr_ifindex;
        sa.sll_halen = ETHER_ADDR_LEN;
        sa.sll_protocol = htons(ETH_P_802_3);
        sa.sll_hatype = 0;
        sa.sll_pkttype = 0;
	if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) == -1) {
                close(sockfd);
                perror("SIOCGIFHWADDR");
                exit(1);
        }
	eth_head = (struct ethernet*)(snd_buffer);
	memset(eth_head->ether_dhost, 0xFF, (6 * sizeof(u_char)));
	memcpy(eth_head->ether_shost,ifr.ifr_hwaddr.sa_data,sizeof(u_char)*6);
	eth_head->ether_type = htons(ETHER_TYPE_DEFAULT);
	tlayer3_head = (struct tresla_layer3*)(snd_buffer + SIZE_ETHERNET);
	tlayer3_head->ttl = 0x00;
	tlayer3_head->source_routing[0]=0x04;
	tlayer3_head->source_routing[1]=0x01;
	
	uint16_t rvalue;
	rvalue = sendto(sockfd, snd_buffer, BUF_SIZE, 0,(struct sockaddr *)&sa, sizeof(sa));
        if( rvalue < 0 )
        {
                perror("sendto");
                close(sockfd);
                exit(1);
        }		
	printf("succesfully sent a tresla packet\n");
	return 0;
}
