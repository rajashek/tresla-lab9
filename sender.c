#include "sniffer.h"
#include <assert.h>
#define APP_NAME "Tresla"
#define SIZE_ETHERNET 14
#define SIZE_TRESLA_LAYER3 sizeof(struct tresla_layer3)
#define ETHER_TYPE_DEFAULT 0x0001
void print_usage(void)
{

        printf("Usage: %s [interface][path]\n", APP_NAME);
        printf("\n");
        printf("Options:\n");
        printf("    interface    IP address of outgoing <interface> \n");
        printf("    path of send packets (source interface) \n");
        printf("\n");
	return;
}

int main(int argc, char **argv){
	char *interface = (char *)malloc(6*sizeof(char));
	char *path = (char *)malloc(20*sizeof(char));
	char *dup,*token;
	struct ethernet *eth_head;
	struct tresla_layer3 *tlayer3_head;
	void* snd_buffer = NULL;
        snd_buffer = (void*)malloc(BUF_SIZE);
	assert(interface!=NULL);
	struct sockaddr_ll sa;
	int sockfd=-1;
	struct ifreq ifr;
	uint8_t src_route_path[10];
	memset(snd_buffer, 0, BUF_SIZE);
	int no_of_hops=0,i=0;
	if(argc > 2){
		memcpy(interface,argv[1],strlen(argv[1]));
		printf("output interface %s \n", interface);
		memcpy(path,argv[2],strlen(argv[2]));
		dup = strdup(path);
		while ((token = strtok(dup, ",")) != NULL) {
        
        		src_route_path[no_of_hops] = (uint8_t)atoi(token);
        		dup = NULL;
			no_of_hops++;
    		}
	}
	else{
		print_usage();
		exit(0);
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
	for(i=0; i<no_of_hops; i++){
		tlayer3_head->source_routing[i]=src_route_path[i];
		tlayer3_head->source_routing[i]=src_route_path[i];
	}
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
