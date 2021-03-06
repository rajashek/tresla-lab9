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
#include "layers.h"
#include "receiver.h"	
typedef unsigned char uchar_t;

// Addressing
#define SOURCE_ADDR_LEN 2

struct layer2 {
    uint16_t original_source_addr;    
};

// Routing
#define MAX_HOPS	2
#define TYPE_UDP 1
#define SNAP_LEN 1518 //what is this value

struct layer3 {
    uint8_t  type;          // 0=layer4_icmp
    uint8_t  ttl;
    uint8_t  source_routing[MAX_HOPS];
};

struct layer4_udp {
    uint8_t  dport;
    uint8_t  sport;
    uint16_t len;
    uint32_t id;
};

void init_receiver(char* file_name,uint16_t from,struct interface output_interface) {

const u_char *sniff_packet;
struct layer2 *sniff_l2;
struct layer3 *sniff_l3;
struct layer4_udp *sniff_l4_udp;
long file_size = 0L;
unsigned char buffer[UDP_DATA_MAX_LENGTH];
unsigned char required_acks = FSCP_DEFAULT_NUMBER_OF_ACKS;
memset(buffer, 0, sizeof(buffer));    
unsigned long long chunk_id = 0L, total_chunks, chunks_ack_count = 0L;
unsigned char *chunks_ack;
FILE *file;
int sockfd, i;
struct sockaddr_ll sa_in;

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

numbytes = recvfrom(sockfd, buffer,1500, 0, NULL, NULL);
printf("listener: got packet %lu bytes\n", numbytes);

sniff_l2 = (struct layer2 *) buffer;
if (ntohs(sniff_l2->original_source_addr) == from) {
	sniff_l3 = (struct layer3 *) (buffer + sizeof(struct layer2));
	if (sniff_l3->type == TYPE_UDP){ 
                sniff_l4_udp = (struct layer4_udp *) (buffer + sizeof(struct layer2) + sizeof(struct layer3));
		buffer = (char*)(sniff_l4_udp + sizeof(struct layer4_udp) - sizeof(sniff_l4_udp->id));		
	}
}
memcpy(&chunk_id, buffer, FSCP_UDP_ID_BYTES);
memcpy(&file_size, buffer+FSCP_UDP_ID_BYTES, sizeof(file_size));
memcpy(&required_acks, buffer+FSCP_UDP_ID_BYTES+sizeof(file_size), 1);
/*if (strlen(file_name) == 0) {
        file_name = (char *) malloc(sizeof(char) * (recvlen-(FSCP_UDP_ID_BYTES+sizeof(file_size)+1)));
        memcpy(file_name, buffer+FSCP_UDP_ID_BYTES+sizeof(file_size)+1, (recvlen-(FSCP_UDP_ID_BYTES+sizeof(file_size)+1)));
    }*/
//CHECK
    total_chunks = (file_size / FSCP_UDP_DATA_BYTES) + ((file_size % FSCP_UDP_DATA_BYTES > 0)?1:0);

    fprintf(stdout, "        Filename: %s\n", file_name);
    fprintf(stdout, "        Filesize: %ld Bytes\n", file_size);
    fprintf(stdout, "   Required ACKs: %d\n", required_acks);
    fprintf(stdout, "  Size of chunks: %d Bytes\n", FSCP_UDP_DATA_BYTES);
    fprintf(stdout, "Number of chunks: %llu (0x%.6llx)\n", total_chunks, total_chunks);
    
    for(i=0; i<i<required_acks+1; i++) {
        send(sockfd, sniff_l2, 1500, 0);
	#ifdef _DEBUG
        fprintf(stdout, "[DEBUG] Send: ACK 0\n");
        #endif
    }
    
    // Open output file and create the buffer
    file = fopen(file_name, "w");
    
    // Initialize chuck acknowledgement bitmap
    chunks_ack = (unsigned char *) malloc(total_chunks/8 + 1);
    memset(chunks_ack, 0, total_chunks/8 + 1);
    
    // Chunk cache declaration
    unsigned char **chunk_cache;
    chunk_cache = (unsigned char **) malloc(sizeof(*chunk_cache) * total_chunks);

    // Start file writer thread
    struct receiver_thread_parameter params;
    params.total_chunks = &total_chunks;
    params.chunk_cache = &chunk_cache[0];
    params.chunks_ack = &chunks_ack;
    params.file = file;
    
    pthread_t thread;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
    
    if(pthread_create(&thread , &attr,  receiver_thread, (void*) &params) < 0) {
        fprintf(stderr, "Error: Can not create a thread for the receiver_thread in init_receiver()\n");
        exit(4);
    }
    
    while (chunks_ack_count < total_chunks) {
        
        recvlen = recvfrom(sockfd, buffer,1500, 0, NULL, NULL);
	if (recvlen != -1UL) {
	    sniff_l2 = (struct layer2 *) buffer;
	    if (ntohs(sniff_l2->original_source_addr) == from) {
        		sniff_l3 = (struct layer3 *) (buffer + sizeof(struct layer2));
			if (sniff_l3->type == TYPE_UDP) {
                		sniff_l4_udp = (struct layer4_udp *) (buffer + sizeof(struct layer2) + sizeof(struct layer3));
                	}	buffer = (char*)(sniff_l4_udp + sizeof(struct layer4_udp) - sizeof(sniff_l4_udp->id)); //buffer points to id now
            }    		
		
            memcpy(&chunk_id, buffer[sizeof(struct layer2) + sizeof(struct layer3) + sizeof(struct layer4_udp)+4], FSCP_UDP_ID_BYTES);
            if (chunk_id > 0) {
                
                #ifdef _DEBUG
                fprintf(stdout, "[DEBUG] Recv: %.6llx %lu\n", chunk_id, recvlen);
                #endif
                
                for(i=0; i<required_acks; i++) {
                    send(sockfd, sniff_l2, 1500, 0);
		    #ifdef _DEBUG	
                    fprintf(stdout, "[DEBUG] Send: ACK %.6llx\n", chunk_id);
                    #endif
                }
                
                if (!is_ack(&chunks_ack, chunk_id)) {
                    
                    // Create cache for a data chunk with structure: recvlen|chunk_id|chunk_data
                    chunk_cache[chunk_id-1] = (unsigned char*) malloc(sizeof(recvlen) + sizeof(unsigned char)*UDP_DATA_MAX_LENGTH);
                    // Put Packet length into cache
                    memcpy(chunk_cache[chunk_id-1], &recvlen, sizeof(recvlen));
                    // Put Chunk ID and data into cache
                    memcpy(chunk_cache[chunk_id-1] + sizeof(recvlen), buffer, recvlen);

                    
                    set_ack(&chunks_ack, chunk_id, true);
                    chunks_ack_count = chunks_ack_count + 1;

                }

            }
            else {
               // sendto(sockfd, buffer, FSCP_UDP_ID_BYTES, 0, (struct sockaddr *)&sndraddr, sndraddr_len);
		  send(sockfd, sniff_l2, FSCP_UDP_ID_BYTES, 0);
            }
        }
        
    }
    
    // Send FIN
    chunk_id = 0;
    chunk_id = ~chunk_id;
    for(i=0; i<required_acks+1; i++) {
        sendto(sockfd, &chunk_id, FSCP_UDP_ID_BYTES, 0, (struct sockaddr *)&sndraddr, sndraddr_len);
        #ifdef _DEBUG
        fprintf(stdout, "[DEBUG] Send: FIN\n");
        #endif
    }
    
    pthread_join(thread, NULL);

    fflush(file);
    fclose(file);
    
}

void *receiver_thread(void *params) {
    
    struct receiver_thread_parameter *p = (struct receiver_thread_parameter *) params;
    unsigned long long *total_chunks = p->total_chunks;
    unsigned char **chunk_cache = p->chunk_cache;
    unsigned char **chunks_ack = p->chunks_ack;
    FILE *file = p->file;
    
    unsigned long long chunk_written = 0L;
    
    size_t recvlen = 0L;
    
    struct timespec ts;
    ts.tv_sec = 0;
    ts.tv_nsec = 100*1000000L;
    
    while (chunk_written < *total_chunks) { //
        
        if (is_ack(chunks_ack, chunk_written+1)) {
            
            memcpy(&recvlen, chunk_cache[chunk_written], sizeof(recvlen));

            fseek(file, (chunk_written)*FSCP_UDP_DATA_BYTES, SEEK_SET);
            fwrite(chunk_cache[chunk_written] + sizeof(recvlen) + FSCP_UDP_ID_BYTES, recvlen - FSCP_UDP_ID_BYTES, 1, file);

            free(chunk_cache[chunk_written]);
            
            chunk_written++;
            
        }
        else {
            nanosleep(&ts, NULL);
        }
        
    }
    
    return 0;
}
