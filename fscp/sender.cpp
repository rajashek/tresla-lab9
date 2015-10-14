//
//  sender.cpp
//  fscp
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

#include "layers.h"
#include "interface.h"



#include "sender.h"

void init_sender(uint16_t src, uint16_t dest, uint8_t *src_routing, uint8_t port, struct interface *dev,  FILE *file, long file_size, const char *file_name, unsigned char required_acks) {

    int sockfd, i;
    size_t recvlen;
    
    unsigned long long chunk_id = 0ULL, total_chunks, chunks_ack_count = 0L, j;
    unsigned long long chunk_id_first_unacked = 1L;
    unsigned long long chunk_id_last_cached = 0L;
    unsigned char *chunks_ack;
    
    unsigned char buffer_udp[UDP_DATA_MAX_LENGTH];
    unsigned char *buffer=buffer_udp;
    unsigned char *recvbuffer = (unsigned char*)malloc (UDP_DATA_MAX_LENGTH*sizeof(unsigned char));
    memset(recvbuffer,0x00,UDP_DATA_MAX_LENGTH);
    size_t file_read_len;
    
    //struct timeval tv;
    /* raw socket parameters*/
    struct layer2 *l2;
    struct layer3 *l3;
    struct layer4_udp *l4;
    struct sockaddr_ll sa_in;
    memset(buffer, 0x00, sizeof(struct layer2) + sizeof(struct layer3) + sizeof(struct layer4_udp));
    memset(buffer + sizeof(struct layer2) + sizeof(struct layer3) + sizeof(struct layer4_udp), 0x00, FSCP_UDP_DATA_BYTES);
    size_t header_size;
    header_size = sizeof(struct layer2) + sizeof(struct layer3) + sizeof(struct layer4_udp);
    l2 = (struct layer2 *) buffer;
    l3 = (struct layer3 *) (buffer + sizeof(struct layer2));
    l4 = (struct layer4_udp *) (buffer + sizeof(struct layer2) + sizeof(struct layer3));
    /*source address*/
     l2->original_source_addr = htons(src);
     
 
    // Read Path
     l3->ttl =0;
     memcpy(l3->source_routing, src_routing, MAX_HOPS);
     l3->type = TYPE_UDP;
     printf("port %u",port);
     l4->dport = port;
     l4->sport = port;
     l4->len = htons(header_size+FSCP_UDP_ID_BYTES + sizeof(file_size) + 1 + strlen(file_name) + 1); 
    /**/

    fprintf(stdout, "        Filename: %s\n", file_name);
    fprintf(stdout, "        Filesize: %ld Bytes\n", file_size);
    fprintf(stdout, "   Required ACKs: %d\n", required_acks);
    
    // Calculate the number of chunks
    total_chunks = (file_size / FSCP_UDP_DATA_BYTES) + ((file_size % FSCP_UDP_DATA_BYTES > 0)?1:0);
    fprintf(stdout, "  Size of chunks: %d Bytes\n", FSCP_UDP_DATA_BYTES);
    fprintf(stdout, "Number of chunks: %llu (0x%.6llx)\n", total_chunks, total_chunks);

    // Chunk cache declaration
    unsigned char **chunk_cache;
    chunk_cache = (unsigned char **) malloc(sizeof(*chunk_cache) * total_chunks);
    pthread_mutex_t *chunk_cache_mutex;
    chunk_cache_mutex = (pthread_mutex_t *) malloc(sizeof(pthread_mutex_t) * total_chunks);

    #ifdef _DEBUG
    fprintf(stdout, "          Status: Connecting\n");
    #else
    fprintf(stdout, "          Status: Connecting");
    fflush(stdout);
    #endif
    
    // Initialize chuck acknowledgement bitmap
    chunks_ack = (unsigned char *) malloc(total_chunks/8 + 1);
    memset(chunks_ack, 0, total_chunks/8 + 1);
    
    // Initialize buffer
    //   Structure: CHUNK_ID|FILE_SIZE|REQUIRED_ACKS|FILE_NAME
    memcpy(buffer + header_size + FSCP_UDP_ID_BYTES, &file_size, sizeof(file_size)); // Add filesize info into the buffer
    memcpy(buffer + header_size + FSCP_UDP_ID_BYTES + sizeof(file_size), &required_acks, 1); // Add required number of acks into the buffer
    memcpy(buffer + header_size + FSCP_UDP_ID_BYTES + sizeof(file_size) + 1, file_name, strlen(file_name)); // Add file name into the buffer
    printf("File size %ld and size %lu\n",file_size,sizeof(file_size));
    // Create socket
    sa_in.sll_family = PF_PACKET;
    sa_in.sll_ifindex = dev->interface_index;
    sa_in.sll_halen = 0;
    sa_in.sll_protocol = htons(ETH_P_ALL);
    sa_in.sll_hatype = 0;
    sa_in.sll_pkttype = 0;

    sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd == -1) {
        fprintf(stderr, "Cannot create raw socket for outgoing interface\n");
        fprintf(stderr, "%s\n", strerror(errno));
    }
    struct ifreq ifopts;
    strncpy(ifopts.ifr_name, dev->interface_name, IFNAMSIZ-1);
    ioctl(sockfd, SIOCGIFFLAGS, &ifopts);
    ifopts.ifr_flags |= IFF_PROMISC;
    ioctl(sockfd, SIOCSIFFLAGS, &ifopts);
    int optval;
    optval = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) == -1) {
		perror("setsockopt");
		close(sockfd);
		exit(EXIT_FAILURE);
    }
 
    if (bind(sockfd, (struct sockaddr *)&sa_in, sizeof(sa_in)) != 0) {
        fprintf(stderr, "Cannot bind to raw socket for outgoing interface\n");
    }
    
    
    // Send the file information to the receiver
    fprintf(stdout, "[DEBUG] Send: 0x");
            for (unsigned int p=0; p<FSCP_UDP_ID_BYTES+sizeof(file_size) + 1 + strlen(file_name) + 1; p++) {
                if (p==FSCP_UDP_ID_BYTES) fprintf(stdout, " ");
                fprintf(stderr, "%.2x", buffer[p]);
   	}
    while (true) {

        for(i=0; i<required_acks+1; i++) {
            
            send(sockfd, buffer, header_size+FSCP_UDP_ID_BYTES + sizeof(file_size) + 1 + strlen(file_name) + 1, 0 );
            
            #ifdef _DEBUG
            fprintf(stdout, "[DEBUG] Send: 0x");
            for (unsigned int p=0; p<FSCP_UDP_ID_BYTES+sizeof(file_size) + 1 + strlen(file_name) + 1; p++) {
                if (p==FSCP_UDP_ID_BYTES) fprintf(stdout, " ");
                fprintf(stdout, "%.2x", buffer[p]);
            }
            fprintf(stdout, "\n");
            #endif
        }
        // Wait for ack (with receive timeout)
        recvlen = recv(sockfd, recvbuffer, header_size+FSCP_UDP_ID_BYTES, 0);
	struct layer2 *l2=(struct layer2 *)recvbuffer;
	
        if (recvlen != -1UL) {
            if (recvlen == FSCP_UDP_ID_BYTES+header_size) {
                if ((uint16_t)ntohs(l2->original_source_addr)==dest){ 
	    		memcpy(&chunk_id, recvbuffer+header_size, FSCP_UDP_ID_BYTES);
                	#ifdef _DEBUG
                	fprintf(stdout, "[DEBUG] Recv: ACK 0x%.6llx\n", chunk_id);
                	#endif
                
                if (chunk_id==0ULL) break;
		}
            }
        }
        else {
            #ifdef _DEBUG
            fprintf(stdout, "[DEBUG] Timeout!\n");
            #endif
        }
    }
   //exit(0); 
    #ifdef _DEBUG
    fprintf(stdout, "          Status: Connected\n");
    fprintf(stdout, "[DEBUG] -------------------------\n");
    #else
    fprintf(stdout, "\r          Status: Connected \n");
    fprintf(stdout, "        Progress:   0%%");
    fflush(stdout);
    #endif
    
    
    // Seek to the beginning of the file
    fseek(file, 0, SEEK_SET);
    memset(buffer + header_size, 0x00, FSCP_UDP_DATA_BYTES); 
    // Start ACK receiver thread
    struct ack_receiver_thread_parameter params;
    params.sockfd = &sockfd;
    params.chunks_ack_count = &chunks_ack_count;
    params.total_chunks = &total_chunks;
    params.chunk_id_first_unacked = &chunk_id_first_unacked;
    //params.rcvraddr = &rcvraddr;
    params.chunks_ack = &chunks_ack;
    params.chunk_cache = &chunk_cache[0];
    params.chunk_cache_mutex = &chunk_cache_mutex;
    params.dest = dest;
    pthread_t thread;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
    
    if(pthread_create(&thread , &attr,  ack_receiver_thread, (void*) &params) < 0) {
        fprintf(stderr, "Error: Can not create a thread for the ack_receiver_thread in init_sender()\n");
        exit(4);
    }
    
    // Sending data packets
    while(chunks_ack_count<total_chunks) {
        //printf("loop~\n");
        // Loop from the first unacked to the last chunk
        for(j=chunk_id_first_unacked; j<=total_chunks && j<=chunk_id_first_unacked+210000L; j++) {
            
            // Send only chunk whose ACK has not been received
            if (!is_ack(&chunks_ack, j)) {
            
                if (chunk_id_last_cached < j) {
                    // Remember id of the last cached chunk
                    chunk_id_last_cached = j;
                    
                    // Create cache for a data chunk with structure: file_read_len|chunk_id|chunk_data
                    chunk_cache[j-1] = (unsigned char*) malloc(sizeof(file_read_len) + sizeof(unsigned char)*UDP_DATA_MAX_LENGTH);
                    // Put Chunk ID into cache
                    memcpy(chunk_cache[j-1] + sizeof(file_read_len), &j, FSCP_UDP_ID_BYTES);
                    // Read file into cache
                    file_read_len = fread(chunk_cache[j-1] + sizeof(file_read_len) + FSCP_UDP_ID_BYTES, sizeof(unsigned char), FSCP_UDP_DATA_BYTES, file);
                    // Put data length of the chunk into cache
                    memcpy(chunk_cache[j-1], &file_read_len, sizeof(file_read_len));
                    
                    // Init mutex
                    pthread_mutex_init(&chunk_cache_mutex[j-1], NULL);
                }
                else {
                    // Try lock to load cache
                    if (pthread_mutex_trylock(&chunk_cache_mutex[j-1]) != 0) {
                        // Skip if cannot lock because ack_receiver_thread probably received ack
                        continue;
                    }
                    
                    // Load cache
                    memcpy(&file_read_len, chunk_cache[j-1], sizeof(file_read_len));
                }

                #ifdef _DEBUG
                fprintf(stdout, "[DEBUG] Send %3llu%%: Chunk 0x%.2x%.2x%.2x", 100*chunks_ack_count/total_chunks, chunk_cache[j-1][10], chunk_cache[j-1][9], chunk_cache[j-1][8]);
                    #ifdef _DEBUG_VERBOSE
                    fprintf(stdout, " : ");
                    for (size_t k=0; k<file_read_len; k++) {
                        fprintf(stdout, "%.2x", chunk_cache[j-1][sizeof(file_read_len)+FSCP_UDP_ID_BYTES+k]);
                    }
                    #endif
                fprintf(stdout, "\n");
                #endif
                l4->len = htons(FSCP_UDP_ID_BYTES+file_read_len); 
                memcpy(buffer+header_size,chunk_cache[j-1]+sizeof(file_read_len),FSCP_UDP_ID_BYTES+file_read_len);
                send(sockfd, buffer, header_size+FSCP_UDP_ID_BYTES+file_read_len, 0);
                pthread_mutex_unlock(&chunk_cache_mutex[j-1]);
                
            }

        }
        
    }
    
    pthread_join(thread, NULL);
    
    close(sockfd);
    fclose(file);
    
    fprintf(stdout, "\n");
}

void *ack_receiver_thread(void *params) {
    unsigned char *recv_buff = (unsigned char*)malloc (UDP_DATA_MAX_LENGTH*sizeof(unsigned char));
    memset(recv_buff,0x00,UDP_DATA_MAX_LENGTH);
    size_t header_size;
    header_size = sizeof(struct layer2) + sizeof(struct layer3) + sizeof(struct layer4_udp);

    struct ack_receiver_thread_parameter *p = (struct ack_receiver_thread_parameter *) params;
    int *sockfd = p->sockfd;
    unsigned long long *chunks_ack_count = p->chunks_ack_count;
    unsigned long long *total_chunks = p->total_chunks;
    unsigned long long *chunk_id_first_unacked = p->chunk_id_first_unacked;
    unsigned char **chunks_ack = p->chunks_ack;
    unsigned char **chunk_cache = p->chunk_cache;
    pthread_mutex_t **chunk_cache_mutex = p->chunk_cache_mutex;
    uint16_t dest = p->dest;
    unsigned long long chunk_id = 0ULL;
    size_t recvlen;
    
    unsigned long long progress = 101;
    
    // Receive ACK
    while (*chunks_ack_count < *total_chunks) {
        //recvlen = recv(*sockfd, &chunk_id, FSCP_UDP_ID_BYTES, 0, (struct sockaddr *)rcvraddr, &rcvraddr_len);
        recvlen = recv(*sockfd, recv_buff, header_size+FSCP_UDP_ID_BYTES, 0);
	struct layer2 *l2=(struct layer2 *)recv_buff;
	if (recvlen == FSCP_UDP_ID_BYTES+header_size) {
	   if ((uint16_t)ntohs(l2->original_source_addr)==dest){
	    memcpy(&chunk_id, recv_buff+header_size, FSCP_UDP_ID_BYTES);
            if (chunk_id>0) {
                
	    		//printf("\n chunk id 0x%.6llx",chunk_id); 
                if (chunk_id == (1ULL<<(FSCP_UDP_ID_BYTES*8))-1) {
                    // Receive FIN
                    *chunks_ack_count = *total_chunks;
                    fprintf(stdout, "\b\b\b\b100%%");
                    break;
                }
                
                if (!is_ack(chunks_ack, chunk_id)) {
                    
                    set_ack(chunks_ack, chunk_id, true);
                    *chunks_ack_count = *chunks_ack_count + 1;
                    
                    // Advance to the next unacked id
                    if (chunk_id == *chunk_id_first_unacked) {
                        do {
                            *chunk_id_first_unacked = *chunk_id_first_unacked + 1;
                        } while (is_ack(chunks_ack, *chunk_id_first_unacked));
                    }
                    
                    // Remove cache of the chunk
                    pthread_mutex_lock(*chunk_cache_mutex+(chunk_id-1));
                    free(chunk_cache[chunk_id-1]);
                    pthread_mutex_destroy(*chunk_cache_mutex+(chunk_id-1));
                    
                    #ifdef _DEBUG
                    fprintf(stdout, "[DEBUG] Recv %3llu%%: ACK 0x%.6llx\n", 100*(*chunks_ack_count)/(*total_chunks), chunk_id);
                    #else
                    if (progress != 100*(*chunks_ack_count)/(*total_chunks)) {
                        progress = 100*(*chunks_ack_count)/(*total_chunks);
                        fprintf(stdout, "\b\b\b\b%3llu%%", progress);
                        fflush(stdout);
                    }
                    #endif
                    
                }
            }    
            }
        }
    }
    
    return 0;
}

