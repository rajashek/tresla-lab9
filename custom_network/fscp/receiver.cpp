//
//  receiver.cpp
//  fscp
//

#include "receiver.h"

void init_receiver(uchar_t *packet, uint16_t srcaddr, uint8_t dport, struct interface *output_interface, char *file_name) {
    
    int sockfd, i;
    
    size_t recvlen;
    
    unsigned char buffer[MTU];
    
    long file_size = 0L;

    unsigned char required_acks = FSCP_DEFAULT_NUMBER_OF_ACKS;
    unsigned char *acks_buffer;
    
    unsigned long long chunk_id = 0L, total_chunks, chunks_ack_count = 0L;
    unsigned char *chunks_ack;
    unsigned char **chunk_cache;
    
    FILE *file;
    //char *fwrite_buffer;
    
    struct sockaddr_ll sa;
    struct packet_mreq mreq;
    struct sock_filter incoming_filter[] = {
        { 0x30, 0, 0, 0x00000001 },
        { 0x15, 0, 5, 0x00000000 }, // ether[1]
        { 0x30, 0, 0, 0x00000000 },
        { 0x15, 0, 3, 0x00000000 }, // ether[0]
        { 0x30, 0, 0, 0x00000006 }, // the position of dport
        { 0x15, 0, 1, 0x00000000 }, // value of the byte at the position of dport
        { 0x6, 0, 0, 0x0000ffff },
        { 0x6, 0, 0, 0x00000000 },
    };
    struct sock_fprog prog_filter;
    
    size_t header_length = sizeof(struct layer2) + sizeof(struct layer3) + sizeof(struct layer4_udp);
    
    struct layer4_udp *packet_l4 = (struct layer4_udp *) (packet + sizeof(struct layer2) + sizeof(struct layer3));
    struct layer4_udp *buffer_l4 = (struct layer4_udp *) (buffer + sizeof(struct layer2) + sizeof(struct layer3));
    
    uchar_t *packet_payload = packet + header_length;
    uchar_t *buffer_payload = buffer + header_length;

    
    // Initialize buffer
    memset(buffer, 0, sizeof(buffer));
    
    // Prepare interface and socket
    sa.sll_family = PF_PACKET;
    sa.sll_ifindex = output_interface->interface_index;
    sa.sll_halen = 0;
    sa.sll_protocol = htons(ETH_P_ALL);
    sa.sll_hatype = 0;
    sa.sll_pkttype = 0;
    
    mreq.mr_ifindex = output_interface->interface_index;
    mreq.mr_type = PACKET_MR_PROMISC;
    mreq.mr_alen = 0;
    
    // Set filter to socket
    prog_filter.len = 8;
    prog_filter.filter = incoming_filter;
    
    incoming_filter[1].k = (uint32_t)(srcaddr & 0xff);
    incoming_filter[3].k = (uint32_t)((srcaddr>>8) & 0xff);
    incoming_filter[4].k = (uint32_t)(sizeof(struct layer2) + sizeof(struct layer3)); // set position of dport
    incoming_filter[5].k = (uint32_t)(dport & 0xff); // set value of dport
    
    // Create socket
    if ((sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        fprintf(stderr, "Error: cannot create raw socket in init_receiver()\n");
        exit(1);
    }
    
    // Set Socket Options
    int so_sndbuf_size = SOCKET_SNDBUFFER;
    if (setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &so_sndbuf_size, sizeof(so_sndbuf_size)) < 0) {
        fprintf(stderr, "Error: cannot set SO_SNDBUF in init_receiver()\n");
        exit(2);
    }
    int so_rcvbuf_size = SOCKET_RCVBUFFER;
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &so_rcvbuf_size, sizeof(so_rcvbuf_size)) < 0) {
        fprintf(stderr, "Error: cannot set SO_RCVBUF in init_receiver()\n");
        exit(2);
    }
    
    // Set Promiscuous mode and filter
    if (setsockopt(sockfd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        fprintf(stderr, "Error: cannot set PACKET_ADD_MEMBERSHIP + PACKET_MR_PROMISC in init_receiver()\n");
        exit(2);
    }
    if (setsockopt(sockfd, SOL_SOCKET, SO_ATTACH_FILTER, &prog_filter, sizeof(prog_filter)) < 0)
    {
        fprintf(stderr, "Error: cannot set SO_ATTACH_FILTER in init_receiver()\n");
        exit(2);
    }

    // Bind socket
    if(::bind(sockfd ,(struct sockaddr *) &sa, sizeof(sa)) <0) {
        fprintf(stderr, "Error bind raw socket failed in init_receiver()\n");
        exit(3);
    }
    
    while (true) {
        recvlen = recv(sockfd, buffer, MTU, 0);
        if ((recvlen != -1UL) && (recvlen >= header_length + FSCP_UDP_ID_BYTES)) {
            
            //if ((buffer_l2->original_source_addr == htons(srcaddr)) && (buffer_l4->dport == dport)) continue;
            
            #ifdef _DEBUG
            fprintf(stdout, "[DEBUG] Rcvd: %.2x%.2x%.2x%.2x\n", buffer[header_length + 0], buffer[header_length + 1], buffer[header_length + 2], buffer[header_length + 3]);
            #endif
            
            memcpy(&chunk_id, buffer_payload, FSCP_UDP_ID_BYTES);
            if (chunk_id == 0ULL) {
                break;
            }
            
        }
    }
    
    // Send ACK for Chunk ID = 0
    for(i=0; i<required_acks+1; i++) {
        send(sockfd, packet, header_length + FSCP_UDP_ID_BYTES, 0);
        #ifdef _DEBUG
        fprintf(stdout, "[DEBUG] Send: ACK 0\n");
        #endif
    }
    
    // Copy file information from the Chunk ID = 0
    memcpy(&file_size, buffer_payload + FSCP_UDP_ID_BYTES, sizeof(file_size));
    memcpy(&required_acks, buffer_payload + FSCP_UDP_ID_BYTES + sizeof(file_size), 1);
    if (strlen(file_name) == 0) {
        file_name = (char *) malloc(sizeof(char) * (ntohs(buffer_l4->len)-(FSCP_UDP_ID_BYTES+sizeof(file_size)+1)));
        memcpy(file_name, buffer_payload + FSCP_UDP_ID_BYTES + sizeof(file_size) + 1, (ntohs(buffer_l4->len)-(FSCP_UDP_ID_BYTES+sizeof(file_size)+1)));
    }

    total_chunks = (file_size / FSCP_UDP_DATA_BYTES) + ((file_size % FSCP_UDP_DATA_BYTES > 0)?1:0);
    
    packet_l4->len = htons(required_acks * FSCP_UDP_ID_BYTES);

    fprintf(stdout, "        Filename: %s\n", file_name);
    fprintf(stdout, "        Filesize: %ld Bytes\n", file_size);
    fprintf(stdout, "   Required ACKs: %d\n", required_acks);
    fprintf(stdout, "  Size of chunks: %d Bytes\n", FSCP_UDP_DATA_BYTES);
    fprintf(stdout, "Number of chunks: %llu (0x%.6llx)\n", total_chunks, total_chunks);
    
    

    // Open output file and create the buffer
    file = fopen(file_name, "w");
    //fwrite_buffer = (char *) malloc(sizeof(char) * 2 * 1024 * 1024ULL);
    //setvbuf(file, fwrite_buffer, _IOFBF, sizeof(char) * 2 * 1024 * 1024ULL);
    //setvbuf(file, NULL, _IONBF, 0);
    
    // Initialize chuck acknowledgement bitmap
    chunks_ack = (unsigned char *) malloc(total_chunks/8 + 1);
    memset(chunks_ack, 0, total_chunks/8 + 1);
    
    // Initialize chunk cache
    chunk_cache = (unsigned char **) malloc(sizeof(*chunk_cache) * total_chunks);
    
    // Initialize acks_buffer;
    acks_buffer = (unsigned char *) malloc(required_acks * FSCP_UDP_ID_BYTES);
    memset(acks_buffer, 0, sizeof(required_acks * FSCP_UDP_ID_BYTES));

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
        
        recvlen = recv(sockfd, buffer, MTU, 0);
        if (likely((recvlen != -1UL) && (recvlen >= header_length + FSCP_UDP_ID_BYTES))) {
            
            memcpy(&chunk_id, buffer_payload, FSCP_UDP_ID_BYTES);
            if (likely(chunk_id > 0)) {
                
                #ifdef _DEBUG
                fprintf(stdout, "[DEBUG] Recv: 0x%.8llx %lu\n", chunk_id, recvlen);
                #endif
                
                // Shift the packet payload to the right
                memmove(packet_payload + FSCP_UDP_ID_BYTES, packet_payload, (required_acks-1) * FSCP_UDP_ID_BYTES);
                // Copy the chunk id into the front of the packet payload
                memcpy(packet_payload, buffer_payload, FSCP_UDP_ID_BYTES);
                // Send ACK (Encapsulate acknowledgement of many chunks into a packet)
                send(sockfd, packet, header_length + required_acks * FSCP_UDP_ID_BYTES, 0);
                
                
                #ifdef _DEBUG
                fprintf(stdout, "[DEBUG] Send: ACK 0x%.8llx\n", chunk_id);
                #endif


                if (!is_ack(&chunks_ack, chunk_id)) {
                    
                    // Create cache for a data chunk with structure: packet_header|chunk_id|chunk_data
                    chunk_cache[chunk_id-1] = (unsigned char*) malloc(sizeof(unsigned char)*MTU);
                    // Put a whole packet into the cache
                    memcpy(chunk_cache[chunk_id-1], buffer, header_length + ntohs(buffer_l4->len));
                    
                    set_ack(&chunks_ack, chunk_id, true);
                    chunks_ack_count = chunks_ack_count + 1;

                }

            }
            else {
                packet_l4->len = htons(FSCP_UDP_ID_BYTES);
                memset(packet_payload, 0, FSCP_UDP_ID_BYTES);
                send(sockfd, packet, header_length + FSCP_UDP_ID_BYTES, 0);
                packet_l4->len = htons(required_acks * FSCP_UDP_ID_BYTES);
            }
        }
        
    }
    
    // Send FIN
    chunk_id = ~ 0ULL;
    packet_l4->len = htons(FSCP_UDP_ID_BYTES);
    memcpy(packet_payload, &chunk_id, FSCP_UDP_ID_BYTES);
    for(i=0; i<required_acks+1; i++) {
        send(sockfd, packet, header_length + FSCP_UDP_ID_BYTES, 0);
        #ifdef _DEBUG
        fprintf(stdout, "[DEBUG] Send: FIN\n");
        #endif
    }
    
    close(sockfd);
    
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

    size_t header_length = sizeof(struct layer2) + sizeof(struct layer3) + sizeof(struct layer4_udp);
    struct layer4_udp *cache_l4;
    
    struct timespec ts;
    ts.tv_sec = 0;
    ts.tv_nsec = 100*1000000L;
    
    while (chunk_written < *total_chunks) { //
        
        if (is_ack(chunks_ack, chunk_written+1)) {
            
            cache_l4 = (struct layer4_udp *) (chunk_cache[chunk_written] + sizeof(struct layer2) + sizeof(struct layer3));
            fseek(file, (chunk_written)*FSCP_UDP_DATA_BYTES, SEEK_SET);
            fwrite(chunk_cache[chunk_written] + header_length + FSCP_UDP_ID_BYTES, ntohs(cache_l4->len) - FSCP_UDP_ID_BYTES, 1, file);

            free(chunk_cache[chunk_written]);
            
            chunk_written++;
            
        }
        else {
            nanosleep(&ts, NULL);
        }
        
    }
    
    return 0;
}

