//
//  sender.cpp
//  fscp
//

#include "sender.h"

void init_sender(uchar_t *packet, uint16_t destaddr, uint8_t dport, uint8_t sport, struct interface *output_interface, FILE *file, long file_size, const char *file_name, unsigned char required_acks, size_t bandwidth) {

    int sockfd, i;
    
    size_t recvlen;
    
    unsigned long long chunk_id = 0L, total_chunks, chunks_ack_count = 0L, j;
    unsigned long long chunk_id_first_unacked = 1L;
    unsigned long long chunk_id_last_cached = 0L;
    unsigned char *chunks_ack;
    
    unsigned char buffer[MTU];
    size_t file_read_len;
    
    struct timeval tv;
    
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
    memcpy(packet_payload + FSCP_UDP_ID_BYTES, &file_size, sizeof(file_size)); // Add filesize info into the packet buffer
    memcpy(packet_payload + FSCP_UDP_ID_BYTES + sizeof(file_size), &required_acks, 1); // Add required number of acks into the packet buffer
    memcpy(packet_payload + FSCP_UDP_ID_BYTES + sizeof(file_size) + 1, file_name, strlen(file_name)); // Add file name into the packet buffer
    packet_l4->len = htons(FSCP_UDP_ID_BYTES + sizeof(file_size) + 1 + strlen(file_name) + 1);
    
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
    
    // Create filter for socket
    prog_filter.len = 8;
    prog_filter.filter = incoming_filter;
    
    incoming_filter[1].k = (uint32_t)(destaddr & 0xff);
    incoming_filter[3].k = (uint32_t)((destaddr>>8) & 0xff);
    incoming_filter[4].k = (uint32_t)(sizeof(struct layer2) + sizeof(struct layer3)); // set position of dport
    incoming_filter[5].k = (uint32_t)(sport & 0xff); // set value of dport
    
    // Create socket
    if ((sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        fprintf(stderr, "Error: cannot create raw socket in init_sender()\n");
        exit(1);
    }
    
    // Set Socket Options
    int so_sndbuf_size = SOCKET_SNDBUFFER;
    if (setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &so_sndbuf_size, sizeof(so_sndbuf_size)) < 0) {
        fprintf(stderr, "Error: cannot set SO_SNDBUF in init_sender()\n");
        exit(2);
    }
    int so_rcvbuf_size = SOCKET_RCVBUFFER;
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &so_rcvbuf_size, sizeof(so_rcvbuf_size)) < 0) {
        fprintf(stderr, "Error: cannot set SO_RCVBUF in init_sender()\n");
        exit(2);
    }
    
    // Set Promiscuous mode and filter
    if (setsockopt(sockfd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        fprintf(stderr, "Error: cannot set PACKET_ADD_MEMBERSHIP + PACKET_MR_PROMISC in init_sender()\n");
        exit(2);
    }
    if (setsockopt(sockfd, SOL_SOCKET, SO_ATTACH_FILTER, &prog_filter, sizeof(prog_filter)) < 0)
    {
        fprintf(stderr, "Error: cannot set SO_ATTACH_FILTER in init_sender()\n");
        exit(2);
    }
    
    tv.tv_sec = 0;
    tv.tv_usec = 400*1000L;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (struct timeval *)&tv, sizeof(struct timeval));

    // Bind socket
    if(::bind(sockfd ,(struct sockaddr *) &sa, sizeof(sa)) <0) {
        fprintf(stderr, "Error bind raw socket failed in init_sender()\n");
        exit(3);
    }
    
    // Seek to the beginning of the file
    fseek(file, 0, SEEK_SET);
    
    // Prepare ACK receiver thread
    struct ack_receiver_thread_parameter params;
    params.sockfd = &sockfd;
    params.chunks_ack_count = &chunks_ack_count;
    params.total_chunks = &total_chunks;
    params.chunk_id_first_unacked = &chunk_id_first_unacked;
    params.required_acks = &required_acks;
    params.chunks_ack = &chunks_ack;
    params.chunk_cache = &chunk_cache[0];
    params.chunk_cache_mutex = &chunk_cache_mutex;
    
    pthread_t thread;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
    
    // Send the file information to the receiver
    while (true) {

        for(i=0; i<required_acks+1; i++) {
            
            send(sockfd, packet, header_length + FSCP_UDP_ID_BYTES + sizeof(file_size) + 1 + strlen(file_name) + 1, 0);
            
            #ifdef _DEBUG
            fprintf(stdout, "[DEBUG] Send: 0x");
            for (unsigned int p=0; p<header_length+FSCP_UDP_ID_BYTES+sizeof(file_size) + 1 + strlen(file_name) + 1; p++) {
                if (p==header_length) fprintf(stdout, " ");
                else if (p==header_length+FSCP_UDP_ID_BYTES) fprintf(stdout, " ");
                fprintf(stdout, "%.2x", packet[p]);
            }
            fprintf(stdout, "\n");
            #endif
        }

        // Wait for ack (with receive timeout)
        recvlen = recv(sockfd, buffer, MTU, 0);
        if ((recvlen != -1UL) && (recvlen >= header_length + FSCP_UDP_ID_BYTES)) {
            if (buffer_l4->len == htons(FSCP_UDP_ID_BYTES)) {

                #ifdef _DEBUG
                fprintf(stdout, "[DEBUG] Recv: ACK 0x%.8llx\n", chunk_id);
                #endif
                
                memcpy(&chunk_id, buffer_payload, FSCP_UDP_ID_BYTES);
                if (chunk_id==0ULL) break;
                
            }
        }
        else {
            #ifdef _DEBUG
            fprintf(stdout, "[DEBUG] Timeout!\n");
            #endif
        }
    }
    
    #ifdef _DEBUG
    fprintf(stdout, "          Status: Connected\n");
    fprintf(stdout, "[DEBUG] -------------------------\n");
    #else
    fprintf(stdout, "\r          Status: Connected \n");
    fprintf(stdout, "        Progress:   0%%");
    fflush(stdout);
    #endif
    
    // Start ACK receiver thread
    if(pthread_create(&thread , &attr,  ack_receiver_thread, (void*) &params) < 0) {
        fprintf(stderr, "Error: Can not create a thread for the ack_receiver_thread in init_sender()\n");
        exit(4);
    }

    // Bandwidth Throttling
    #ifdef _THROTTLING_ENABLED
    struct timespec start, now, next, wait;
    size_t bytes_sent_during_window = 0;
    size_t max_bytes_per_second = bandwidth;
    size_t max_bytes_during_window = (max_bytes_per_second * _THROTTLING_TIME_WINDOW_MS) / 1000;
    
    clock_gettime(CLOCK_REALTIME, &start);
    #endif
    
    // Sending data packets
    while(chunks_ack_count<total_chunks) {

        // Loop from the first unacked to the last chunk
        for(j=chunk_id_first_unacked; j<=total_chunks && j<=chunk_id_first_unacked+210000L; j++) {
            
            // Send only chunk whose ACK has not been received
            if (!is_ack(&chunks_ack, j)) {
            
                if (chunk_id_last_cached < j) {
                    // Remember id of the last cached chunk
                    chunk_id_last_cached = j;
                    
                    // Create cache for a data chunk with structure: file_read_len|packet_header|chunk_id|chunk_data
                    chunk_cache[j-1] = (unsigned char*) malloc(sizeof(file_read_len) + sizeof(unsigned char) * MTU);
                    
                    // Put Chunk ID into cache
                    memcpy(chunk_cache[j-1] + sizeof(file_read_len) + header_length, &j, FSCP_UDP_ID_BYTES);
                    // Read file into cache
                    file_read_len = fread(chunk_cache[j-1] + sizeof(file_read_len) + header_length + FSCP_UDP_ID_BYTES, sizeof(unsigned char), FSCP_UDP_DATA_BYTES, file);
                    // Put Packet Header into cache
                    packet_l4->len = htons(file_read_len + FSCP_UDP_ID_BYTES);
                    memcpy(chunk_cache[j-1] + sizeof(file_read_len), packet, header_length);
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
                fprintf(stdout, "[DEBUG] Send %3llu%%: Chunk 0x%.2x%.2x%.2x%.2x", 100*chunks_ack_count/total_chunks, chunk_cache[j-1][21], chunk_cache[j-1][20], chunk_cache[j-1][19], chunk_cache[j-1][18]);
                    #ifdef _DEBUG_VERBOSE
                    fprintf(stdout, " : ");
                    for (size_t k=0; k<file_read_len; k++) {
                        fprintf(stdout, "%.2x", chunk_cache[j-1][sizeof(file_read_len)+header_length+FSCP_UDP_ID_BYTES+k]);
                    }
                    #endif
                fprintf(stdout, "\n");
                #endif

                send(sockfd, chunk_cache[j-1] + sizeof(file_read_len), header_length + FSCP_UDP_ID_BYTES + file_read_len, 0);
                pthread_mutex_unlock(&chunk_cache_mutex[j-1]);
                
                
                
                #ifdef _THROTTLING_ENABLED
                bytes_sent_during_window += header_length + FSCP_UDP_ID_BYTES + file_read_len;
                if (bytes_sent_during_window >= max_bytes_during_window) {

                    // Calculate the next window time
                    next.tv_sec  = start.tv_sec;
                    next.tv_nsec = start.tv_nsec;
                    next.tv_nsec += _THROTTLING_TIME_WINDOW_MS * 1000000L;
                    if (next.tv_nsec > 1000000000L) {
                        next.tv_sec += 1;
                        next.tv_nsec -= 1000000000L;
                    }

                    // Get Current time
                    clock_gettime(CLOCK_REALTIME, &now);
                    
                    // If not reach the end of the current window?
                    if (now.tv_sec <  next.tv_sec ||
                       (now.tv_sec == next.tv_sec && now.tv_nsec < next.tv_nsec)) {
                        wait.tv_sec = next.tv_sec - now.tv_sec;
                        if (next.tv_nsec >= now.tv_nsec) {
                            wait.tv_nsec = next.tv_nsec - now.tv_nsec;
                        } else {
                            wait.tv_nsec = 1000000000L + next.tv_nsec - now.tv_nsec;
                            wait.tv_sec -= 1;
                        }
                        
                        // Sleep until the end of the window
                        nanosleep(&wait, NULL);
                    }
                    
                    // Reset for the next window
                    bytes_sent_during_window = 0;
                    clock_gettime(CLOCK_REALTIME, &start);
                }
                #endif
            }

        }
        
    }
    
    pthread_join(thread, NULL);
    
    close(sockfd);
    fclose(file);
    
    fprintf(stdout, "\n");
}

void *ack_receiver_thread(void *params) {
    
    struct ack_receiver_thread_parameter *p = (struct ack_receiver_thread_parameter *) params;
    int *sockfd = p->sockfd;
    unsigned long long *chunks_ack_count = p->chunks_ack_count;
    unsigned long long *total_chunks = p->total_chunks;
    unsigned long long *chunk_id_first_unacked = p->chunk_id_first_unacked;
    unsigned char *required_acks = p->required_acks;
    unsigned char **chunks_ack = p->chunks_ack;
    unsigned char **chunk_cache = p->chunk_cache;
    pthread_mutex_t **chunk_cache_mutex = p->chunk_cache_mutex;
    
    size_t header_length = sizeof(struct layer2) + sizeof(struct layer3) + sizeof(struct layer4_udp);
    
    unsigned int i;
    unsigned char buffer[header_length + (*required_acks * FSCP_UDP_ID_BYTES)];
    unsigned long long chunk_id = 0L;

    size_t recvlen;
    
    unsigned long long progress = 101;
    
    struct layer4_udp *buffer_l4 = (struct layer4_udp *) (buffer + sizeof(struct layer2) + sizeof(struct layer3));
    uchar_t *buffer_payload = buffer + header_length;
    
    
    
    // Receive ACK
    while (*chunks_ack_count < *total_chunks) {
        
        recvlen = recv(*sockfd, buffer, header_length + (*required_acks * FSCP_UDP_ID_BYTES), 0);
        if ((recvlen != -1UL) && (recvlen >= header_length + FSCP_UDP_ID_BYTES)) {
            
            // The packet may contain acknowledgement of more than one chunk
            for(i=0; ((i<ntohs(buffer_l4->len)/FSCP_UDP_ID_BYTES) && (i<*required_acks)); i++) {
                
                // Get chunk id
                memcpy(&chunk_id, buffer_payload + i*FSCP_UDP_ID_BYTES, FSCP_UDP_ID_BYTES);
                
                if (likely(chunk_id>0)) {
                    
                    if (unlikely(chunk_id == (1ULL<<(FSCP_UDP_ID_BYTES*8))-1)) {
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
                            #ifdef _PROGRESS_ENABLED
                            if (progress != 100*(*chunks_ack_count)/(*total_chunks)) {
                                progress = 100*(*chunks_ack_count)/(*total_chunks);
                                fprintf(stdout, "\b\b\b\b%3llu%%", progress);
                                fflush(stdout);
                            }
                            #endif
                        #endif
                        
                    }
                    
                }
            }
        }
    }
    
    return 0;
}

