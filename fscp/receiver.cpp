//
//  receiver.cpp
//  fscp
//

#include "receiver.h"

void init_receiver(char *file_name) {
    
    int sockfd, i;
    struct sockaddr_in sndraddr, rcvraddr;
    socklen_t sndraddr_len;
    size_t recvlen;
    
    unsigned char buffer[UDP_DATA_MAX_LENGTH];
    
    long file_size = 0L;
    unsigned char required_acks = FSCP_DEFAULT_NUMBER_OF_ACKS;
    
    unsigned long long chunk_id = 0L, total_chunks, chunks_ack_count = 0L;
    unsigned char *chunks_ack;
    
    FILE *file;
    //char *fwrite_buffer;
    
    memset(&rcvraddr, 0, sizeof(rcvraddr));
    rcvraddr.sin_family = AF_INET;
    rcvraddr.sin_addr.s_addr = htonl(INADDR_ANY);
    rcvraddr.sin_port = htons(FSCP_UDP_PORT);
    
    // Create socket
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        fprintf(stderr, "Error: cannot create UDP socket in init_receiver()\n");
        exit(1);
    }
    
    // Initialize buffer
    memset(buffer, 0, sizeof(buffer));
    
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

    
    if (::bind(sockfd, (struct sockaddr *) &rcvraddr, sizeof(rcvraddr)) < 0) {
        fprintf(stderr, "Error: cannot bind UDP socket port %d in init_receiver()\n", FSCP_UDP_PORT);
        exit(3);
    }
    
    
    while (true) {
        recvlen = recvfrom(sockfd, buffer, UDP_DATA_MAX_LENGTH, 0, (struct sockaddr *)&sndraddr, &sndraddr_len);
        if (recvlen != -1UL) {
            if (recvlen > FSCP_UDP_ID_BYTES) {
                
                #ifdef _DEBUG
                fprintf(stdout, "[DEBUG] Rcvd: %.2x%.2x%.2x\n", buffer[0], buffer[1], buffer[2]);
                #endif
                
                memcpy(&chunk_id, buffer, FSCP_UDP_ID_BYTES);
                if (chunk_id == 0ULL) {
                    break;
                }
            }
        }
    }

    // Copy file information from the Chunk ID = 0
    memcpy(&file_size, buffer+FSCP_UDP_ID_BYTES, sizeof(file_size));
    memcpy(&required_acks, buffer+FSCP_UDP_ID_BYTES+sizeof(file_size), 1);
    if (strlen(file_name) == 0) {
        file_name = (char *) malloc(sizeof(char) * (recvlen-(FSCP_UDP_ID_BYTES+sizeof(file_size)+1)));
        memcpy(file_name, buffer+FSCP_UDP_ID_BYTES+sizeof(file_size)+1, (recvlen-(FSCP_UDP_ID_BYTES+sizeof(file_size)+1)));
    }

    total_chunks = (file_size / FSCP_UDP_DATA_BYTES) + ((file_size % FSCP_UDP_DATA_BYTES > 0)?1:0);

    fprintf(stdout, "        Filename: %s\n", file_name);
    fprintf(stdout, "        Filesize: %ld Bytes\n", file_size);
    fprintf(stdout, "   Required ACKs: %d\n", required_acks);
    fprintf(stdout, "  Size of chunks: %d Bytes\n", FSCP_UDP_DATA_BYTES);
    fprintf(stdout, "Number of chunks: %llu (0x%.6llx)\n", total_chunks, total_chunks);
    
    for(i=0; i<required_acks+1; i++) {
        sendto(sockfd, buffer, FSCP_UDP_ID_BYTES, 0, (struct sockaddr *)&sndraddr, sndraddr_len);
        #ifdef _DEBUG
        fprintf(stdout, "[DEBUG] Send: ACK 0\n");
        #endif
    }
    
    // Open output file and create the buffer
    file = fopen(file_name, "w");
    //fwrite_buffer = (char *) malloc(sizeof(char) * 2 * 1024 * 1024ULL);
    //setvbuf(file, fwrite_buffer, _IOFBF, sizeof(char) * 2 * 1024 * 1024ULL);
    //setvbuf(file, NULL, _IONBF, 0);
    
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
        
        recvlen = recvfrom(sockfd, buffer, UDP_DATA_MAX_LENGTH, 0, (struct sockaddr *)&sndraddr, &sndraddr_len);
        if (recvlen != 1UL) {
            memcpy(&chunk_id, buffer, FSCP_UDP_ID_BYTES);
            if (chunk_id > 0) {
                
                #ifdef _DEBUG
                fprintf(stdout, "[DEBUG] Recv: %.6llx %lu\n", chunk_id, recvlen);
                #endif
                
                for(i=0; i<required_acks; i++) {
                    sendto(sockfd, buffer, FSCP_UDP_ID_BYTES, 0, (struct sockaddr *)&sndraddr, sndraddr_len);
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
                sendto(sockfd, buffer, FSCP_UDP_ID_BYTES, 0, (struct sockaddr *)&sndraddr, sndraddr_len);
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

