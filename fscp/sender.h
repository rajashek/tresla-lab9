//
//  sender.h
//  fscp
//

#ifndef __fscp__sender__
#define __fscp__sender__

#include <stdio.h>
#include <iostream>
#include <stdint.h>
#include <cstring>
#include <string.h>
#include <cstdlib>
#include <unistd.h> 

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/time.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <fcntl.h>

#include <pthread.h>

#include "define.h"
#include "ack.h"
//#include "interface.h"
//#include "layers.h"
using namespace std;

void init_sender( uint16_t src, uint16_t dest, uint8_t *src_routing, uint8_t port, struct interface *dev, FILE *file, long file_size, const char *file_name, unsigned char required_acks);

struct ack_receiver_thread_parameter {
    int *sockfd;
    unsigned long long *chunks_ack_count;
    unsigned long long *total_chunks;
    unsigned long long *chunk_id_first_unacked;
    struct sockaddr_in *rcvraddr;
    unsigned char **chunks_ack;
    unsigned char **chunk_cache;
    pthread_mutex_t **chunk_cache_mutex;
    uint16_t dest;
};

void *ack_receiver_thread(void *params);

#endif /* defined(__fscp__sender__) */
