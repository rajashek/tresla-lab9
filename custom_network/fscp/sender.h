//
//  sender.h
//  fscp
//

#ifndef __fscp__sender__
#define __fscp__sender__

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

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

#include <linux/if_packet.h>
#include <linux/filter.h>

#include <pthread.h>

#include "define.h"
#include "ack.h"

#include "../layers.h"
#include "../interface.h"

#ifdef _THROTTLING_ENABLED
#include <time.h>
#endif

void init_sender(uchar_t *packet, uint16_t destaddr, uint8_t dport, uint8_t sport, struct interface *output_interface, FILE *file, long file_size, const char *file_name, unsigned char required_acks, size_t bandwidth);

struct ack_receiver_thread_parameter {
    int *sockfd;
    unsigned long long *chunks_ack_count;
    unsigned long long *total_chunks;
    unsigned long long *chunk_id_first_unacked;
    unsigned char *required_acks;
    unsigned char **chunks_ack;
    unsigned char **chunk_cache;
    pthread_mutex_t **chunk_cache_mutex;
};

void *ack_receiver_thread(void *params);

#endif /* defined(__fscp__sender__) */
