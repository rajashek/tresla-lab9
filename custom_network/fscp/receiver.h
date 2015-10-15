//
//  receiver.h
//  fscp
//

#ifndef __fscp__receiver__
#define __fscp__receiver__

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

void init_receiver(uchar_t *packet, uint16_t srcaddr, uint8_t dport, struct interface *output_interface, char *file_name);

struct receiver_thread_parameter {
    unsigned long long *total_chunks;
    unsigned char **chunk_cache;
    unsigned char **chunks_ack;
    FILE *file;
};

void *receiver_thread(void *params);

#endif /* defined(__fscp__receiver__) */
