//
//  receiver.h
//  fscp
//

#ifndef __fscp__receiver__
#define __fscp__receiver__

#include <stdio.h>
//#include <iostream>
#include <stdint.h>
//#include <cstring>
#include <string.h>
//#include <cstdlib>
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
#include <stdbool.h>
#include <pthread.h>

//#include <queue>

#include "define.h"
#include "interface.h"
//using namespace std;

void init_receiver(char* file_name,uint16_t from,struct interface* output_interface,unsigned char required_acks,struct layer3 *l3); 
void set_ack(unsigned char **chunks_ack, unsigned long long chunk_id, bool is_ack);
bool is_ack(unsigned char **chunks_ack, unsigned long long chunk_id);

struct receiver_thread_parameter {
    unsigned long long *total_chunks;
    unsigned char **chunk_cache;
    unsigned char **chunks_ack;
    FILE *file;
};

void *receiver_thread(void *params);

#endif /* defined(__fscp__receiver__) */
