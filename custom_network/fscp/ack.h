//
//  ack.h
//  fscp
//

#ifndef __fscp__ack__
#define __fscp__ack__

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

void set_ack(unsigned char **chunks_ack, unsigned long long chunk_id, bool is_ack);
bool is_ack(unsigned char **chunks_ack, unsigned long long chunk_id);

#endif /* defined(__fscp__ack__) */

