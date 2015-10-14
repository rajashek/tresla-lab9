//
//  ack.h
//  fscp
//

#ifndef __fscp__ack__
#define __fscp__ack__

#include <stdio.h>
#include <iostream>
#include <stdint.h>
#include <cstring>
#include <string.h>
#include <cstdlib>
#include <unistd.h>

void set_ack(unsigned char **chunks_ack, unsigned long long chunk_id, bool is_ack);
bool is_ack(unsigned char **chunks_ack, unsigned long long chunk_id);

#endif /* defined(__fscp__ack__) */

