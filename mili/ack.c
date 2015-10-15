#include "ack.h"

void set_ack(unsigned char **chunks_ack, unsigned long long chunk_id, bool is_ack) {
    unsigned char x = 1<<(7-chunk_id%8);
    if (is_ack) {
        *(*chunks_ack+(chunk_id/8)) = *(*chunks_ack+(chunk_id/8)) | x;
    }
    else {
        *(*chunks_ack+(chunk_id/8)) = *(*chunks_ack+(chunk_id/8)) & (~x);
    }
}

bool is_ack(unsigned char **chunks_ack, unsigned long long chunk_id) {
    return ((*(*chunks_ack+(chunk_id/8)) & (1<<(7-chunk_id%8)))==(1<<(7-chunk_id%8)));
}

