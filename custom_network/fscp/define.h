//
//  define.h
//  fscp
//

#ifndef fscp_define_h
#define fscp_define_h

#define SOCKET_RCVBUFFER 212992     // net.core.rmem_max
#define SOCKET_SNDBUFFER 212992     // net.core.wmem_max

#define MTU 1514
#define FSCP_UDP_ID_BYTES 3
#define FSCP_UDP_DATA_BYTES 1497

#define FSCP_DEFAULT_NUMBER_OF_ACKS 1

// Options
//#define _DEBUG
//#define _DEBUG_VERBOSE
#define _PROGRESS_ENABLED
//#define _THROTTLING_ENABLED
#define _THROTTLING_TIME_WINDOW_MS 50

#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)

#endif
