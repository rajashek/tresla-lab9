//
//  define.h
//  fscp
//

#ifndef fscp_define_h
#define fscp_define_h

#define FSCP_UDP_PORT 45559

#define SOCKET_RCVBUFFER 212992     // net.core.rmem_max
#define SOCKET_SNDBUFFER 212992     // net.core.wmem_max

#define UDP_RCV_BUFFER_SIZE 1600

#define UDP_DATA_MAX_LENGTH 1500
#define FSCP_UDP_ID_BYTES 4
#define FSCP_UDP_DATA_BYTES 1486
#define FSCP_DEFAULT_NUMBER_OF_ACKS 1

//#define _DEBUG
//#define _DEBUG_VERBOSE

#endif
