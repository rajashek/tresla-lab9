//
//  main.cpp
//  fscp
//

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include <sys/stat.h>
#include <libgen.h>

#include "../layers.h"
#include "../interface.h"

#include "receiver.h"
#include "sender.h"
#include "define.h"

void print_usage();
int read_arg_str(char ** v, char * n, const char * a);
int read_arg_int(int * i, char * n, const char * a);

int main(int argc, const char * argv[]) {
    
    FILE *file;
    long file_size = -1;
    char *file_path, *file_name;
    struct stat file_stat;
    unsigned char required_acks = FSCP_DEFAULT_NUMBER_OF_ACKS;
    
    uchar_t  *packet;
    uint16_t recvfrom_addr;
    struct layer2 *l2;
    struct layer3 *l3;
    struct layer4_udp *l4;
    int i;
    char *dup, *token;
    uint8_t port;
    struct interface output_interface;
    
    size_t bandwidth = ~0;
    
    if (argc <= 1) {
        print_usage();
        exit(1);
    }
    
    // Increase the priority of the process (max priority is -20, min is 19)
    if (setpriority(PRIO_PROCESS, 0, -15) < 0) {
        fprintf(stderr, "** It is recommend to run as a superuser! **\n");
    }
    
    // Initializing packet and its header
    packet = (uchar_t *) malloc(MTU);
    memset(packet, 0, MTU);
    l2 = (struct layer2 *) packet;
    l3 = (struct layer3 *) (packet + sizeof(struct layer2));
    l4 = (struct layer4_udp *) (packet + sizeof(struct layer2) + sizeof(struct layer3));
    l3->type = TYPE_UDP;

    if (strcmp("-r", argv[1]) == 0) {
        
        //Begin receiving the file
        if (argc >= 11) {
            
            if (strcmp("-src", argv[2]) == 0) {
                l2->original_source_addr = htons((uint16_t) atoi(argv[3]));
            }
            else {
                print_usage();
                exit(1);
            }
            
            if (strcmp("-from", argv[4]) == 0) {
                recvfrom_addr = (uint16_t) atoi(argv[5]);
            }
            else {
                print_usage();
                exit(1);
            }
            
            if (strcmp("-path", argv[6]) == 0) {
                
                i = 0;
                dup = strdup(argv[7]);
                while ((token = strtok(dup, ",")) != NULL) {
                    
                    l3->source_routing[i] = atoi(token);
                    
                    i++;
                    dup = NULL;
                    
                    if (i > MAX_HOPS-1) break;
                }
                
                free(dup);
            }
            else {
                print_usage();
                exit(1);
            }
            
            if (strcmp("-port", argv[8]) == 0) {
                port = (uint8_t) atoi(argv[9]);
                l4->sport = port;
                l4->dport = port;
                l4->len = htons(FSCP_UDP_ID_BYTES);
            }
            else {
                print_usage();
                exit(1);
            }
            
            if (strcmp("-dev", argv[10]) == 0) {
                strcpy(output_interface.interface_name, argv[11]);
                fill_interface_info(&output_interface);
            }
            else {
                print_usage();
                exit(1);
            }
            
            if ((argc >= 13) && (strcmp("-f", argv[12]) == 0)) {
                if (argc >= 14) {
                    file_name = (char *) malloc(sizeof(char) * (strlen(argv[13]) + 1));
                    strcpy(file_name, argv[13]);
                }
                else {
                    print_usage();
                    exit(1);
                }
            }
            else {
                file_name = strdup("");
            }

            init_receiver(packet, recvfrom_addr, port, &output_interface, file_name);
            
        }
        else {
            print_usage();
            exit(1);
        }
        
    }
    else if (strcmp("-s", argv[1]) == 0) {
        if (argc >= 14) {

            if (strcmp("-src", argv[2]) == 0) {
                l2->original_source_addr = htons((uint16_t) atoi(argv[3]));
            }
            else {
                print_usage();
                exit(1);
            }
            
            if (strcmp("-dest", argv[4]) == 0) {
                recvfrom_addr = (uint16_t) atoi(argv[5]);
            }
            else {
                print_usage();
                exit(1);
            }

            if (strcmp("-path", argv[6]) == 0) {
                
                i = 0;
                dup = strdup(argv[7]);
                while ((token = strtok(dup, ",")) != NULL) {
                    
                    l3->source_routing[i] = atoi(token);
                    
                    i++;
                    dup = NULL;
                    
                    if (i > MAX_HOPS-1) break;
                }
                
                free(dup);
            }
            else {
                print_usage();
                exit(1);
            }
            
            if (strcmp("-port", argv[8]) == 0) {
                port = (uint8_t) atoi(argv[9]);
                l4->sport = port;
                l4->dport = port;
            }
            else {
                print_usage();
                exit(1);
            }
            
            if (strcmp("-dev", argv[10]) == 0) {
                strcpy(output_interface.interface_name, argv[11]);
                fill_interface_info(&output_interface);
            }
            else {
                print_usage();
                exit(1);
            }
            
            if (strcmp("-f", argv[12]) == 0) {
                file = fopen(argv[13], "r");
                if(!file) {
                    fprintf(stderr, "Error: cannot read the file %s\n", argv[13]);
                    exit(1);
                }
                
                stat(argv[13], &file_stat);
                file_size = file_stat.st_size;
                file_path = strdup(argv[13]);
                file_name = strdup(basename(file_path));
                
            }
            else {
                print_usage();
                exit(1);
            }
            
            if (argc >= 15) {
                if ((strcmp("-ack", argv[14]) == 0) && (argc >= 16)) {
                    required_acks = atoi(argv[15]);
                    if (required_acks == 0) {
                        required_acks = FSCP_DEFAULT_NUMBER_OF_ACKS;
                    }
                }
                #ifdef _THROTTLING_ENABLED
                else if ((strcmp("-bw", argv[14]) == 0) && (argc >= 16)) {
                    bandwidth = atoi(argv[15]);
                    bandwidth *= 125 * 1000;
                }
                #endif
                else {
                    print_usage();
                    exit(1);
                }
            }
            
            #ifdef _THROTTLING_ENABLED
            if (argc >= 17) {
                if ((strcmp("-bw", argv[16]) == 0) && (argc >= 18)) {
                    bandwidth = atoi(argv[17]);
                    bandwidth *= 125 * 1000;
                }
                else {
                    print_usage();
                    exit(1);
                }
            }
            #endif

            init_sender(packet, recvfrom_addr, port, port, &output_interface, file, file_size, file_name, required_acks, bandwidth);
            
        }
        else {
            print_usage();
            exit(1);
        }
        
    }
    else {
        print_usage();
        exit(1);
    }
    
    return 0;
}

void print_usage() {
    fprintf(stderr, "Error: invalid options\n");
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "  Receiver:\n");
    fprintf(stderr, "  fscp -r -src <saddr> -from <sender_addr> -path <routing_path_to_sender> -port <port_number> -dev <interface_name>\n");
    fprintf(stderr, "  fscp -r -src <saddr> -from <sender_addr> -path <routing_path_to_sender> -port <port_number> -dev <interface_name> [-f <filename>]\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "  Sender:\n");
    fprintf(stderr, "  fscp -s -src <saddr> -dest <daddr> -path <routing_path_to_receiver> -port <port_number> -dev <interface_name> -f <filename>\n");
    fprintf(stderr, "  fscp -s -src <saddr> -dest <daddr> -path <routing_path_to_receiver> -port <port_number> -dev <interface_name> -f <filename> [-ack numbers_of_ack]\n");
    #ifdef _THROTTLING_ENABLED
    fprintf(stderr, "  fscp -s -src <saddr> -dest <daddr> -path <routing_path_to_receiver> -port <port_number> -dev <interface_name> -f <filename> [-ack numbers_of_ack] [-bw Mbps]\n");
    #endif
    fprintf(stderr, "\n");
    fprintf(stderr, "  Tips:\n");
    fprintf(stderr, "  - Increasing numbers of acknowledgement will help improve throughput of transferring file through lossy networks.\n");
}
int read_arg_str(char ** v, char * n, const char * a) {
    if (strncmp(n, a, strlen(n) * sizeof(char)) == 0) {
        *v =  (char *) malloc(sizeof(char) * (strlen(a) - strlen(n) + 1));
        strncpy(*v, a + strlen(n), strlen(a) - strlen(n) + 1);
        return 1;
    }
    return 0;
}
int read_arg_int(int * i, char * n, const char * a) {
    char * temp;
    if (strlen(a) == strlen(n)) return false;
    if (strncmp(n, a, strlen(n) * sizeof(char)) == 0) {
        temp = (char *) malloc(sizeof(char) * (strlen(a) - strlen(n) + 1));
        strncpy(temp, a + strlen(n), strlen(a) - strlen(n) + 1);
        *i = atoi(temp);
        free(temp);
        return 1;
    }
    return 0;
}