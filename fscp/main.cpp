//
//  main.cpp
//  fscp
//

#include <stdio.h>
#include <iostream>
#include <stdint.h>
#include <cstring>
#include <string.h>
#include <cstdlib>
#include <unistd.h>
#include <sys/stat.h>
#include <libgen.h>

#include "receiver.h"
#include "sender.h"
#include "layers.h"
#include "interface.h"
#define MAX_HOPS 2
using namespace std;

void print_usage();
bool read_arg_str(char ** v, char * n, const char * a);
bool read_arg_int(int * i, char * n, const char * a);

int main(int argc, const char * argv[]) {
    
    FILE *file;
    long file_size = -1;
    char *file_path, *file_name;
    struct stat file_stat;
    unsigned char required_acks = FSCP_DEFAULT_NUMBER_OF_ACKS;
    uint16_t destination;
    uint8_t  *source_routing=(uint8_t *)malloc(MAX_HOPS*sizeof(uint8_t));
    uint16_t src;
    uint8_t port;
    struct interface output_interface; 
    char *dup, *token;
    if (argc <= 1) {
        print_usage();
        exit(1);
    }
    
    // Increase the priority of the process (max priority is -20, min is 19)
    if (setpriority(PRIO_PROCESS, 0, -15) < 0) {
        fprintf(stderr, "** It is recommend to run as a superuser! **\n");
    }

    if (strcmp("-r", argv[1]) == 0) {
        
        //Begin receiving the file
        if (argc >= 3) {
            
            if ((argc >= 4) && (strcmp("-f", argv[2]) == 0)) {
                file_name = (char *) malloc(sizeof(char) * (strlen(argv[3]) + 1));
                strcpy(file_name, argv[3]);
                init_receiver(file_name);
            }
            else {
                print_usage();
                exit(1);
            }
        }
        else {
            file_name = strdup("");
            init_receiver(file_name);
        }
        
    }
    else if (strcmp("-s", argv[1]) == 0) {
        if (argc >= 14) {
            
            /*if (strcmp("-h", argv[2]) == 0) {
                host = (char *) malloc(sizeof(char) * strlen(argv[3]) + 1);
                memset(host, 0, strlen(argv[3]));
                strcpy(host, argv[3]);
            }
            else {
                print_usage();
                exit(1);
            }
            */
            if (strcmp("-src", argv[2]) == 0) {
        		src = (uint16_t) atoi(argv[3]);
			printf("\n src main .. %u",src);
    	    }
    	    else {
        		print_usage();
        		exit(1);
            }
 	    if (strcmp("-dest", argv[4]) == 0) {
                        destination = (uint16_t) atoi(argv[5]);
            }
            else {
                        print_usage();
                        exit(1);
            }
	    int i=0;
	    if (strcmp("-path", argv[6]) == 0) {

        		dup = strdup(argv[7]);
        		while ((token = strtok(dup, ",")) != NULL) {

            			source_routing[i] = atoi(token);

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
                    fprintf(stderr, "Error: cannot read the file %s\n", argv[5]);
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
                else {
                    print_usage();
                    exit(1);
                }
            }
            
            init_sender(src,destination,source_routing,port,&output_interface, file, file_size, file_name, required_acks);
            
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
    fprintf(stderr, "  fscp -r\n");
    fprintf(stderr, "  fscp -r [-f filename]\n");
    fprintf(stderr, "  fscp -s -h host -f filename\n");
    fprintf(stderr, "  fscp -s -h host -f filename [-ack numbers_of_ack]\n");
    fprintf(stderr, "    increasing numbers of acknowledgement will help improve\n");
    fprintf(stderr, "    throughput of transferring file through lossy networks.\n");
}
bool read_arg_str(char ** v, char * n, const char * a) {
    if (strncmp(n, a, strlen(n) * sizeof(char)) == 0) {
        *v =  (char *) malloc(sizeof(char) * (strlen(a) - strlen(n) + 1));
        strncpy(*v, a + strlen(n), strlen(a) - strlen(n) + 1);
        return true;
    }
    return false;
}
bool read_arg_int(int * i, char * n, const char * a) {
    char * temp;
    if (strlen(a) == strlen(n)) return false;
    if (strncmp(n, a, strlen(n) * sizeof(char)) == 0) {
        temp = (char *) malloc(sizeof(char) * (strlen(a) - strlen(n) + 1));
        strncpy(temp, a + strlen(n), strlen(a) - strlen(n) + 1);
        *i = atoi(temp);
        free(temp);
        return true;
    }
    return false;
}
