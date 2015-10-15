#include <stdio.h>
//#include <iostream>
#include <stdint.h>
//#include <cstring>
#include <string.h>
//#include <cstdlib>
#include <unistd.h>
#include <sys/stat.h>
#include <libgen.h>
#include "receiver.h"
#include "interface.h"
#include <stdbool.h>
//include interface.c file in the folder with interface.h and receiver.h and reciever.c
//using namespace std;
#define MAX_HOPS 2
struct layer3 {
    uint8_t  type;          // 0=layer4_icmp
    uint8_t  ttl;
    uint8_t  source_routing[MAX_HOPS];
};

//void print_usage();
bool read_arg_str(char ** v, char * n, const char * a);
bool read_arg_int(int * i, char * n, const char * a);

int main(int argc, const char * argv[]) {
   
   // char *host;
   // FILE *file;
   // long file_size = -1;
    char *file_path;
    char *file_name;
    unsigned char required_acks = FSCP_DEFAULT_NUMBER_OF_ACKS;
    struct interface output_interface;
    uint16_t from;
    struct layer3 *l3;
    char *dup, *token;
    int i;
   
    // Increase the priority of the process (max priority is -20, min is 19)
    if (setpriority(PRIO_PROCESS, 0, -15) < 0) {
        fprintf(stderr, "** It is recommend to run as a superuser! **\n");
    }

    if (strcmp("-r", argv[1]) == 0) { //./receiver

        //Begin receiving the file
        if (argc >= 3) {

           if(strcmp("-f", argv[2]) == 0) {
                file_name = (char *) malloc(sizeof(char) * (strlen(argv[3]) + 1));
                strcpy(file_name, argv[3]);
           }
            if (strcmp("-from", argv[4]) == 0) {
                   from = (uint16_t) atoi(argv[5]);
               }
            if (strcmp("-dev", argv[6]) == 0) {
                strcpy(output_interface.interface_name, argv[7]);
                fill_interface_info(&output_interface);
            }
            if((strcmp("-ack", argv[8]) == 0) && (argc >= 9)) {
                    required_acks = atoi(argv[9]);
                    if (required_acks == 0) {
                        required_acks = FSCP_DEFAULT_NUMBER_OF_ACKS;
           	    }
	     }	
	     if (strcmp("-path", argv[10]) == 0) {
	        i=0;
        	dup = strdup(argv[11]);
		l3 = (struct layer3 *) malloc(sizeof(struct layer3));
        	while((token = strtok(dup, ",")) != NULL) {
                	l3->source_routing[i] = atoi(token);
                	i++;
                	dup = NULL;
                	if (i > MAX_HOPS-1) break;
               }    
             }
     	init_receiver(file_name,from,&output_interface,required_acks,l3);
    }
   
}

}
