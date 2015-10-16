//
//  main.c
//  router
//
//  Created by Peera Yoodee on 9/23/15.
//

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/resource.h>
#include "interface.h"
#include "route.h"
#include "sniffer.h"

#define _VERBOSE

void print_usage();

int main(int argc, const char * argv[]) {
    
    int i;
    char *arg_interface = NULL;
    char *token, *dup;
    
    int num_input_interfaces = 0;
    struct interface *input_interface;
    
    if (argc <= 1) {
        print_usage();
        exit(1);
    }
    
    // Read command line arguments
    if (strcmp("-i", argv[1]) == 0) {
        arg_interface = strdup(argv[2]);
    }
   
    /*
     * CPU Prioritization
     *
     */
    // Increase the priority of the process (max priority is -20, min is 19)
    if (setpriority(PRIO_PROCESS, 0, -20) < 0) {
        fprintf(stderr, "** It is recommend to run as a superuser! **\n");
    }
    
    /*
     * Listening Interfaces - defined in command line arguments
     *
     */
    
    // Realloc doesn't work so we count commas to approx the number of interfaces
    for (i=0; i<strlen(arg_interface); i++) {
        if (arg_interface[i] == ',') num_input_interfaces++;
    }
    num_input_interfaces++;
    
    // Allocate input interface array
    input_interface = (struct interface *) malloc(num_input_interfaces * sizeof(struct interface));
    
    // Parse input interfaces
    num_input_interfaces = 0;
    dup = strdup(arg_interface);
    while ((token = strtok(dup, ",")) != NULL) {
        
        strcpy(input_interface[num_input_interfaces].interface_name, token);
        fill_interface_info(&input_interface[num_input_interfaces]);
        
        // Interface name is valid
        if (input_interface[num_input_interfaces].interface_index != -1) {
            num_input_interfaces++;
        }
        
        dup = NULL;
        
    }
    
    free(arg_interface);
    
    // Print listening interfaces information
    #ifdef _VERBOSE
    fprintf(stderr, "[LISTENING INTERFACES]\n");
    fprintf(stderr, "   Number of listening interfaces: %d\n", num_input_interfaces);
    fprintf(stderr, "   %-5s %-6s %-19s %-15s\n", "Dev", "DevId", "Interface MAC addr", "Inf IP addr");
    for(i=0; i<num_input_interfaces; i++) {
        fprintf(stderr, "%2d ", i+1);
        fprintf_interface(stderr, &input_interface[i]);
    }
    fprintf(stderr, "\n");
    #endif

    
    /*
     * Start packet sniffing threads
     *
     */
    pthread_t thread[num_input_interfaces];
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
    
    struct sniffer_thread_parameter params[num_input_interfaces];
    
    for (i=0; i<num_input_interfaces; i++) {
        
        fprintf(stderr, "[Start sniffer #%d - %s]\n", i+1, input_interface[i].interface_name);
        
        params[i].interfaces = &input_interface;
        params[i].num_interfaces = num_input_interfaces;
        params[i].sniff_interface = i;
        
        if (pthread_create(&thread[i], &attr, sniffer_thread, (void *) &params[i]) < 0) {
            fprintf(stderr, "Error: Can not create a thread for the sniffer_thread in main()\n");
        }
        
    }

    for (i=0; i<num_input_interfaces; i++) {
        pthread_join(thread[i], NULL);
    }
    
    return 0;
    
}

void print_usage() {
    fprintf(stderr, "Error: invalid options\n");
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "  fscp -i eth0,eth1\n");
}
