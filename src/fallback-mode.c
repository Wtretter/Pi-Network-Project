#include <errno.h>
#include <endian.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/un.h>

#include "raw-network.h"
#include "fix-checksums.h"
#include "check-packet.h"


int main(int argc, char **argv){
    if (argc != 3){
        printf("not right args;\n Usage: %s <Interface Name> <Interface Name>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    port_handler_t handler;

    setup_handler(&handler, argv[1], argv[2]);

    uint8_t packet[MAX_PACKET_SIZE];
    
    time_t start_time = time(NULL);
    while (time(NULL) <= start_time + 10) {
        size_t packet_size;
        
        int ready_port = get_packet(&handler, packet, &packet_size);
       
        bool to_left;
        if (ready_port == handler.left_port){
            to_left = false;
        }
        else if (ready_port == handler.right_port){
            to_left = true;
        } else {
            int out_port = *(int32_t *)(packet + packet_size - 4);
            packet_size -= 4;
            if (out_port == handler.left_port){
                to_left = false;
            } else{
                to_left = true;
            }
        }

        send_packet(&handler, packet, packet_size, to_left);
    }

    printf("attempting automatic restart of main program\n");
    pid_t pid = fork();

    if (pid == 0){
        char *child_argv[4] = {"./packet-sorter", argv[1], argv[2], NULL};
        execvp("./packet-sorter", child_argv);
        printf("failed exec: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    exit(EXIT_SUCCESS);
}