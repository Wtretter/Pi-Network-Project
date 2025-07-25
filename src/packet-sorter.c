#define _POSIX_C_SOURCE 1

#include <errno.h>
#include <endian.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
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

bool interupted = false;

bool send_to_python(uint8_t *packet, size_t packet_length, int python_fd, int out_port){
    *(int32_t *)(packet + packet_length) = out_port;
    packet_length += 4;
    if (send(python_fd, packet, packet_length, 0) == -1){
        return false;
    }
    return true;
}

void interrupt_handler(int sig){
    interupted = true;
}

void fallback(int argc, char **argv){
    char *child_argv[4] = {"./fallback-mode", argv[1], argv[2], NULL};
    execvp("./fallback-mode", child_argv);
    printf("failed exec: %s\n", strerror(errno));
    exit(EXIT_FAILURE);
}

int main(int argc, char **argv){
    if (argc != 3){
        printf("not right args;\n Usage: %s <Interface Name> <Interface Name>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    printf("Welcome to Packet-Filter!\n");

    signal(SIGINT, interrupt_handler);

    port_handler_t handler;

    setup_handler(&handler, argv[1], argv[2]);

    pid_t pid = fork();
    if (pid == 0){
        char *child_argv[2] = {"./dns-checker.py", NULL};
        execvp("./dns-checker.py", child_argv);
        printf("failed exec: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
   }
    sleep(3);

    uint8_t packet[MAX_PACKET_SIZE];

    struct sockaddr_un python_addr;
    python_addr.sun_family = AF_UNIX;
    strcpy(python_addr.sun_path, "./packet.sock");
    int python_fd = socket(PF_UNIX, SOCK_STREAM, 0);
    if (connect(python_fd, (struct sockaddr *)&python_addr, sizeof(python_addr)) == -1) {
        printf("failed to open connection to python: %s\n", strerror(errno));
    
        // go into fallback mode
        fallback(argc, argv);
    }

    register_fd(&handler, python_fd);
    
    while (!interupted) {
        size_t packet_size;
        
        int ready_port = get_packet(&handler, packet, &packet_size);
        if (ready_port == 0){
            continue;
        }

        if (ready_port == -1){
            if (interupted){
                break;
            }
            fallback(argc, argv);
        }

        bool to_left;
        if (ready_port == handler.left_port){
            to_left = false;
        }
        else if (ready_port == handler.right_port){
            to_left = true;
        } else {
            int out_port = *(int32_t *)(packet + packet_size - 4);
            packet_size -= 4;
            if (out_port == -1){
                interupted = true;
                break;
            }
            else if (out_port == handler.left_port){
                to_left = false;
            } else{
                to_left = true;
            }
        }

        if (ready_port != python_fd && check_packet(packet + 12, packet_size - 12)){
            if (!send_to_python(packet, packet_size, python_fd, ready_port)){
                send_packet(&handler, packet, packet_size, to_left);
                // go into fallback mode
                fallback(argc, argv);
            }
        }
        else {
            send_packet(&handler, packet, packet_size, to_left);
        }
    }
    // kill python so it doesn't run forever
    kill(pid, SIGTERM);
    exit(EXIT_SUCCESS);
}