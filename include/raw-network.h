#ifndef RAW_NETWORK_H
#define RAW_NETWORK_H

#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>


#define MAX_PACKET_SIZE 65535

typedef struct port_handler
{
    int epoll_fd;
    struct sockaddr_ll left_addr;
    struct sockaddr_ll right_addr;
    int left_port;
    int right_port;
} port_handler_t;


int open_port(char *interface_name, struct sockaddr_ll *interface_addr_out);
bool setup_handler(port_handler_t *handler, char *left_if_name, char *right_if_name);
void register_fd(port_handler_t *handler, int fd);
int get_packet(port_handler_t *handler, uint8_t *packet, size_t *packet_size);
void send_packet(port_handler_t *handler, uint8_t *packet, size_t packet_size, bool to_left);

#endif