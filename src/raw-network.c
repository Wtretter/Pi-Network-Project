#include "fix-checksums.h"
#include "raw-network.h"

#include <errno.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <linux/if.h>
#include <sys/epoll.h>

int open_port(char *interface_name, struct sockaddr_ll *interface_addr_out){
    int open_socket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if (open_socket == -1){
        printf("Failed to open Socket: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    // Ignore outgoing packets
    int ignore_out = 1;
    if (setsockopt(open_socket, SOL_PACKET, PACKET_IGNORE_OUTGOING, &ignore_out, sizeof ignore_out) == -1) {
        printf("failed to setsockopt PACKET_IGNORE_OUTGOING: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }


    // Get mac address of interface
    struct ifreq interface_request = {0};
    strncpy(interface_request.ifr_name, interface_name, IFNAMSIZ);
    if (ioctl(open_socket, SIOCGIFHWADDR, &interface_request) == -1) {
        printf("Failed to get MAC address of interface \"%s\"\n", interface_name);
        exit(EXIT_FAILURE);
    }
    uint8_t mac_address[6];
    memcpy(mac_address, interface_request.ifr_ifru.ifru_hwaddr.sa_data, 6);

    // Get index of interface
    strncpy(interface_request.ifr_name, interface_name, IFNAMSIZ);
    if (ioctl(open_socket, SIOCGIFINDEX, &interface_request) == -1) {
        printf("Failed to get index of interface \"%s\"\n", interface_name);
        exit(EXIT_FAILURE);
    }
    int interface_index = interface_request.ifr_ifru.ifru_ivalue;

    struct sockaddr_ll interface_address = {
        .sll_family = AF_PACKET,
        .sll_ifindex = interface_index,
        .sll_protocol = htons(ETH_P_ALL),
    };
    if (bind(open_socket, (struct sockaddr *)&interface_address, sizeof interface_address) == -1) {
        printf("Failed to bind to interface \"%s\"\n", interface_name);
        exit(EXIT_FAILURE);
    }
    memcpy(interface_addr_out, &interface_address, sizeof interface_address);
    return open_socket;
}

void setup_handler(port_handler_t *handler, char *left_if_name, char *right_if_name){
    handler->left_port = open_port(left_if_name, &handler->left_addr);
    handler->right_port = open_port(right_if_name, &handler->right_addr);
    handler->epoll_fd = epoll_create(2);

    struct epoll_event events;
    events.events = EPOLLIN;

    events.data.fd = handler->left_port;
    epoll_ctl(handler->epoll_fd, EPOLL_CTL_ADD, handler->left_port, &events);
    events.data.fd = handler->right_port;
    epoll_ctl(handler->epoll_fd, EPOLL_CTL_ADD, handler->right_port, &events);
} 

void register_fd(port_handler_t *handler, int fd){
    struct epoll_event events;
    events.events = EPOLLIN;

    events.data.fd = fd;
    epoll_ctl(handler->epoll_fd, EPOLL_CTL_ADD, fd, &events);
}

int get_packet(port_handler_t *handler, uint8_t *packet, size_t *packet_size){
    struct epoll_event events;
    if (epoll_wait(handler->epoll_fd, &events, 1, -1) == -1){
        printf("failed EPOLL_WAIT");
        exit(EXIT_FAILURE);
    }
    if (events.events & EPOLLERR){printf("EPOLLERR event\n"); exit(EXIT_FAILURE);}

    if (events.events & EPOLLHUP){printf("EPOLLHUP event\n"); exit(EXIT_FAILURE);}

    struct sockaddr_in sender_address = {0};
    socklen_t sender_address_length = sizeof sender_address;

    int ready_port = events.data.fd;
    ssize_t packet_length = recvfrom(ready_port, packet, MAX_PACKET_SIZE, 0, (struct sockaddr *)&sender_address, &sender_address_length);
    if (packet_length <= 0) {
        printf("Receive failed: %s\n", strerror(errno));
        close(ready_port);
        exit(EXIT_FAILURE);
    }

    *packet_size = packet_length;

    return ready_port;
}

void send_packet(port_handler_t *handler, uint8_t *packet, size_t packet_size, bool to_left){
    int out_port;
    struct sockaddr_ll *out_addr;
    if (to_left){
        out_port = handler->left_port;
        out_addr = &handler->left_addr;
    } else {
        out_port = handler->right_port;
        out_addr = &handler->right_addr;
    }
    
    fix_checksums(packet, packet_size);

    sendto(out_port, packet, packet_size, 0, (struct sockaddr *)out_addr, sizeof(*out_addr));
}