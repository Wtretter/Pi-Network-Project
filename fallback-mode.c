#include <errno.h>
#include <endian.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <sys/un.h>

void fix_checksums(uint8_t *packet, size_t packet_length);
void fix_ipv4_checksums(uint8_t *packet, size_t packet_length);
void fix_ipv6_checksums(uint8_t *packet, size_t packet_length);
void fix_tcp_checksums(uint8_t *packet, size_t packet_length, uint32_t pseudoheader);
void fix_udp_checksums(uint8_t *packet, size_t packet_length, uint32_t pseudoheader);
bool check_packet(uint8_t *packet, size_t packet_length);
bool check_packet_ipv4(uint8_t *packet, size_t packet_length);
bool check_packet_ipv6(uint8_t *packet, size_t packet_length);
bool check_packet_tcp(uint8_t *packet, size_t packet_length);
bool check_packet_udp(uint8_t *packet, size_t packet_length);


void fix_checksums(uint8_t *packet, size_t packet_length){
    int ether_type = be16toh(*(uint16_t *)(packet + 12));
    if (ether_type == 0x0800){
        fix_ipv4_checksums(packet + 14, packet_length - 14);
    }
    else if (ether_type == 0x86DD){
        fix_ipv6_checksums(packet + 14, packet_length - 14);
    }
}

void fix_ipv4_checksums(uint8_t *packet, size_t packet_length){
    int protocol = packet[9];
    int header_length = ((packet[0] & 0b00001111) * 4);
    uint32_t pseudo_header = 0;
    pseudo_header += be16toh(*(uint16_t *)(packet + 12));
    pseudo_header += be16toh(*(uint16_t *)(packet + 14));
    pseudo_header += be16toh(*(uint16_t *)(packet + 16));
    pseudo_header += be16toh(*(uint16_t *)(packet + 18));
    pseudo_header += protocol;
    pseudo_header += (packet_length - header_length);

    // tcp
    if (protocol == 0x06){
        fix_tcp_checksums(packet + header_length, packet_length - header_length, pseudo_header);
    }
    // udp
    if (protocol == 0x11){
        fix_udp_checksums(packet + header_length, packet_length - header_length, pseudo_header);
    }

}

void fix_ipv6_checksums(uint8_t *packet, size_t packet_length){
    int protocol = packet[6];

    uint32_t pseudo_header = 0;
    for (size_t i = 8; i < 40; i += 2){
        pseudo_header += be16toh(*(uint16_t *)(packet + i));
    }
    pseudo_header += protocol;
    pseudo_header += (packet_length - 40);
     // tcp
    if (protocol == 0x06){
        fix_tcp_checksums(packet + 40, packet_length - 40, pseudo_header);
    }
    // udp
    if (protocol == 0x11){
        fix_udp_checksums(packet + 40, packet_length - 40, pseudo_header);
    }
}

void fix_tcp_checksums(uint8_t *packet, size_t packet_length, uint32_t pseudoheader){
    uint32_t checksum = pseudoheader;
    *(uint16_t *)(packet + 16) = htobe16(0);
    if (packet_length %2 == 1){
        packet[packet_length] = 0x00;
    }
    for (size_t i=0; i < packet_length; i += 2){
        checksum += be16toh(*(uint16_t *)(packet + i));
    }
    uint32_t top = checksum >> 16;
    uint32_t bottom = checksum & 0x0000ffff;
    uint32_t new_checksum = top + bottom;
    top = new_checksum >> 16;
    bottom = new_checksum & 0x0000ffff;
    new_checksum = top + bottom;
    new_checksum = ~new_checksum;
    *(uint16_t *)(packet + 16) = htobe16((uint16_t)new_checksum);
}

void fix_udp_checksums(uint8_t *packet, size_t packet_length, uint32_t pseudoheader){
    uint32_t checksum = pseudoheader;
    *(uint16_t *)(packet + 6) = htobe16(0);
    if (packet_length %2 == 1){
        packet[packet_length] = 0x00;
    }
    for (size_t i=0; i < packet_length; i += 2){
        checksum += be16toh(*(uint16_t *)(packet + i));
    }
    uint16_t top = checksum >> 16;
    uint16_t bottom = checksum & 0x0000ffff;
    uint16_t new_checksum = top + bottom;
    new_checksum = ~new_checksum;
    *(uint16_t *)(packet + 6) = htobe16(new_checksum);
}

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


int main(int argc, char **argv){
    if (argc != 3){
        printf("not right args;\n Usage: %s <Interface Name> <Interface Name>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in sender_address = {0};
    socklen_t sender_address_length = sizeof sender_address;
    size_t max_packet_size = 65535;
    uint8_t packet[max_packet_size];
    
    struct sockaddr_ll left_addr;
    struct sockaddr_ll right_addr;
    int left_port = open_port(argv[1], &left_addr);
    int right_port = open_port(argv[2], &right_addr);
    int out_port;
    struct sockaddr_ll *out_addr;

    int epoll_fd = epoll_create(2);
    struct epoll_event events;
    events.events = EPOLLIN;

    events.data.fd = left_port;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, left_port, &events);
    events.data.fd = right_port;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, right_port, &events);

    int n = 0;
    while (n < 10) {
        
        printf("fallback loop - %d loops until automatic restart of main program\n", (10 - n));

        if (epoll_wait(epoll_fd, &events, 1, -1) == -1){
            printf("failed EPOLL_WAIT");
            exit(EXIT_FAILURE);
        }
        if (events.events & EPOLLERR){printf("EPOLLERR event\n"); exit(EXIT_FAILURE);}

        if (events.events & EPOLLHUP){printf("EPOLLHUP event\n"); exit(EXIT_FAILURE);}

        int ready_port = events.data.fd;
        ssize_t packet_length = recvfrom(ready_port, packet, max_packet_size, 0, (struct sockaddr *)&sender_address, &sender_address_length);
        if (packet_length < 0) {
            printf("Receive failed: %s\n", strerror(errno));
            close(ready_port);
            exit(EXIT_FAILURE);
        } else if (packet_length == 0){
            printf("ready port: %d\n", ready_port);
            continue;
        }

        if (ready_port == left_port){
            out_port = right_port;
            out_addr = &right_addr;
        }
        else{
            out_port = left_port;
            out_addr = &left_addr;
        }

        fix_checksums(packet, packet_length);

        sendto(out_port, packet, packet_length, 0, (struct sockaddr *)out_addr, sizeof(*out_addr));

        n += 1;
    }

    close(epoll_fd);

    printf("attempting automatic restart of main program\n");

    pid_t pid = fork();

    if (pid == 0){
        sleep(3);
        char *child_argv[4] = {"./packet-sorter", argv[1], argv[2], NULL};
        execvp("./packet-sorter", child_argv);
        printf("failed exec: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
   }
    exit(EXIT_SUCCESS);
}