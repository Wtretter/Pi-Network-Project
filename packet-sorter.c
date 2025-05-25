#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <sys/ioctl.h>


unsigned short csum(unsigned short *buf, int nwords)
{
    unsigned long sum;
    for(sum=0; nwords>0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum &0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}


int main(int argc, char **argv){
    if (argc != 2){
        printf("not right args\n");
        exit(EXIT_FAILURE);
    }

    int s = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if (s == -1){
        printf("Failed to open Socket\n");
        exit(EXIT_FAILURE);
    }

    // Get mac address of interface
    struct ifreq interface_request = {0};
    strncpy(interface_request.ifr_name, argv[1], IFNAMSIZ);
    if (ioctl(s, SIOCGIFHWADDR, &interface_request) == -1) {
        printf("Failed to get MAC address of interface \"%s\"\n", argv[1]);
        exit(EXIT_FAILURE);
    }
    uint8_t mac_address[6];
    memcpy(mac_address, interface_request.ifr_ifru.ifru_hwaddr.sa_data, 6);

    // Get index of interface
    strncpy(interface_request.ifr_name, argv[1], IFNAMSIZ);
    if (ioctl(s, SIOCGIFINDEX, &interface_request) == -1) {
        printf("Failed to get index of interface \"%s\"\n", argv[1]);
        exit(EXIT_FAILURE);
    }
    int interface_index = interface_request.ifr_ifru.ifru_ivalue;

    struct sockaddr_ll interface_address = {
        .sll_family = AF_PACKET,
        .sll_ifindex = interface_index,
        .sll_protocol = htons(ETH_P_ALL),
    };
    if (bind(s, (struct sockaddr *)&interface_address, sizeof interface_address) == -1) {
        printf("Failed to bind to interface \"%s\"\n", argv[1]);
        exit(EXIT_FAILURE);
    }

    // Receive packets in a loop
    struct sockaddr_in sender_address = {0};
    socklen_t sender_address_length = sizeof sender_address;
    size_t max_packet_size = 65535;
    uint8_t packet[max_packet_size];

    while (true) {
        ssize_t packet_length = recvfrom(s, packet, max_packet_size, 0, (struct sockaddr *)&sender_address, &sender_address_length);
        if (packet_length <= 0) {
            printf("Receive failed\n");
            close(s);
            exit(EXIT_FAILURE);
        }

        printf("Received packet of length: %zd\n", packet_length);
        for (ssize_t i=0; i < packet_length; i++) {
            printf("%02x ", packet[i]);
        }
        printf("\n");

        break;
    }
}