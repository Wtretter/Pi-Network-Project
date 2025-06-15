#define _DEFAULT_SOURCE
#include <endian.h>
#include "check-packet.h"

bool check_packet(uint8_t *packet, size_t packet_length){
    int ether_type = be16toh(*(uint16_t *)(packet));
    if (ether_type == 0x0800){
        return check_packet_ipv4(packet + 2, packet_length - 2);
    }
    else if (ether_type == 0x86DD){
        return check_packet_ipv6(packet + 2, packet_length - 2);
    } else{
        return false;
    }
}

bool check_packet_ipv4(uint8_t *packet, size_t packet_length){
    int protocol = packet[9];
    int header_length = ((packet[0] & 0b00001111) * 4);
    if (protocol == 0x06){
        return check_packet_tcp(packet + header_length, packet_length - header_length);
    } else if (protocol == 0x11){
        return check_packet_udp(packet + header_length, packet_length - header_length);
    } else{
        return false;
    }
}

bool check_packet_ipv6(uint8_t *packet, size_t packet_length){
    int protocol = packet[6];
    if (protocol == 0x06){
        return check_packet_tcp(packet + 40, packet_length - 40);
    } else if (protocol == 0x11){
        return check_packet_udp(packet + 40, packet_length - 40);
    } else{
        return false;
    }
}

bool check_packet_tcp(uint8_t *packet, size_t packet_length){
    return false;
}

bool check_packet_udp(uint8_t *packet, size_t packet_length){
    uint16_t src_port = be16toh(*(uint16_t *)(packet));
    uint16_t dst_port = be16toh(*(uint16_t *)(packet + 2));
    if (src_port == 53||dst_port == 53){
        return true;
    } else{
        return false;
    }
}
