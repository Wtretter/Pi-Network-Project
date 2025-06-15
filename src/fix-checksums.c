#define _DEFAULT_SOURCE
#include <endian.h>
#include "fix-checksums.h"

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
