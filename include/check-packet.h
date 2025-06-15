#ifndef CHECK_PACKET_H
#define CHECK_PACKET_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

bool check_packet(uint8_t *packet, size_t packet_length);
bool check_packet_ipv4(uint8_t *packet, size_t packet_length);
bool check_packet_ipv6(uint8_t *packet, size_t packet_length);
bool check_packet_tcp(uint8_t *packet, size_t packet_length);
bool check_packet_udp(uint8_t *packet, size_t packet_length);

#endif