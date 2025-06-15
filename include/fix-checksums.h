#ifndef FIX_CHECKSUMS_H
#define FIX_CHECKSUMS_H

#include <stdint.h>
#include <stddef.h>

void fix_checksums(uint8_t *packet, size_t packet_length);
void fix_ipv4_checksums(uint8_t *packet, size_t packet_length);
void fix_ipv6_checksums(uint8_t *packet, size_t packet_length);
void fix_tcp_checksums(uint8_t *packet, size_t packet_length, uint32_t pseudoheader);
void fix_udp_checksums(uint8_t *packet, size_t packet_length, uint32_t pseudoheader);

#endif