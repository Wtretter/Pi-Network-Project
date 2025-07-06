#!/usr/bin/env python3

import socket
import os
import requests
import datetime
from scapy.layers.l2 import Ether
from scapy.layers.dns import DNS, EDNS0TLV


log_file = open("dns.log", "a")

try:
    with open("blacklist", "r") as blacklist_file:
        pre_blacklist = blacklist_file.read().splitlines()
except FileNotFoundError:
    print("Blacklist empty, fetching default list")

    url = f"https://v.firebog.net/hosts/AdguardDNS.txt"
    response = requests.get(url)
    new_blacklist = response.text
    pre_blacklist = new_blacklist.splitlines()

    with open("blacklist", "w") as blacklist_file:
        blacklist_file.write(new_blacklist)

blacklist = []

for item in pre_blacklist:
    item = item.strip()
    if item.startswith("#"):
        continue
    if not item:
        continue
    blacklist.append(item)

def handle_client(client: socket.socket, address):
    while True:
        modified = False
        packet = client.recv(8192)

        packet, ident = packet[:-4], packet[-4:]
    
        parsed_packet = Ether(packet)
        dns_message = parsed_packet.lastlayer()
        if isinstance(dns_message, DNS):
            req_domain = dns_message.fields["qd"].qname.decode()[:-1]
            requesting_ip = get_sender_ip(packet)
            time = datetime.datetime.now().strftime("%d-%m-%Y %H:%M:%S")
            log_message = f"{time} {requesting_ip} requested: {req_domain}"
            if not dns_message.fields["qr"]:
                if req_domain in blacklist:
                    
                    log_file.write(log_message + " (BLOCKED)\n")
                    log_file.flush()
                else:    
                    log_file.write(log_message + "\n")
                    log_file.flush()
            else:
                if req_domain in blacklist:
                    remove_dns_answers(parsed_packet)
                    modified = True
        else:
            print("Packet not DNS")

        # parsed_packet.show()


        # print(dns_message.fields)

        if modified:
            packet = parsed_packet.build()
            eth_header = packet[:14]
            next_proto = int.from_bytes(packet[12:14])
            if next_proto == 0x0800:
                # IPV4
                ipv4_len = int.from_bytes(packet[16:18])
                pre_len = packet[14:16]
                rest_of_packet = packet[18:]
                correct_ip_len = len(packet) - 14
                if ipv4_len != correct_ip_len:
                    print("IPV4 len incorrect, fixing")
                    packet = eth_header + pre_len + correct_ip_len.to_bytes(2) + rest_of_packet
                    ihl = (packet[14] & 0b00001111) * 4
                    udp_header_start = 14 + ihl
                    packet_b4_udp_len = packet[:udp_header_start+4]
                    packet_after_udp_len = packet[udp_header_start+6:]
                    udp_len = int.from_bytes(packet[udp_header_start+4:udp_header_start+6])
                    correct_udp_len = len(packet) - udp_header_start
                    if udp_len != correct_udp_len:
                        packet = packet_b4_udp_len + correct_udp_len.to_bytes(2) + packet_after_udp_len


            elif next_proto == 0x86DD:
                # IPV6
                pass
            else:
                print("Invalid Next Protocol")

        parsed_packet = Ether(packet)
        
        # print(packet.hex(bytes_per_sep=1, sep=" "), "\n")
        parsed_packet.show()
        packet += ident
        client.send(packet)
        

def remove_dns_answers(parsed_packet: Ether):
    dns_message: DNS = parsed_packet.lastlayer()
    dns_message.fields["ancount"] = 0
    dns_message.fields["an"] = None
    dns_message.fields["rcode"] = 5
    dns_message.fields["aa"] = 0

    dns_message.fields["ar"].fields["rdata"] = [EDNS0TLV(optcode=15, optlen=2, optdata='\x00\x17')]
    dns_message.fields["ar"].fields["rdlen"] = 6

    
def get_sender_ip(packet: bytes) -> str:
    ether_type = int.from_bytes(packet[12:14], "big")

    if ether_type == 0x0800:
        return "ipv4"
    
    elif ether_type == 0x86DD:
        return "ipv6"
    
    else: 
        print("failed to decode EtherType")

def main():
    try:
        os.unlink("./packet.sock")
    except FileNotFoundError:
        pass
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind("./packet.sock")

    server.listen()

    while True:
        client, address = server.accept()
        try:
            handle_client(client, address)
        finally:
            client.close()
        
    server.close()


main()