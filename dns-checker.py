#!/usr/bin/env python3

import socket
import os

def handle_client(client: socket.socket, address):
    while True:
        packet = client.recv(8192)

        

        client.send(packet)
        

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
        except:
            client.close()
        

    server.close()


main()