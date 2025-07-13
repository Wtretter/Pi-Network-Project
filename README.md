# Dependencies
- Clang
- Make
- Python3
    - Scapy
    - Requests

# Getting Started
- run `make` from the project top level directory
- run `./packet-sorter <interface 1> <interface 2>` as root
    - for a list of available interfaces, run `ip a`

# Notes
- to utilize a custom Blacklist, create a file called "blacklist" at the project's top level directory
    - each entry on the blacklist must be seperated by a new line
    - comments may be added with #
- if no custom blacklist is provided, the program will attempt to pull a default blacklist from "https://v.firebog.net/hosts/AdguardDNS.txt"