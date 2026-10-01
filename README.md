# Network Packet Sniffer 🦈

A Python-based network analysis tool built to capture, unpack, and analyze live IPv4 traffic directly from the Network Interface Card (NIC). 

**Features:**
* Utilizes Python's native `socket` library to establish raw network sockets, bypassing high-level application protocols.
* Employs the `struct` module to unpack and decode binary IPv4 headers, extracting TTL, Protocol flags, and Source/Destination IPs.
* Implements Windows-specific socket I/O controls (`SIO_RCVALL`) to programmatically force the network adapter into promiscuous mode.
* Features a Wireshark-inspired, multi-threaded Tkinter UI that captures high-volume traffic without locking the main thread.

*Built as Day 18 of a 30-Day Network Engineering & Security portfolio streak. Note: Requires Administrator/root execution to bind raw sockets.*
