# PocketGenerator

PocketGenerator - data transfer protocol packet generator at various levels of the ISO/OSI model. 

The package generation software module performs the following functions:
- allows the user to form any IP, TCP, UDP and ICMP (only Echo request and Echo Reply) packet in terms of filling in all protocol fields (including reserved ones);
- automatic detection of the present network interfaces and the ability to select the desired interface by the user;
- automatic formation of information on link-level packets (Ethernet 802.3) - the MAC address of the sender and the MAC address of the recipient at the specified ip-addresses;
- allows the user to enter incorrect data into the protocol fields (length, checksum, fragmentation, etc.);
- formation of a sequence from the generated network packets and the implementation of sending these packets via the interface selected by the user. 
