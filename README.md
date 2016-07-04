# DNS-Packet-Injection

In this project I have developed 1) an on-path DNS packet injector and
2) a passive DNS poisoning attack detector.
 
 
Libraries used :
Libpcap : sudo apt-get install libpcap-dev
		  sudo apt-get install pcaputil
Libnet 	: sudo apt-get install libnet1-dev

Part 1:

The DNS packet injector, named 'dnsinject', captures the traffic from a network
interface in promiscuous mode, and injects forged responses to selected DNS A
requests.

dnsinject [-i interface] [-f hostnames] 'expression'

Note: BPF filter 'expression' should be must be supplied in quotes.
Additionally to the user supplied BPF filter, a 'udp dst port 53' filter is used
in the code to filter only DNS packets and make the injector fast.

Approach: 
To read packets from live interface, pcap lib is used to capture packets in loop.
Then the requested domain name is extracted from the packet, and based on the
hostnames files and specific user filter in dnsinject command, injection is
done. A DNS reply packet is created and src and dest ip are copied in reverse
order for reply packet. Then either the IP corresponding to domain in hostfile 
or the user machine's IP is set in the DNS reply packet.
The packet is created and written to wire using libnet library api like:
libnet_build_udp()
libnet_build_ipv4()
libnet_write()
If no hostfile is specified, then injector injects all DNS requests.
The hostfile contains tab separated entries IP, DOMAIN

77.77.77.77	www.github.com


To run DNSINJECT:
sudo ./dnsinject
sudo ./dnsinject -f hostfile
sudo ./dnsinject -f hostfile


Note: If 'src <ip>' like filter is specified, then dnsinject only
injects victim specified in filter.


Part 2:

The DNS poisoning attack detector named 'dnsdetect', captures the traffic from
a network interface in promiscuous mode and detect DNS poisoning attack
attempts, such as those generated by dnsinject.

dnsdetect [-i interface] [-r tracefile] 'expression'

-i  Listen on network device <interface> (e.g., eth0). If not specified,
    the program selects a default interface to listen on.

-r  Read packets from <tracefile> (tcpdump format). Useful for detecting
    DNS poisoning attacks in existing network traces.

<expression> is a BPF filter that specifies a subset of the traffic to be
monitored. It should be written inside quotes.

Approach:
The program uses a BPF filter 'udp port 53' for listening only UDP packets on
port 53. It maintains a data of DNS reply packets in an array of pointers.
Once a DNS reply comes, its ID and IP are matched with list items
one by one. If ID of both dns headers mathces but there is mismatch in IP
address, it means that DNS poisoning attack has been done and an alert is 
printed on standard output to notify the user.
