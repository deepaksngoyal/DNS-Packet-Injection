#include <stdio.h>
#include <unistd.h>
#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <time.h>
#include <errno.h>
#include <resolv.h>

#define ETHER_ADDR_LEN 6
#define SIZE_ETHERNET 14
#define ETHERTYPE_IPV4 0x0800
#define IP_HL(ip)       (((ip)->ip_vhl) & 0x0f)

#define INTERFACE 0
#define FILE 1

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

pcap_t *pcap_handle;
in_addr_t my_ip = 0;
int isFileOrInterface = 0;

struct spoof_domain {
	u_short id;
	char *ip;
};

struct spoof_domain *list[10];
int delete_index = 0;
char *check_spoofing(u_short id, char *ip) {
	int i = 0;
	for(i = 0; i < 10 ; i++) {
		if(list[i] == NULL) {
			list[i] = malloc(sizeof(struct spoof_domain));
			list[i]->ip = strdup(ip);
			list[i]->id = id;
			return NULL;
		}
		if(list[i]->id == id && strcmp(list[i]->ip,ip)) {
			return list[i]->ip;
		}
	}
	free(list[delete_index]->ip);
	list[delete_index]->ip = strdup(ip);
	list[delete_index]->id = id;

	delete_index = (delete_index+1)%10;
	return NULL;
}

void stop(int itr) {
	printf("\nStopping dnsdetect...\n");
	pcap_close(pcap_handle);
	exit(itr);
}

void handle_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	const struct eth_header *ethernet;
	const struct ip_header *ip;
	const struct udp_header *udp;
	u_char *dns_query;
	const struct dns_header *dns_header;
	u_char *dns_end;
	char host_name[MAXHOSTNAMELEN];
	int size_ip;
	int size_udp = 8;
	int i = 0;
	u_short id = 0;
	u_short qtype = 0;
	u_short qclass = 0;
	struct in_addr spoof_ip;
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
		/*Handle only DNS response packets, src port is 53 in them*/
		if(ntohs(udp->sport) != 53) {
			return;
		}
		dns_header = (struct dns_header*)(((u_char*) udp) + sizeof(struct udp_header));
		dns_query = ((u_char*)dns_header) + sizeof(struct dns_header);
		
		int size = dn_expand((u_char *)dns_header, dns_end, dns_query, host_name, sizeof(host_name));
		
		u_char * ptr = dns_query;
		ptr = ptr + size;
		
		GETSHORT(qtype, ptr);
		GETSHORT(qclass, ptr);
		if(qtype != 1)
			return;
		memcpy(&spoof_ip, ptr + 12, sizeof(spoof_ip));
		GETSHORT(id, dns_header);
		char * rec_ip = inet_ntoa(spoof_ip);
		char *saved_ip = check_spoofing(id, rec_ip);
		if(saved_ip != NULL) {
			printf("DNS poisoning attack:\n");
			printf("TXID: 0x%x Request: %s\n", id, host_name);
			printf("Answer 1: %s\n", saved_ip);
			printf("Answer 2: %s\n", rec_ip);
		}
	}
}

int main(int argc, char *argv[]) {
	int option;
	int err = 0;
	char *trace_file = NULL;
	char *dev = NULL;
	char *filter_exp = NULL;
	char err_buf[PCAP_ERRBUF_SIZE];

	bpf_u_int32 netp=0, maskp=0;
	struct bpf_program fp;
	char dns_filter[256];

    	while ((option = getopt(argc, argv, "i:r:")) != -1) {
		switch(option) {
			case 'i': {
				dev = optarg;
				isFileOrInterface = INTERFACE;
				break;
			}
			case 'r': {
				trace_file = optarg;
				isFileOrInterface = FILE;
				break;
			}

			case '?': {
				printf("Unknown argument!\n");
				printf("Usage : dnsinject [-i interface] [-r tracefile] expression\n");
				return 0;
			}
		}
	}

    	if (optind == argc - 1)
		filter_exp = argv[optind];
	if (dev != NULL && trace_file != NULL) {
		printf("mydump : Specify either interface or trace file, can't handle both.\n");
		printf("Usage : mydump [-i interface] [-r taracefile] expression\n");
		return(2);
	}
	if(dev == NULL && trace_file == NULL) {
		dev = pcap_lookupdev(err_buf);
		if(dev == NULL) {
			printf("Error : %s\n", err_buf);
			return(1);
		} else {
			isFileOrInterface = INTERFACE;
		}
    	}
	
	if (isFileOrInterface == FILE) {
		//read from pcap dump file
		pcap_handle = pcap_open_offline(trace_file, err_buf);
		if (pcap_handle == NULL) {
			printf("Error in opening dump file: %s\n", err_buf);
			return(2);
		}
    	} else {
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
	}
	if (pcap_datalink(pcap_handle) != DLT_EN10MB) {
		fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", dev);
		return(2);
	}
	memset(dns_filter, '\0', 256);
	if(filter_exp != NULL) {
		sprintf(dns_filter, "%s and udp port 53", filter_exp);
	} else {
		sprintf(dns_filter, "udp port 53");
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
	printf("******************* dnsdetect running ********************\n");
    	pcap_loop(pcap_handle, -1, handle_packet, NULL);
	stop(0);
}