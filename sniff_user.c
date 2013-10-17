/*

   This is the user level program that runs and connects to the
   kernel module.

*/

#include <errno.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <linux/icmp.h>
#include <sys/ioctl.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_arp.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include "ioctl.h"
#include "filter.h"

#define DEFAULT 0
#define ETHERNET 1
#define IP 2
#define ICMP 3

#define PROMISC 1

// user buffer for sniffed packets
user_buf  buffer[3];

// user rules to apply for filtering
filter_t myrules[3]={
	{FILTER_IP_PROTO,IP_PROTO_LEN,0x06},
	{FILTER_TCP_DPORT,TCP_DPORT_LEN,0x0016},
	{0,0,0}
};

/*filter_t myrules[2]={
	{FILTER_IP_PROTO,IP_PROTO_LEN,0x01},
	{0,0,0}
};*/
//the filter and mode options
int filter = 0;
int mode = 0;

//delcaring the function
void print_packet(char *buffer);

//The main function
int main(int argc, char *argv[]){

        int fd = 0;		//file descriptor to the device
	int nBytes = 0;		//total bytes read
	int i = 0;		//loop counter
	int total = 0;		//total packets read while active

	if(argc == 3){
		filter = atoi(argv[1]);
		mode = atoi(argv[2]);
	}
	
	//opening the device
        fd = open("/root/sniff/sniffer",0);
	// sending the network card mode option using ioctl
	if(mode == 1) {
		ioctl(fd, IOCTL_PROM, PROMISC);
	}

	// sending the filter option using ioctl
	switch (filter) {
		case 0 : 
			 if(ioctl(fd, IOCTL_FILTER,(unsigned long)&myrules)<0)
			 {
				 perror("ioctl failed 4");
				 return 0;
			 }
			 break;
		
		default:if(ioctl(fd, IOCTL_HARDRESET, NULL)<0)
			{
				perror("ioctl failed to reset ");
				return 0;
			}
			//return 0;
			
	}

	for(;;){
	//reading from the device
        while ( (nBytes=read(fd,(char *)buffer,3)) !=0 ) {
        	for(i=0;i<nBytes;i++){
             		total++;
             		print_packet((char *)(buffer+i));
          	}
        }
	}
	printf("Total packets read = %d\n",total);
       
	//setting the card to normal
	ioctl(fd, IOCTL_PROM, -1);
	
	//closing the device
	close(fd);
}


/* This function prints the packet */
void print_packet(char *buffer){
        
	//The Ethernet header
	struct ethhdr *eth;
	struct ether_addr *eth_addr_s;
        struct ether_addr *eth_addr_d;

	//The IP header 
        struct iphdr *ip;
        struct in_addr ipaddress;
	unsigned char *pkt;
        user_buf *x = (user_buf *) buffer;
	
	// extract ethernet header
        eth = (struct ethhdr *)&(x->pkt_hdr.mac.eth);
        eth_addr_s = (struct ether_addr *)eth->h_source;
        eth_addr_d = (struct ether_addr *)eth->h_dest;
	
	printf("\nEthernet Header--> ");
	printf("Dest: %s Src: %s Protocol: %d\n", ether_ntoa(eth_addr_s),\
			ether_ntoa(eth_addr_d), eth->h_proto);

	if(eth->h_proto == 8){// IP	
		
		//Extracting the IP data
		printf("IP Header--> ");
        	ip = (struct iphdr *) &(x->buff[14]);
        	ipaddress.s_addr = ip->saddr;
        	printf("Src: %s ", inet_ntoa(ipaddress));
        	ipaddress.s_addr = ip->daddr;
        	printf("Dest: %s ", inet_ntoa(ipaddress));
		printf("TTL: %u ",ip->ttl);
		printf("Protocol: %u \n",ip->protocol);
		switch(ip->protocol){
		    case 1:
			    // Extract ICMP packet
			    printf("ICMP Header--> ");
			    { 
				short *echo = (short*) &x->buff[42];
				short *seq = (short*) &x->buff[40];
			    	printf("Type: %u Code: %u ",x->buff[34]
					    ,x->buff[35]);
			    	printf("Echo id: %u ",ntohs(*echo));
			    	printf("Echo sequence: %u \n",ntohs(*seq));
			    }
			    break;
		    case 6:
			    // Extract TCP packet
			    printf("TCP Header--> ");
			    {
				short *srcp = (short*)&x->buff[34];
				short *destp = (short*)&x->buff[36];
			    	printf("Src port: %u ",ntohs(*srcp)); 
			    	printf("Dest port: %u \n",ntohs(*destp)); 
			    }
			    break;
		    case 17:
			    // Extract UDP packet
			    printf("UDP Header--> "); 
			    {
				short *srcp = (short*)&x->buff[34];
				short *destp = (short*)&x->buff[36];
			    	printf("Src port: %u ",ntohs(*srcp)); 
			    	printf("Dest port: %u \n",ntohs(*destp)); 
			    }
			    break;
		    default:	    
		};
	}
	else if(eth->h_proto ==0){
		// Extract ARP packet
		struct arphdr *arph = (struct arphdr *)&(x->buff[14]);
		printf("ARP Header--> ");
		printf("Opcode: %u",arph->ar_op);
	}

        return;
}

 
