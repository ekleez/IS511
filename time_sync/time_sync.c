#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "time.h"
#include "sys/socket.h"
#include "sys/types.h"
#include "netinet/in.h"
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netdb.h>

int get_local_ip(char *);
unsigned short csum(unsigned short *, int);

// Pseudo Header
struct packet_header{
	unsigned int source_address;
	unsigned int dest_address;
	unsigned char placeholder;
	unsigned char protocol;
	unsigned short tcp_length;

	struct tcphdr tcp;
};

// Main : Create Session With Server & Send RST TCP packet via connection
// Usage : a.out <IP address> (ex > %./a.out 143.248.230.81 )
void main(int argc, char *argv[]){

	char datagram[1024*4];
	struct sockaddr_in server_addr;

	int i;
	struct sockaddr_in sin;
	socklen_t len = sizeof(sin);

	int client_fd;
	struct linger so_linger;
	so_linger.l_onoff = 1;
	so_linger.l_linger = 0;

	// IP Datagram, TCP packet (IP datagram + TCP header)
	struct iphdr *iph = (struct iphdr *) datagram;
	struct tcphdr *tcph = (struct tcphdr *)(datagram +sizeof(struct ip));
	struct packet_header packet;

	if(argc != 2)
		exit(0);

	// Create Socket for Connect with Server
	if((client_fd = socket(PF_INET, SOCK_RAW, IPPROTO_TCP)) < 0){
		printf("Can't create socket\n");
		exit(0);
	}
	bzero((char *)&server_addr, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = inet_addr(argv[1]);
	server_addr.sin_port = htons(80);

	
	int one = 1;
	const int *val = &one;
	
	if(setsockopt(client_fd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0){
		printf("Error setting IP_HDRINCL.");
		exit(0);
	}
	
	if(connect(client_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0){
		printf("Can't connect\n");
		exit(0);
	}

	// Check the Port number which is connected to server
	if(getsockname(client_fd, (struct sockaddr *)&sin, &len) == 0)
		printf("Port number %d\n", ntohs(sin.sin_port));

	// Fresh datagram before fill the header
	memset(datagram, 0, 1024*4);

	// Get source IP & Port to make IP packet
	int source_port = ntohs(sin.sin_port);
	char source_ip[20];
	get_local_ip(source_ip);

	// Fill In the IP Header (Some value is random ex id)
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = sizeof(struct ip) + sizeof(struct tcphdr);
	iph->id = htons(5525);
	iph->frag_off = htons(0);
	iph->ttl = 64;
	iph->protocol = IPPROTO_TCP;
	iph->check = 0;
	iph->saddr = inet_addr(source_ip);
	iph->daddr = server_addr.sin_addr.s_addr;

	iph->check = csum((unsigned short *)datagram, iph->tot_len >> 1);

	//Fill In the TCP Header (Some value is random ex window)
	tcph->source = htons(source_port);
	tcph->dest = htons(80);
	tcph->seq = htonl(0);
	tcph->ack_seq = 0;
	tcph->doff = sizeof(struct tcphdr)/4;
	tcph->fin = 0;
	tcph->syn = 0;
	tcph->rst = 1;
	tcph->psh = 0;
	tcph->ack = 0;
	tcph->urg = 0;
	tcph->window = htons(29200);
	tcph->check = 0;
	tcph->urg_ptr = 0;

	//setsockopt(client_fd, SOL_SOCKET, SO_LINGER, &so_linger, sizeof(so_linger));

	// Send 50 packet with delay 1 sec. Seq, ACK # shoould be added ( Not implemented ) & checksum should be recalculated
	for(i = 1; i<51; i++){
		// Zero the checksum for recalculating
		tcph->dest = htons(80);
		tcph->check = 0;

		packet.source_address = inet_addr(source_ip);
		packet.dest_address = server_addr.sin_addr.s_addr;
		packet.placeholder = 0;
		packet.protocol = IPPROTO_TCP;
		packet.tcp_length = htons(sizeof(struct tcphdr));
		
		memcpy(&packet.tcp, tcph, sizeof(struct tcphdr));

		tcph->check = csum((unsigned short *)&packet, sizeof(struct packet_header));

		//Send the packet
		if(sendto(client_fd, datagram, sizeof(struct iphdr) + sizeof(struct tcphdr), 0, (struct sockaddr *)&server_addr, sizeof(server_addr)) <0){
			printf("Error sending packet.\n");
			exit(0);
		}
		//sleep(1);
		printf("Send %d Packet\n", i);
	}

	close(client_fd);
}

// Making Checksum function
unsigned short csum(unsigned short *ptr, int nbytes){
	register long sum;
	unsigned short oddbyte;
	unsigned short answer;

	sum = 0;
	while(nbytes>1){
		sum+=*ptr++;
		nbytes-=2;
	}
	if(nbytes == 1){
		oddbyte = 0;
		*((u_char *)&oddbyte) = *(u_char *)ptr;
		sum+=oddbyte;
	}
	sum = (sum>>16)+(sum & 0xffff);
	sum = sum + (sum >>16);
	answer = (short)~sum;

	return answer;
}

// Get local IP address from Google DNS
int get_local_ip(char *buffer){

	int sock				 					= socket(AF_INET, SOCK_DGRAM, 0);
	const char *DNSIP 				= "8.8.8.8";
	int dns_port				 			= 53;
	struct sockaddr_in 					serv;

	memset(&serv, 0, sizeof(serv));
	serv.sin_family						= AF_INET;
	serv.sin_addr.s_addr			= inet_addr(DNSIP);
	serv.sin_port							= htons(dns_port);

	int	err										= connect(sock, (const struct sockaddr *) &serv, sizeof(serv));

	struct sockaddr_in					name;
	socklen_t namelen					= sizeof(name);
	
	err = getsockname(sock, (struct sockaddr *)&name, &namelen);

	const char *p							= inet_ntop(AF_INET, &name.sin_addr, buffer, 100);

	close(sock);
}
