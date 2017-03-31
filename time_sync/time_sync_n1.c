#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <linux/ip.h>
#include <linux/tcp.h>

#define MAX_PLEN 8192

// Packet length
//#define PCKT_LEN 8192

// May create separate header file (.h) for all
// headers' structures
// IP header's structure
/*struct ipheader {
	unsigned char      iph_ihl : 5, /* Little-endian */
/*		iph_ver : 4;
	unsigned char      iph_tos;
	unsigned short int iph_len;
	unsigned short int iph_ident;
	unsigned char      iph_flags;
	unsigned short int iph_offset;
	unsigned char      iph_ttl;
	unsigned char      iph_protocol;
	unsigned short int iph_chksum;
	unsigned int       iph_sourceip;
	unsigned int       iph_destip;
};
gc
/* Structure of a TCP header */
/*struct tcpheader {
	unsigned short int tcph_srcport;
	unsigned short int tcph_destport;
	unsigned int       tcph_seqnum;
	unsigned int       tcph_acknum;
	unsigned char      tcph_reserved : 4, tcph_offset : 4;
	// unsigned char tcph_flags;
	unsigned int
		tcp_res1 : 4,       /*little-endian*/
//		tcph_hlen : 4,      /*length of tcp header in 32-bit words*/
//		tcph_fin : 1,       /*Finish flag "fin"*/
//		tcph_syn : 1,       /*Synchronize sequence numbers to start a connection*/
//		tcph_rst : 1,       /*Reset flag */
//		tcph_psh : 1,       /*Push, sends data to the application*/
//		tcph_ack : 1,       /*acknowledge*/
//		tcph_urg : 1,       /*urgent pointer*/
//		tcph_res2 : 2;
/*	unsigned short int tcph_win;
	unsigned short int tcph_chksum;
	unsigned short int tcph_urgptr;
};*/

// Simple checksum function, may use others such as Cyclic Redundancy Check, CRC
/*unsigned short csum(unsigned short *buf, int len)
{
	unsigned long sum;
	for (sum = 0; len>0; len--)
		sum += *buf++;
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return (unsigned short)(~sum);
}

unsigned short csum(unsigned short *addr, int len)
{
	int sum = 0;
	int nleft = len;
	unsigned short *w = addr;
	unsigned short res = 0;
	
	while (nleft > 1)
	{
		sum += *w++;
	}
}*/

struct pseudohdr
{
	uint32_t saddr;
	uint32_t daddr;
	uint8_t useless;
	uint8_t protocol;
	uint16_t tcplength;
	
	struct tcphdr th;
};

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

unsigned short chksum(u_short *addr, int len)
{
    int sum=0;
    int nleft = len;
    unsigned short *w=addr;
    unsigned short answer = 0;
     
    while (nleft > 1)
	{
        sum += *w++;
        nleft -= 2;
    }  
    
    if (nleft == 1)
	{
        *(u_char *)(&answer) = *(u_char *)w ;
        sum += answer;
    }
 
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);                
    answer = ~sum;                     
    return(answer);                    
}

void print_iphdr(struct iphdr *p)
{	
}

void print_tcphdr(struct tcphdr *p)
{
	printf("%x %x\n", ntohl(p->seq), ntohl(p->ack_seq));
}
 

int main(int argc, char *argv[])
{
	int sockfd;
	int on = 1;
	int rlen;
	
	uint32_t n_seq, n_ack;
	
	struct iphdr *ip_hdr, *rip_hdr;
	struct tcphdr *tcp_hdr, *rtcp_hdr;
	
	struct sockaddr_in target_addr;
	struct in_addr src_addr, dst_addr;
	
	struct pseudohdr pseudo_hdr;
	
	char send_buf[MAX_PLEN], recv_buf[MAX_PLEN];
	//int sd;
	// No data, just datagram
	//char buffer[PCKT_LEN];
	// The size of the headers
	//struct ipheader *ip = (struct ipheader *) buffer;
	//struct tcpheader *tcp = (struct tcpheader *) (buffer + sizeof(struct ipheader));
	//struct sockaddr_in sin, din;
	//int one = 1;
	//const int *val = &one;
	
	src_addr.s_addr = inet_addr("192.168.69.128");
	dst_addr.s_addr = inet_addr(argv[1]);
	
	memset(send_buf, 0, sizeof(send_buf));
	
	sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if (sockfd < 0)
	{
		perror("socket error");
		exit(1);
	}
	
	setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, (char *)&on, sizeof(on));
	
	tcp_hdr = (struct tcphdr *)(send_buf + sizeof(struct iphdr));
	
	memset((char *)tcp_hdr, 0, 20);
	
	tcp_hdr->source = htons(55555);
	tcp_hdr->dest = htons(80);
	tcp_hdr->seq = htonl(0x12345678);
	tcp_hdr->ack_seq = htonl(0);
	tcp_hdr->doff = 5;
	tcp_hdr->syn = 1;
	tcp_hdr->window = htons(32767);
	tcp_hdr->check = 0;
	
	pseudo_hdr.saddr = src_addr.s_addr;
	pseudo_hdr.daddr = dst_addr.s_addr;
	pseudo_hdr.useless = 0;
	pseudo_hdr.protocol = IPPROTO_TCP;
	pseudo_hdr.tcplength = htons(sizeof(struct tcphdr));
	
	memcpy(&pseudo_hdr.th, tcp_hdr, sizeof(struct tcphdr));
	tcp_hdr->check = csum((unsigned short *)&pseudo_hdr, sizeof(struct pseudohdr));

	/*pseudo_hdr = (struct pseudohdr *)((char *)tcp_hdr - sizeof(struct pseudohdr));
	pseudo_hdr->saddr = src_addr.s_addr;
	pseudo_hdr->daddr = dst_addr.s_addr;
	pseudo_hdr->protocol = IPPROTO_TCP;
	pseudo_hdr->tcplength = htons(sizeof(struct tcphdr));
	
	tcp_hdr->check = chksum((unsigned short *)pseudo_hdr, sizeof(struct pseudohdr) + sizeof(struct tcphdr));*/
	
	ip_hdr = (struct iphdr *)send_buf;
	
	memset((char *)ip_hdr, 0, 20);
	
	ip_hdr->ihl = 5;
	ip_hdr->version = 4;
	ip_hdr->tos = 0;
	ip_hdr->tot_len = 40;
	ip_hdr->protocol = IPPROTO_TCP;
	ip_hdr->id = htons(777);
	ip_hdr->ttl = 64;
	ip_hdr->saddr = src_addr.s_addr;
	ip_hdr->daddr = dst_addr.s_addr;
	ip_hdr->check = 0;
	
	//ip_hdr->check = csum((unsigned short *)send_buf, (sizeof(struct iphdr) + sizeof(struct tcphdr)));
	ip_hdr->check = chksum((unsigned short *)ip_hdr, sizeof(struct iphdr));
	
	target_addr.sin_family = AF_INET;
	target_addr.sin_port = htons(80);
	target_addr.sin_addr.s_addr = dst_addr.s_addr;
	
	// send syn
	sendto(sockfd, send_buf, ip_hdr->tot_len, 0, (struct sockaddr *)&target_addr, sizeof(target_addr));
	
	rlen = sizeof(target_addr);
	// recv syn, ack
	recvfrom(sockfd, recv_buf, sizeof(recv_buf), 0, (struct sockaddr *)&target_addr, &rlen);
	
	rip_hdr = (struct iphdr *)recv_buf;
	rtcp_hdr = (struct tcphdr *)(recv_buf + sizeof(struct iphdr));
	
	print_iphdr(rip_hdr);
	print_tcphdr(rtcp_hdr);
	
	tcp_hdr->seq = htonl(ntohl(rtcp_hdr->ack_seq));
	tcp_hdr->ack_seq = htonl(ntohl(rtcp_hdr->seq) + 1);
	tcp_hdr->syn = 0;
	tcp_hdr->ack = 1;
	tcp_hdr->check = 0;
	
	pseudo_hdr.saddr = src_addr.s_addr;
	pseudo_hdr.daddr = dst_addr.s_addr;
	pseudo_hdr.useless = 0;
	pseudo_hdr.protocol = IPPROTO_TCP;
	pseudo_hdr.tcplength = htons(sizeof(struct tcphdr));
	
	memcpy(&pseudo_hdr.th, tcp_hdr, sizeof(struct tcphdr));
	tcp_hdr->check = csum((unsigned short *)&pseudo_hdr, sizeof(struct pseudohdr));

	/*pseudo_hdr = (struct pseudohdr *)((char *)tcp_hdr - sizeof(struct pseudohdr));
	pseudo_hdr->saddr = src_addr.s_addr;
	pseudo_hdr->daddr = dst_addr.s_addr;
	pseudo_hdr->protocol = IPPROTO_TCP;
	pseudo_hdr->tcplength = htons(sizeof(struct tcphdr));
	
	tcp_hdr->check = chksum((unsigned short *)pseudo_hdr, sizeof(struct pseudohdr) + sizeof(struct tcphdr));*/	
	
	// send ack
	sendto(sockfd, send_buf, ip_hdr->tot_len, 0, (struct sockaddr *)&target_addr, sizeof(target_addr));	
	
	FILE *out = fopen("out.bin", "wb");
	fwrite(recv_buf, 1, sizeof(recv_buf), out);
	fclose(out);
	
	close(sockfd);
	//memset(buffer, 0, PCKT_LEN);

	/*if (argc != 5)
	{
		printf("- Invalid parameters!!!\n");
		printf("- Usage: %s <source hostname/IP> <source port> <target hostname/IP> <target port>\n", argv[0]);
		exit(-1);
	}

	sd = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
	if (sd < 0)
	{
		perror("socket() error");
		exit(-1);
	}
	else
		printf("socket()-SOCK_RAW and tcp protocol is OK.\n");
*/
	// The source is redundant, may be used later if needed
	// Address family
	/*sin.sin_family = AF_INET;
	din.sin_family = AF_INET;
	// Source port, can be any, modify as needed
	sin.sin_port = htons(atoi(argv[2]));
	din.sin_port = htons(atoi(argv[4]));
	// Source IP, can be any, modify as needed
	sin.sin_addr.s_addr = inet_addr(argv[1]);
	din.sin_addr.s_addr = inet_addr(argv[3]);
	// IP structure
	ip->iph_ihl = 5;
	ip->iph_ver = 4;
	ip->iph_tos = 16;
	ip->iph_len = sizeof(struct ipheader) + sizeof(struct tcpheader);
	ip->iph_ident = htons(54321);
	ip->iph_offset = 0;
	ip->iph_ttl = 64;
	ip->iph_protocol = 6; // TCP
	ip->iph_chksum = 0; // Done by kernel

						// Source IP, modify as needed, spoofed, we accept through command line argument
	ip->iph_sourceip = inet_addr(argv[1]);
	// Destination IP, modify as needed, but here we accept through command line argument
	ip->iph_destip = inet_addr(argv[3]);

	// The TCP structure. The source port, spoofed, we accept through the command line
	tcp->tcph_srcport = htons(atoi(argv[2]));
	// The destination port, we accept through command line
	tcp->tcph_destport = htons(atoi(argv[4]));
	tcp->tcph_seqnum = htonl(1);
	tcp->tcph_acknum = 0;
	tcp->tcph_offset = 5;
	tcp->tcph_syn = 1;
	tcp->tcph_ack = 0;
	tcp->tcph_win = htons(32767);
	tcp->tcph_chksum = 0; // Done by kernel
	tcp->tcph_urgptr = 0;
	// IP checksum calculation
	ip->iph_chksum = csum((unsigned short *)buffer, (sizeof(struct ipheader) + sizeof(struct tcpheader)));

	// Inform the kernel do not fill up the headers' structure, we fabricated our own
	if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
	{
		perror("setsockopt() error");
		exit(-1);
	}
	else
		printf("setsockopt() is OK\n");

	printf("Using:::::Source IP: %s port: %u, Target IP: %s port: %u.\n", argv[1], atoi(argv[2]), argv[3], atoi(argv[4]));

	// sendto() loop, send every 2 second for 50 counts
	unsigned int count;
	for (count = 0; count < 20; count++)
	{
		if (sendto(sd, buffer, ip->iph_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)
			// Verify
		{
			perror("sendto() error");
			exit(-1);
		}
		else
			printf("Count #%u - sendto() is OK\n", count);
		sleep(2);
	}
	close(sd);*/
	return 0;
}