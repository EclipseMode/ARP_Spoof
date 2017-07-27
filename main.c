#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

void parse_usr_mac_address(char*,arphdr*);
void parse_usr_ip_address (char*,arphdr*);
void parse_and_make_str(char*, arphdr*, arphdr_str*);

int main(int argc, char** argv){
	arphdr arp;
	arphdr_str arp_str;
	char* interface = argv[1];

	parse_and_make_str(interface, &arp, &arp_str);
	printf("DEV : %s\n",interface);
	printf("MAC : %s\n",arp_str.sender_hw_addr);
	printf("IP  : %s\n",arp_str.sender_ip_addr);
	return 0;
}



void parse_usr_mac_address(char* interface, arphdr* arp){			/*PARSE MAC ADDRESS*/
	int fd;
	struct ifreq ifr;
	u_char* mac = NULL;;

	memset(&ifr, 0, sizeof(ifr));
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
	ioctl(fd, SIOCGIFHWADDR, &ifr);
	mac = (u_char*)ifr.ifr_hwaddr.sa_data;

	for(int i = 0 ; i < __MACADDR_LEN__ ; i++){arp->sender_hw_addr[i] = mac[i];}
	close(fd);
}

void parse_usr_ip_address (char* interface, arphdr* arp){			/*PARSE IP  ADDRESS*/
	int fd;
	struct ifreq ifr;
	u_char* ip;
	const int IPADDR_START = 2;
	
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name,interface,IFNAMSIZ-1);
	ioctl(fd,SIOCGIFADDR, &ifr);
	for(int i = IPADDR_START ; i < IPADDR_START + __IPADDR_LEN__ ; i++) arp->sender_ip_addr[i-2] = ifr.ifr_addr.sa_data[i];
	close(fd);
}

void parse_and_make_str(char* interface, arphdr* arp, arphdr_str* arp_str){	/*MAKE IP / MAC STR*/
	parse_usr_mac_address(interface, arp);
        sprintf(arp_str->sender_hw_addr,"%X:%X:%X:%X:%X:%X",arp->sender_hw_addr[0],arp->sender_hw_addr[1],arp->sender_hw_addr[2],arp->sender_hw_addr[3],arp->sender_hw_addr[4],arp->sender_hw_addr[5]);
        parse_usr_ip_address (interface, arp);
        sprintf(arp_str->sender_ip_addr,"%d.%d.%d.%d",arp->sender_ip_addr[0],arp->sender_ip_addr[1],arp->sender_ip_addr[2],arp->sender_ip_addr[3]);
}
