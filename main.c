#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <unistd.h>
#include <pcap.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "arpheader.h"

typedef enum { false, true} bool; 		/* Define Boolean Type	*/
typedef struct strarphdr{
	u_char sender_hw_addr[18];
	u_char sender_ip_addr[16];
}arphdr_str;

void parse_usr_mac_address(char*,arphdr*);
void parse_usr_ip_address (char*,arphdr*);
void parse_and_make_str(char*, arphdr*, arphdr_str*);

int main(int argc, char** argv){
	arphdr arp;
	arphdr_str arp_str;
	char* interface = argv[1];
	char ip[100] = "FUCK";

	parse_and_make_str(interface, &arp, &arp_str);
	printf("DEV : %s\n",interface);
	printf("MAC : %s\n",arp_str.sender_hw_addr);
	printf("IP  : %s\n",arp_str.sender_ip_addr);
	return 0;
}



void parse_usr_mac_address(char* interface, arphdr* arp){	/*MAKE MAC ADDRESS STRING*/
	int fd;
	struct ifreq ifr;
	u_char* mac = NULL;
	char ip[20];

	memset(&ifr, 0, sizeof(ifr));
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
	ioctl(fd, SIOCGIFHWADDR, &ifr);
	mac = (u_char*)ifr.ifr_hwaddr.sa_data;

	for(int i = 0 ; i < 6 ; i++){arp->sender_hw_addr[i] = mac[i];}
	close(fd);
}

void parse_usr_ip_address (char* interface, arphdr* arp){
	int fd;
	struct ifreq ifr;
	u_char* ip;
	
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name,interface,IFNAMSIZ-1);
	ioctl(fd,SIOCGIFADDR, &ifr);
	for(int i = 2 ; i < 6 ; i++) arp->sender_ip_addr[i-2] = ifr.ifr_addr.sa_data[i];
	close(fd);
}

void parse_and_make_str(char* interface, arphdr* arp, arphdr_str* arp_str){
	parse_usr_mac_address(interface, arp);
        sprintf(arp_str->sender_hw_addr,"%X:%X:%X:%X:%X:%X",arp->sender_hw_addr[0],arp->sender_hw_addr[1],arp->sender_hw_addr[2],arp->sender_hw_addr[3],arp->sender_hw_addr[4],arp->sender_hw_addr[5]);
        parse_usr_ip_address (interface, arp);
        sprintf(arp_str->sender_ip_addr,"%d.%d.%d.%d",arp->sender_ip_addr[0],arp->sender_ip_addr[1],arp->sender_ip_addr[2],arp->sender_ip_addr[3]);
}
