#pragma once

#include <socket.h>

typedef unsigned char u_char;
typedef unsigned short u_short;

#define __IPTYPE__ 4

#define __MACADDR_LEN__ 6
#define __IPADDR_LEN__ 4

#define __ETHERTYPE_ARP__ 0x0806

typedef struct arpheader{					/* 	Define ARP Header Struct	*/
	u_short		hw_type;				//[H a r d w a r e T y p e : 2 b y t e s ] 
	u_short 	proto_type;				//[P r o t o c o l T y p e : 2 b y t e s ]
	u_char		hw_addr_len;				//[h w a d d r l e n g t h : 2 b y t e s ]
	u_char		proto_addr_len;				//[p t a d d r l e n g t h : 2 b y t e s ]
	u_short 	operation;				//[                        o p e r a t i o n : 4 b y t e s                     ]
	u_char		src_hw_addr[__MACADDR_LEN__];		//[                        s e n d e r m a c : 4 b y t e s                     ]
	u_char		src_ip_addr[__IPADDR_LEN__];		//[                        s e n d e r i p   : 4 b y t e s                     ]
	u_char		dst_hw_addr[__MACADDR_LEN__];		//[                        t a r g e t m a c : 4 b y t e s                     ]
	u_char		dst_ip_addr[__IPADDR_LEN__];		//[                        t a r g e t i p   : 4 b y t e s                     ]
}arphdr;

typedef struct arprequest{
	struct		sockaddr arp_pa;
	struct 		sockaddr arp_ha;
	int 		arp_flags;
}arpreq;

typedef enum {false, true} bool;				/*	Define Boolean Type	*/
