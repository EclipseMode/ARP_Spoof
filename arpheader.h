#pragma once

#include <stdint.h>

typedef unsigned char u_char;

#define __IPTYPE__ 4

#define __MACADDR_LEN__ 6
#define __IPADDR_LEN__ 4

#define __ETHERTYPE_ARP__ 0x0806

typedef struct arpheader{					/* 	Define ARP Header Struct	*/
	uint16_t	hw_type;				//[H a r d w a r e T y p e : 2 b y t e s ] 
	uint16_t 	proto_type;				//[P r o t o c o l T y p e : 2 b y t e s ]
	u_char		hw_addr_len;				//[h w a d d r l e n g t h : 2 b y t e s ]
	u_char		proto_addr_len;				//[p t a d d r l e n g t h : 2 b y t e s ]
	uint16_t	operation;				//[                        o p e r a t i o n : 4 b y t e s                     ]
	u_char		sender_hw_addr[__MACADDR_LEN__];	//[                        s e n d e r m a c : 4 b y t e s                     ]
	u_char		sender_ip_addr[__IPADDR_LEN__];		//[                        s e n d e r i p   : 4 b y t e s                     ]
	u_char		target_hw_addr[__MACADDR_LEN__];		//[                        t a r g e t m a c : 4 b y t e s                     ]
	u_char		target_ip_addr[__IPADDR_LEN__];		//[                        t a r g e t i p   : 4 b y t e s                     ]
}arphdr;

typedef struct strarphdr{					/*	Define String Address	*/
	u_char 		sender_hw_addr[18];
	u_char		sender_ip_addr[16];
}arphdr_str;

typedef enum {false, true} bool;				/*	Define Boolean Type	*/
