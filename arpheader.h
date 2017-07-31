#pragma once

#include <stdint.h>

typedef unsigned char u_char;
typedef unsigned short u_short;

#define __IPTYPE__ 4

#define __MACADDR_LEN__ 6
#define __IPADDR_LEN__ 4

#define __ETHERTYPE_ARP__ 0x0806

#define __ARP_REQUEST__ 1
#define __ARP_REPLY__ 2

typedef struct ethheader{
	uint8_t 	src_hw_addr[6];
	uint8_t		dst_hw_addr[6];
	uint16_t	type;
}ethernet;

typedef struct arpheader{					/* 	Define ARP Header Struct	*/
	uint16_t	hw_type;				//[H a r d w a r e T y p e : 2 b y t e s ] 
	uint16_t 	proto_type;				//[P r o t o c o l T y p e : 2 b y t e s ]
	uint8_t		hw_addr_len;				//[h w a d d r l e n g t h : 2 b y t e s ]
	uint8_t		proto_addr_len;				//[p t a d d r l e n g t h : 2 b y t e s ]
	uint16_t 	operation;				//[                        o p e r a t i o n : 4 b y t e s                     ]
	uint8_t		src_hw_addr[6];				//[                        s e n d e r m a c : 4 b y t e s                     ]
	uint8_t		src_ip_addr[4];				//[                        s e n d e r i p   : 4 b y t e s                     
	uint8_t		dst_hw_addr[6];				//[                        t a r g e t m a c : 4 b y t e s                     ]
	uint8_t		dst_ip_addr[4];				//[                        t a r g e t i p   : 4 b y t e s                     ]
}arphdr;

typedef enum {false, true} bool;				/*	Define Boolean Type	*/
