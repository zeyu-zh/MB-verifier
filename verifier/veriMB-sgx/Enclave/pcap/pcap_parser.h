#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#ifndef _PCAP_PARSER_H_
#define _PCAP_PARSER_H_

#define swap16(A) ((((uint16_t)(A) & 0xff00) >> 8) | (((uint16_t)(A) & 0x00ff) << 8))
#define swap32(A) ((((uint32_t)(A) & 0xff000000) >> 24) | \
				   (((uint32_t)(A) & 0x00ff0000) >>  8) | \
				   (((uint32_t)(A) & 0x0000ff00) <<  8) | \
				   (((uint32_t)(A) & 0x000000ff) << 24))


typedef struct pcap_hdr {
    uint32_t magic_number;   /* magic number */
    uint16_t version_major;  /* major version number */
    uint16_t version_minor;  /* minor version number */
    int32_t  thiszone;       /* GMT to local correction */
    uint32_t sigfigs;        /* accuracy of timestamps */
    uint32_t snaplen;        /* max length of captured packets, in bytes */
    uint32_t network;        /* data link type */
} __attribute__((packed)) PCAP_HDR;

typedef struct pcaprec_hdr {
    uint32_t ts_sec;         /* timestamp seconds */
    uint32_t ts_usec;        /* timestamp microseconds */
    uint32_t incl_len;       /* number of octets of packet saved in file */
    uint32_t orig_len;       /* actual length of packet */
} __attribute__((packed)) PCAP_PKHDR;

typedef struct ethernet_hdr {
	uint8_t dst_mac[6]; 
	uint8_t src_mac[6];
	uint16_t type_length;  /* NETWORK ORDER */ 
} __attribute__((packed)) ETH_HDR;

typedef struct ipv4_hdr {
	uint8_t vers_hdrlen;
	uint8_t dscp_ecn;
	uint16_t total_len;         /* NETWORK ORDER */
	uint16_t identification;         /* NETWORK ORDER */
	uint16_t flags_frag_ofs;        /* NETWORK ORDER */
	uint8_t ttl;
	uint8_t proto; 
	uint16_t hdr_checksum;         /* NETWORK ORDER */
	uint32_t src_ip;         /* NETWORK ORDER */
	uint32_t dst_ip;         /* NETWORK ORDER */
    uint16_t a;
    uint16_t b;
    uint16_t c;
    uint16_t d;
} __attribute__((packed)) IPV4_HDR;



typedef struct tcp_hdr {
	uint16_t src_port;        /* NETWORK ORDER */
	uint16_t dst_port;         /* NETWORK ORDER */
	uint32_t seq_num;         /* NETWORK ORDER */
	uint32_t ack_num;        /* NETWORK ORDER */
	uint16_t ofs_ctrl;        /* NETWORK ORDER */        
	uint16_t window_size;         /* NETWORK ORDER */
	uint16_t checksum;         /* NETWORK ORDER */
	uint16_t urgent_pointer;         /* NETWORK ORDER */
} __attribute__((packed)) TCP_HDR;

typedef struct udp_hdr {
	uint16_t src_port;        /* NETWORK ORDER */
	uint16_t dst_port;         /* NETWORK ORDER */
	uint16_t total_len;        /* NETWORK ORDER */
	uint16_t checksum;         /* NETWORK ORDER */
} UDP_HDR;

typedef struct icmp_hdr {
	uint8_t type;
	uint8_t code;
	uint16_t checksum;  /* NETWORK ORDER */
} __attribute__((packed)) ICMP_HDR;



typedef struct veri_data {
    uint16_t* p_a; /* the a of each packet */
    uint16_t* p_b;
    uint16_t* p_c;
    uint16_t* p_d; 
    uint8_t** p_data; /* the payload of each packet */
    int* p_len; /* the length of each packet's payload */
    int amount; /* packet number in this pcap file*/
} VERI_DATA;


int get_pcap_data(const char* path, VERI_DATA* p_veri_data);
void destory_pcap_data(VERI_DATA* p_veri_data);



#endif

