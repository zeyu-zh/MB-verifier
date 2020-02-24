#ifndef _PKTREADER_H_
#define _PKTREADER_H_

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#define PACKET_DATA_OFFSET(p,type,offset) ((p)?((type)(p+(offset))):0)

#define IP_HLEN 20
#define IP_PROTO_ICMP 1
#define IP_PROTO_UDP 17
#define IP_PROTO_TCP 6

#define BigLittleSwap16(A)  ((((uint16_t)(A) & 0xff00) >> 8) | (((uint16_t)(A) & 0x00ff) << 8))
#define BigLittleSwap32(A)  ((((uint32_t)(A) & 0xff000000) >> 24) | (((uint32_t)(A) & 0x00ff0000) >> 8) | \
                            (((uint32_t)(A) & 0x0000ff00) << 8) | (((uint32_t)(A) & 0x000000ff) << 24))

struct in_addr {
    unsigned long s_addr;  // load with inet_aton()
};
struct sockaddr_in {
    short            sin_family;   // e.g. AF_INET
    unsigned short   sin_port;     // e.g. htons(3490)
    struct in_addr   sin_addr;     // see struct in_addr, below
    char             sin_zero[8];  // zero this if you want to
};



class PktReader
{
public:
	PktReader() {
		this->packet = NULL; 
        this->length = 0;
		//ip_header_offset = ether_len;
	}
	PktReader(uint8_t* pkg, size_t length) {
		this->packet = pkg;
        this->length = length;
		//ip_header_offset = ether_len;
	}

    uint32_t htonl(uint32_t h) { return BigLittleSwap32(h); }
    uint32_t ntohl(uint32_t n) { return BigLittleSwap32(n); }
    uint16_t htons(uint16_t h) { return BigLittleSwap16(h); }
    uint16_t ntohs(uint16_t n) { return BigLittleSwap16(n); }
	inline uint8_t* getIPHeader() { return PACKET_DATA_OFFSET(packet, uint8_t*, ip_header_offset); }
	inline uint8_t getIPVersion() { return  (*PACKET_DATA_OFFSET(packet, uint8_t*, ip_header_offset)) >> 4;  };
	inline uint8_t getIPHeaderLength() {return ((*PACKET_DATA_OFFSET(packet, uint8_t*, ip_header_offset)) & 0xf) * 4;};
	inline uint16_t getIPTotalLength() { return ntohs(*PACKET_DATA_OFFSET(packet, uint16_t*, ip_header_offset + 2)); };
	inline uint16_t getIPID() { return ntohs(*PACKET_DATA_OFFSET(packet, uint16_t*, ip_header_offset + 4)); };
	inline bool getMF() { return *PACKET_DATA_OFFSET(packet, uint8_t*, ip_header_offset + 6) >> 5 & 0x1; };
	inline bool getDF() { return *PACKET_DATA_OFFSET(packet, uint8_t*, ip_header_offset + 6) >> 6 & 0x1; };
	inline uint16_t getFragmentOffset() { return ntohs(*PACKET_DATA_OFFSET(packet, uint16_t*, ip_header_offset + 6)) & 0x1FFF; };
	inline struct in_addr getSrcIP() { return *PACKET_DATA_OFFSET(packet, in_addr*, ip_header_offset + 12); };
	inline struct in_addr getDstIP() { return *PACKET_DATA_OFFSET(packet, in_addr*, ip_header_offset + 16); };
	inline uint8_t* getIpOption() { return PACKET_DATA_OFFSET(packet, uint8_t*, ip_header_offset+ ip_default_len);}
	inline uint8_t getProtocol() { return *PACKET_DATA_OFFSET(packet, uint8_t*, ip_header_offset + 9); };
	inline uint16_t getSrcPort() { return ntohs(*PACKET_DATA_OFFSET(packet, uint16_t*, ip_header_offset + getIPHeaderLength())); };
	inline uint16_t getDstPort() { return ntohs(*PACKET_DATA_OFFSET(packet, uint16_t*, ip_header_offset + getIPHeaderLength() + sizeof(uint16_t))); };
	inline uint16_t getDataLength() {return getProtocol() == IP_PROTO_TCP ? (getIPTotalLength() - getIPHeaderLength() - (*PACKET_DATA_OFFSET(packet, uint8_t*, ip_header_offset + getIPHeaderLength() + 12) * 4)) : (getIPTotalLength() - getIPHeaderLength() - udp_default_len);};
	inline uint8_t* getData() {return getIPHeader() + getIPHeaderLength();};
private:
	uint8_t* packet; // ip header + tcp/udp header + content
    size_t length;
	int udp_default_len = 10;
	int ip_header_offset = IP_HLEN;
    int ip_default_len = 20; // XXXXX ?????
};

#endif
