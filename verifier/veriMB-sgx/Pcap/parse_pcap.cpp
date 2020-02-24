#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string>
#include <vector>
#include <chrono>
#include <fstream>
#include <iomanip>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/time.h>
#include <unistd.h>
#include <pwd.h>
using namespace std;

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



int main(int argc, char* argv[]){
    string pcap_path = "./m58.pcap";
    struct stat sk;

    /* map this file to memory */
    int fd = open(pcap_path.c_str(), O_RDWR, 0644);
    if(fd == -1){
        cout << "Failed to open file " << pcap_path << endl;
        return -1;
    }
    stat(pcap_path.c_str(), &sk);
    uint8_t* p_pcap = (uint8_t*)mmap(NULL, sk.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if(p_pcap == nullptr){
        cout << "Failed to mmap file " << pcap_path << endl;
        return -1;
    }
    close(fd);


    /* parse the pcap file */
    /* parse the metadata */
    PCAP_HDR* p_pcap_hdr = (PCAP_HDR*)p_pcap;
    cout << "The metadata of this .pcap file:" << endl;
    cout << "   Magic number: " << hex << p_pcap_hdr->magic_number << " (should be 0xa1b2c3d4 or 0xd4c3b2a1)" << endl;
    cout << "   Major version: " << p_pcap_hdr->version_major << endl;
    cout << "   Minor version: " << p_pcap_hdr->version_minor << endl;
    cout << "   ThisZone: " << p_pcap_hdr->thiszone << endl;
    cout << "   Snap length: " << dec << p_pcap_hdr->snaplen << "(65536 for unlimited length)" << endl;
    cout << "   Link type: " << p_pcap_hdr->network << "(1 for Ethernet)"  << endl << endl;


    /* parse each packat */
    uint32_t offset = sizeof(PCAP_HDR), next_packet_offset = 0;    
    while(offset < sk.st_size){
        uint32_t initial_offset = offset;
        PCAP_PKHDR* p_pcap_hdr = (PCAP_PKHDR*)(p_pcap + offset);
        next_packet_offset = offset + p_pcap_hdr->incl_len + sizeof(PCAP_PKHDR);
        cout << "The metadata of packet (provided by tcpdump):" << endl;
        cout << "   Timestamp (seconds): " << hex << p_pcap_hdr->ts_sec << endl;
        cout << "   Timestamp (microseconds): " << p_pcap_hdr->ts_usec << endl;
        cout << "   Current length: " << dec << p_pcap_hdr->incl_len << endl;
        cout << "   Offset data length: " << p_pcap_hdr->orig_len << endl << endl;

        /* Ethenet header */
        offset = offset + sizeof(PCAP_PKHDR);
        ETH_HDR* p_eth_hdr = (ETH_HDR*)(p_pcap + offset);
        cout << "Packet header data:" << endl;
        cout << hex;
        cout << "   Dest mac: " << setfill('0') << setw(2) << *(uint16_t*)(p_eth_hdr->dst_mac) \
            << *(uint16_t*)(p_eth_hdr->dst_mac+2) << *(uint16_t*)(p_eth_hdr->dst_mac+4) << endl;
        cout << "   Src mac: " << setfill('0') << setw(2) << *(uint16_t*)(p_eth_hdr->src_mac) \
            << *(uint16_t*)(p_eth_hdr->src_mac+2) << *(uint16_t*)(p_eth_hdr->dst_mac+4) << endl << endl;
    
        /* Ip header */
        offset = offset + sizeof(ETH_HDR);
        IPV4_HDR* p_ipv4_hdr = (IPV4_HDR*)(p_pcap + offset);
        cout << "Ip header data:" << endl;
        cout << "   Dest ip: " << dec <<(p_ipv4_hdr->dst_ip & 0x000000ff) << "." \
            << ((p_ipv4_hdr->dst_ip & 0x0000ff00) >> 8) << "." \
            << ((p_ipv4_hdr->dst_ip & 0x00ff0000) >> 16) << "." \
            << ((p_ipv4_hdr->dst_ip & 0xff000000) >> 24) << endl;
        cout << "   Src ip: " << (p_ipv4_hdr->src_ip & 0x000000ff) << "." \
            << ((p_ipv4_hdr->src_ip & 0x0000ff00) >> 8) << "." \
            << ((p_ipv4_hdr->src_ip & 0x00ff0000) >> 16) << "." \
            << ((p_ipv4_hdr->src_ip & 0xff000000) >> 24) << endl;

        cout << "   a: " << p_ipv4_hdr->a << endl;
        cout << "   b: " << p_ipv4_hdr->b << endl;
        cout << "   c: " << p_ipv4_hdr->c << endl;
        cout << "   d: " << p_ipv4_hdr->d << endl;

        /* L4 header */
        offset = offset + sizeof(IPV4_HDR);
        if(p_ipv4_hdr->proto == 6){
            TCP_HDR* p_tcp_hdr = (TCP_HDR*)(p_pcap + offset);
            /* TCP header */
            cout << "TCP header:" << endl;
            cout << "   Dest port: " << swap16(p_tcp_hdr->dst_port) << endl;
            cout << "   Src port: " << swap16(p_tcp_hdr->src_port) << endl << endl;
            offset = offset + sizeof(TCP_HDR);
        } else if(p_ipv4_hdr->proto == 17) {
            UDP_HDR* p_udp_hdr = (UDP_HDR*)(p_pcap + offset);
            /* UDP header */
            cout << "UDP header:" << endl;
            cout << "   Dest port: " << swap16(p_udp_hdr->dst_port) << endl;
            cout << "   Src port: " << swap16(p_udp_hdr->src_port) << endl << endl;
            offset = offset + sizeof(UDP_HDR);
        } else{
            cout << "   Unknown L4 protocol: " << p_ipv4_hdr->proto << endl;
            return -1;
        }

        /* packet payload */
        uint8_t* p_data = p_pcap + offset;
        cout << "Payload:"<< dec << (int)(p_pcap_hdr->incl_len + sizeof(PCAP_PKHDR) - (offset - initial_offset)) << endl;
        cout << hex;
        for(int i = 0; i < (int)(p_pcap_hdr->incl_len + sizeof(PCAP_PKHDR) - (offset - initial_offset)); i = i + 2)
            cout << setfill('0') << setw(2) << (uint16_t)(p_data[i]) << " ";
        cout << endl << endl;

        cout << "Press <Enter> to view the next packet data" << endl;
        getchar();
        offset = next_packet_offset;
    }

    return 0;
}
