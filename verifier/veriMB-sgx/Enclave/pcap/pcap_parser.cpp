#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "pcap_parser.h"
#include "Enclave.h"
#include <string.h>
#include "Enclave_t.h"

#define CHECK_POINTER(p) if(p == NULL) return -1;

int get_pcap_data(const char* path, VERI_DATA* p_veri_data){
    uint8_t* p_pcap;
    uint64_t length;
    int amount;
    uint32_t offset = sizeof(PCAP_HDR), next_packet_offset = 0;

    ocall_mmap_pcap(&length, path, (uint64_t*)&p_pcap);
    
    /* get the packet number */
    for(amount = 0 ; offset < length; amount++){
        PCAP_PKHDR* p_pcap_hdr = (PCAP_PKHDR*)(p_pcap + offset);
        offset = offset + p_pcap_hdr->incl_len + sizeof(PCAP_PKHDR);
    }
    
    p_veri_data->amount = amount;
    p_veri_data->p_data = (uint8_t**)malloc(sizeof(uint8_t*) * amount);
    CHECK_POINTER(p_veri_data->p_data);
    p_veri_data->p_len = (int*)malloc(sizeof(int) * amount);
    CHECK_POINTER(p_veri_data->p_len);
    p_veri_data->p_a = (uint16_t*)malloc(sizeof(uint16_t) * amount);
    CHECK_POINTER(p_veri_data->p_a);
    p_veri_data->p_b = (uint16_t*)malloc(sizeof(uint16_t) * amount);
    CHECK_POINTER(p_veri_data->p_b);
    p_veri_data->p_c = (uint16_t*)malloc(sizeof(uint16_t) * amount);
    CHECK_POINTER(p_veri_data->p_c)
    p_veri_data->p_d = (uint16_t*)malloc(sizeof(uint16_t) * amount);
    CHECK_POINTER(p_veri_data->p_d);

    /* parse variable a, b, c, d, and packet data*/
    offset = sizeof(PCAP_HDR);
    for(int i = 0; i < p_veri_data->amount; i++){
        uint32_t initial_offset = offset;
        PCAP_PKHDR* p_pcap_hdr = (PCAP_PKHDR*)(p_pcap + offset);
        next_packet_offset = offset + p_pcap_hdr->incl_len + sizeof(PCAP_PKHDR);
        
        /* Eth header*/
        offset = offset + sizeof(PCAP_PKHDR);
        
        /* Ip header */
        offset = offset + sizeof(ETH_HDR);
        IPV4_HDR* p_ipv4_hdr = (IPV4_HDR*)(p_pcap + offset);

        p_veri_data->p_a[i] = p_ipv4_hdr->a;
        p_veri_data->p_b[i] = p_ipv4_hdr->b;
        p_veri_data->p_c[i] = p_ipv4_hdr->c;
        p_veri_data->p_d[i] = p_ipv4_hdr->d;

        /* L4 header */
        offset = offset + sizeof(IPV4_HDR);
        if(p_ipv4_hdr->proto == 6)
            offset = offset + sizeof(TCP_HDR);
        else if(p_ipv4_hdr->proto == 17)
            offset = offset + sizeof(UDP_HDR);

        /* packet payload */
        uint8_t* p_data = p_pcap + offset;
        int len = (int)(p_pcap_hdr->incl_len + sizeof(PCAP_PKHDR) - (offset - initial_offset));
        p_veri_data->p_data[i] = (uint8_t*)malloc(sizeof(int)*len);
        CHECK_POINTER(p_veri_data->p_data[i]);
        memcpy(p_veri_data->p_data[i], p_data, len);
        p_veri_data->p_len[i] = len;

        offset = next_packet_offset;
    }
    
    ocall_munmap_pcap(length, p_pcap);
    return 0;
}

void destory_pcap_data(VERI_DATA* p_veri_data){
    if(p_veri_data == NULL)
        return;
    for(int i = 0; i < p_veri_data->amount; i++)
        free(p_veri_data->p_data[i]);

    free(p_veri_data->p_len);
    free(p_veri_data->p_data);
    free(p_veri_data->p_a);
    free(p_veri_data->p_b);
    free(p_veri_data->p_c);
    free(p_veri_data->p_d);

    return;
}




// int main(int argc, char* argv[]){
//     string pcap_path = "./m58.pcap";
//     struct stat sk;

//     /* map this file to memory */
//     int fd = open(pcap_path.c_str(), O_RDWR, 0644);
//     if(fd == -1){
//         cout << "Failed to open file " << pcap_path << endl;
//         return -1;
//     }
//     stat(pcap_path.c_str(), &sk);
//     uint8_t* p_pcap = (uint8_t*)mmap(NULL, sk.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
//     if(p_pcap == nullptr){
//         cout << "Failed to mmap file " << pcap_path << endl;
//         return -1;
//     }
//     close(fd);


//     /* parse the pcap file */
//     /* parse the metadata */
//     PCAP_HDR* p_pcap_hdr = (PCAP_HDR*)p_pcap;
//     cout << "The metadata of this .pcap file:" << endl;
//     cout << "   Magic number: " << hex << p_pcap_hdr->magic_number << " (should be 0xa1b2c3d4 or 0xd4c3b2a1)" << endl;
//     cout << "   Major version: " << p_pcap_hdr->version_major << endl;
//     cout << "   Minor version: " << p_pcap_hdr->version_minor << endl;
//     cout << "   ThisZone: " << p_pcap_hdr->thiszone << endl;
//     cout << "   Snap length: " << dec << p_pcap_hdr->snaplen << "(65536 for unlimited length)" << endl;
//     cout << "   Link type: " << p_pcap_hdr->network << "(1 for Ethernet)"  << endl << endl;


//     /* parse each packat */
//     uint32_t offset = sizeof(PCAP_HDR), next_packet_offset = 0;    
//     while(offset < sk.st_size){
//         uint32_t initial_offset = offset;
//         PCAP_PKHDR* p_pcap_hdr = (PCAP_PKHDR*)(p_pcap + offset);
//         next_packet_offset = offset + p_pcap_hdr->incl_len + sizeof(PCAP_PKHDR);
//         cout << "The metadata of packet (provided by tcpdump):" << endl;
//         cout << "   Timestamp (seconds): " << hex << p_pcap_hdr->ts_sec << endl;
//         cout << "   Timestamp (microseconds): " << p_pcap_hdr->ts_usec << endl;
//         cout << "   Current length: " << dec << p_pcap_hdr->incl_len << endl;
//         cout << "   Offset data length: " << p_pcap_hdr->orig_len << endl << endl;

//         /* Ethenet header */
//         offset = offset + sizeof(PCAP_PKHDR);
//         ETH_HDR* p_eth_hdr = (ETH_HDR*)(p_pcap + offset);
//         cout << "Packet header data:" << endl;
//         cout << hex;
//         cout << "   Dest mac: " << setfill('0') << setw(2) << *(uint16_t*)(p_eth_hdr->dst_mac) \
//             << *(uint16_t*)(p_eth_hdr->dst_mac+2) << *(uint16_t*)(p_eth_hdr->dst_mac+4) << endl;
//         cout << "   Src mac: " << setfill('0') << setw(2) << *(uint16_t*)(p_eth_hdr->src_mac) \
//             << *(uint16_t*)(p_eth_hdr->src_mac+2) << *(uint16_t*)(p_eth_hdr->dst_mac+4) << endl << endl;
    
//         /* Ip header */
//         offset = offset + sizeof(ETH_HDR);
//         IPV4_HDR* p_ipv4_hdr = (IPV4_HDR*)(p_pcap + offset);
//         cout << "Ip header data:" << endl;
//         cout << "   Dest ip: " << dec <<(p_ipv4_hdr->dst_ip & 0x000000ff) << "." \
//             << ((p_ipv4_hdr->dst_ip & 0x0000ff00) >> 8) << "." \
//             << ((p_ipv4_hdr->dst_ip & 0x00ff0000) >> 16) << "." \
//             << ((p_ipv4_hdr->dst_ip & 0xff000000) >> 24) << endl;
//         cout << "   Src ip: " << (p_ipv4_hdr->src_ip & 0x000000ff) << "." \
//             << ((p_ipv4_hdr->src_ip & 0x0000ff00) >> 8) << "." \
//             << ((p_ipv4_hdr->src_ip & 0x00ff0000) >> 16) << "." \
//             << ((p_ipv4_hdr->src_ip & 0xff000000) >> 24) << endl;

//         cout << "   a: " << p_ipv4_hdr->a << endl;
//         cout << "   b: " << p_ipv4_hdr->b << endl;
//         cout << "   c: " << p_ipv4_hdr->c << endl;
//         cout << "   d: " << p_ipv4_hdr->d << endl;

//         /* L4 header */
//         offset = offset + sizeof(IPV4_HDR);
//         if(p_ipv4_hdr->proto == 6){
//             TCP_HDR* p_tcp_hdr = (TCP_HDR*)(p_pcap + offset);
//             /* TCP header */
//             cout << "TCP header:" << endl;
//             cout << "   Dest port: " << swap16(p_tcp_hdr->dst_port) << endl;
//             cout << "   Src port: " << swap16(p_tcp_hdr->src_port) << endl << endl;
//             offset = offset + sizeof(TCP_HDR);
//         } else if(p_ipv4_hdr->proto == 17) {
//             UDP_HDR* p_udp_hdr = (UDP_HDR*)(p_pcap + offset);
//             /* UDP header */
//             cout << "UDP header:" << endl;
//             cout << "   Dest port: " << swap16(p_udp_hdr->dst_port) << endl;
//             cout << "   Src port: " << swap16(p_udp_hdr->src_port) << endl << endl;
//             offset = offset + sizeof(UDP_HDR);
//         } else{
//             cout << "   Unknown L4 protocol: " << p_ipv4_hdr->proto << endl;
//             return -1;
//         }

//         /* packet payload */
//         uint8_t* p_data = p_pcap + offset;
//         cout << "Payload:"<< dec << (int)(p_pcap_hdr->incl_len + sizeof(PCAP_PKHDR) - (offset - initial_offset)) << endl;
//         cout << hex;
//         for(int i = 0; i < (int)(p_pcap_hdr->incl_len + sizeof(PCAP_PKHDR) - (offset - initial_offset)); i = i + 2)
//             cout << setfill('0') << setw(2) << (uint16_t)(p_data[i]) << " ";
//         cout << endl << endl;

//         cout << "Press <Enter> to view the next packet data" << endl;
//         getchar();
//         offset = next_packet_offset;
//     }

//     return 0;
// }
