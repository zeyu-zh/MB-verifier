import sys
import struct
import random
import string
import thread
from scapy.all import *

seed = 'qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM0123456789'

def generate_pcap(pcap_file_path, pkt_size):
    pkts = []
    for srcport in range(7000, 7050):
        for dstport in range(7000, 7100):
            for pkt_num in range(50):
                data = []
                for i in range(pkt_size):
                    data.append(random.choice(seed))
                pkt = IP(src = '127.0.0.1', dst = '127.0.0.1')/UDP(sport = srcport, dport = dstport)/"".join(data)
                pkts.append(pkt)
    print pcap_file_path, ': writing packet to file......'
    wrpcap(pcap_file_path, pkts)
    print pcap_file_path, ': done'


if __name__ == "__main__":
    print 'Generating packets......'
    argus = [("200.pcap", 200), ("400.pcap", 400), ("600.pcap", 600), ("800.pcap", 800), ("1000.pcap", 1000), ("1200.pcap", 1200)]
    for i in range(len(argus)):
        thread.start_new_thread( generate_pcap, argus[i] )

    while 1:
        pass

