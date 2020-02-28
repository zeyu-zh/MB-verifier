import sys
import os
import struct
import random
import string
import thread
import time
from scapy.all import *

seed = 'qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM0123456789'
flag = 0

snort_pattern = []
etopen_pattern = []

def generate_pcap(pcap_file_path, pkt_size, is_etopen, probability):
    pkts = []
    num = 0
    global flag

    if is_etopen == 0:
        num = len(snort_pattern)
    else:
        num = len(etopen_pattern)

    for srcport in range(7000, 7050):
        for dstport in range(7000, 7100):
            for pkt_num in range(50):
                data = []

                # add malicious payloads
                if random.randint(0, 100) < probability:
                    if is_etopen == 0:
                        data.append(snort_pattern[random.randint(0, num -1)]); 
                    else:
                        data.append(etopen_pattern[random.randint(0, num -1)]); 
        
                if(len(data) < pkt_size):
                    for i in range(pkt_size - len(data)):
                        data.append(random.choice(seed))
                pkt = IP(src = '127.0.0.1', dst = '127.0.0.1')/UDP(sport = srcport, dport = dstport)/"".join(data)
                pkts.append(pkt)

    print pcap_file_path, ': writing packet to file......'
    wrpcap(pcap_file_path, pkts)
    flag = flag + 1
    print pcap_file_path, ': done',


if __name__ == "__main__":
    # init the string
    snort_path = "../../rules/snort_5779.pat"
    etopen_path = "../../rules/snort_63615.pat"

    if not os.path.isfile(snort_path):
        print 'Failed to open file: ', snort_path
        exit(0)

    if not os.path.isfile(etopen_path):
        print 'Failed to open file: ', etopen_path
        exit(0)

    f = open(snort_path)
    snort_pattern = f.readlines()
    f.close()

    f = open(etopen_path)
    etopen_pattern = f.readlines()
    f.close()


    # parameters: filename payloadsize ifetopen probability
    argus_25 = [("400-snort-25.pcap", 400, 0, 25), ("800-snort-25.pcap", 800, 0, 25), ("1200-snort-25.pcap", 1200, 0, 25), ("400-etopen-25.pcap", 400, 1, 25), ("800-etopen-25.pcap", 800, 1, 25), ("1200-etopen-25.pcap", 1200, 1, 25)]
    argus_50 = [("400-snort-50.pcap", 400, 0, 50), ("800-snort-50.pcap", 800, 0, 50), ("1200-snort-50.pcap", 1200, 0, 50), ("400-etopen-50.pcap", 400, 1, 50), ("800-etopen-50.pcap", 800, 1, 50), ("1200-etopen-50.pcap", 1200, 1, 50)]
    argus_100 = [("400-snort-100.pcap", 400, 0, 100), ("800-snort-100.pcap", 800, 0, 100), ("1200-snort-100.pcap", 1200, 0, 100), ("400-etopen-100.pcap", 400, 1, 100), ("800-etopen-100.pcap", 800, 1, 100), ("1200-etopen-100.pcap", 1200, 1, 100)]
    print 'Generating packets......'
    for i in range(len(argus_25)):
        thread.start_new_thread( generate_pcap, argus_25[i] )
        thread.start_new_thread( generate_pcap, argus_50[i] )
        thread.start_new_thread( generate_pcap, argus_100[i] )


    while flag != 18:
        time.sleep(10)
    
    print 'All done',
