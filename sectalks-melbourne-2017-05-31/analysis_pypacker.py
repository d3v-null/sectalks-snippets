from __future__ import print_function
from pypacker import ppcap
from pypacker.layer12 import ethernet
from pypacker.layer3 import ip
from pypacker.layer4 import tcp

def main():
    pcap = ppcap.Reader(filename="Gateway.pcap")
    for timestamp, buf in list(pcap):
        eth = ethernet.Ethernet(buf)
        print(eth.src_s, eth.dst_s, eth.type)

if __name__ == '__main__':
    main()
