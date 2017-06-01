#!/usr/bin/python

from scapy.all import *
import base64
import sys

image = False
image_data=''
line_strip=''

filename = open("output.txt",'w')
packets = rdpcap('internet_perimeter.pcap')

for pkt in packets:
	if Ether in pkt:
		src_mac=pkt[Ether].src
		if src_mac=='????????':
			p_data=pkt.load
			juice_info=p_data[???????]
			sys.stdout=filename
			print juice_info
filename.close()
infile=open("output.txt",'r')
outfile = open("decoded.txt",'a')
for dat in infile:
        if (dat.startswith('??????')):
                deco1=????????(dat)
                sys.stdout=outfile
                print deco1
        if(dat.startswith('???????')):
                deco2=????????(dat)
                if '????????' in deco2:
                        image_data +=deco2.replace('??????:', '')
                        image = True
                continue
        if (dat.startswith('??????')):
                line = dat[???????]
                deco3=base64.b64decode(line)
                sys.stdout=outfile
                print deco3

with open('picture_new.jpg','wb') as f:
        f.write(image_data)
