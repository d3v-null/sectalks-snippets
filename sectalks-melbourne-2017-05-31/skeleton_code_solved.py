#!/usr/bin/python

import scapy
import base64
import sys

image = False
image_data = ''
line_strip = ''

packets = scapy.utils.rdpcap('Gateway.pcap')

with  open("output.txt", 'w') as filename:
    for pkt in packets:
        if scapy.layers.l2.Ether in pkt:
            src_mac = pkt[scapy.layers.l2.Ether].src
            if src_mac == '00:12:9f:12:33:44':
                try:
                    p_data = pkt.load
                except AttributeError:
                    print "no load in pkt", type(pkt), pkt.show()
                juice_info = p_data[60:-1]
                filename.write(juice_info + "\n")

with open("output.txt", 'r') as infile, open("decoded.txt", 'a') as outfile:
    for dat in infile:
        if dat.startswith('Xlhm5d'):
            encoded = dat[6:]
            deco1 = ""
            try:
                deco1 = base64.b64decode(encoded)
            except TypeError as e:
                print "could not decode dat: %s \n reason: %s" % (encoded, e)
            finally:
                outfile.write(deco1)
        # if(dat.startswith('REFUQT')):
        #     deco2 = base64.b64decode(dat)
        #     if '????????' in deco2:
        #         image_data += deco2.replace('??????:', '')
        #         image = True
        #     continue
        # if (dat.startswith('??????')):
        #     line = dat[???????]
        #     deco3 = base64.b64decode(line)
        #     sys.stdout = outfile
        #     print deco3
#
# with open('picture_new.jpg', 'wb') as f:
#     f.write(image_data)
