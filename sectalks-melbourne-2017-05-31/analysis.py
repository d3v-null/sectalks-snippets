#!/usr/bin/python
import base64
from collections import Counter, OrderedDict
from operator import itemgetter
import re
import sys
import inspect

from tabulate import tabulate
from pprint import pprint

from scapy.all import *
from scapy.utils import rdpcap
from scapy.layers.l2 import Ether, Packet
from scapy.layers.inet import TCP, UDP

# PCAP_FILE = 'Gateway.pcap'
# PCAP_FILE = 'httpd.pcap'
PCAP_FILE = 'CCNP-SWITCH-final.pcap'
PCAP_COUNT = 0
# PCAP_COUNT = 1000

class CountStore(OrderedDict):
    def __getitem__(self, key):
        if not self.__contains__(key):
            self.__setitem__(key, Counter())
        return super(CountStore, self).__getitem__(key)

    def increment(self, key, value):
        self[key].update([value])

class SetStore(OrderedDict):
    def __getitem__(self, key):
        if not self.__contains__(key):
            self.__setitem__(key, set())
        return super(SetStore, self).__getitem__(key)

FIELD_TYPES = SetStore()
PACKET_FIELDS = SetStore()
FIELD_STRINGS = OrderedDict()

def report_counts(counts, name="COUNTS"):
    response = "%s: " % name.upper()
    if counts:
        table = [(str(typ), qty) for typ, qty in counts.items()]
        table = sorted(table, key=itemgetter(1), reverse=True)
        response += "\n%s\n" % tabulate(table, headers=["TYPE", "QTY"])
    else:
        response += 'NONE'
    return response + "\n"

def scapy_field_info():
    field_counts = Counter()
    for module in sys.modules:
        if re.match('scapy.layers', module):
            for _, obj in inspect.getmembers(sys.modules[__name__]):
                if inspect.isclass(obj) and obj not in PACKET_FIELDS \
                and issubclass(obj, Packet) and hasattr(obj, 'fields_desc'):
                    for field in obj.fields_desc:
                        field_counts.update([field.name])
                        PACKET_FIELDS[obj].add(field.name)
                        FIELD_TYPES[field.name].add(obj)
    # pprint(sorted(PACKET_FIELDS.items()))
    # pprint(sorted(FIELD_TYPES.items()))
    for field in ['type', 'proto']:
        if field in FIELD_TYPES:
            FIELD_STRINGS[field] = ""
            for pkt_class in FIELD_TYPES[field]:
                FIELD_STRINGS[field] += r"{%s:%%%s%%}" % (pkt_class.__name__, field)
    print report_counts(field_counts)
    pprint(FIELD_STRINGS)





# exit()


def analyse(packets):
    with open('analysis.txt', 'w') as analysis_file:
        # list protos

        # count_dict = OrderedDict([
        #     ('class', Counter()),
        #     ('proto', Counter()),
        #     ('port', Counter()),
        #     ('ethertype', Counter()),
        #     ('class proto', Counter()),
        # ])

        count_dict = CountStore()

        for pkt in packets:
            layers = []
            layer_ptr = pkt
            while layer_ptr:
                layers.append(str(type(layer_ptr).__name__))
                # layers.append(str(type(layer_ptr)))
                try:
                    layer_ptr = layer_ptr.payload
                except AttributeError:
                    layer_ptr = None
            pkt_class = " | ".join(layers)
            count_dict.increment('class', pkt_class)
            ethertype = pkt.sprintf('{Ether:%Ether.type%}')
            count_dict.increment('ethertype', ethertype)
            proto = pkt.sprintf(FIELD_STRINGS['proto'])
            count_dict.increment('proto', proto)
            class_proto = pkt_class
            if proto:
                class_proto = "(%s) %s" % (proto, class_proto)
            count_dict.increment('class proto', class_proto)
            port_components = []
            if TCP in pkt:
                port_compoment = pkt.sprintf("%TCP.dport%")
                if not re.match(r"\d+", port_compoment):
                    port_compoment = "%s (%d)" % (port_compoment, pkt[TCP].dport)
                port_components.append("TCP: %s" % port_compoment)
            if UDP in pkt:
                port_compoment = pkt.sprintf("%UDP.dport%")
                if not re.match(r"\d+", port_compoment):
                    port_compoment = "%s (%d)" % (port_compoment, pkt[UDP].dport)
                port_components.append("UDP: %s" % port_compoment)
            port = " | ".join(port_components)
            count_dict.increment('port', port)



        print "summary:"

            # if Ether in pkt:
            #
            #     port = pkt.sprintf(r"{TCP:TCP:%TCP.dport%}{UDP:UDP:%UDP.dport%}{ICMP:ICMP:%ICMP.type%}")
            #     if not port:
            #         port = pkt.summary()
            #     count_dict['port'].update([port])

        for name, counts in count_dict.items():
            print "name %s, counts %s" % (name, counts)
            analysis_file.write(report_counts(counts, name))

def main():
    scapy_field_info()
    rdpcap_args = [PCAP_FILE]
    if PCAP_COUNT:
        rdpcap_args += [PCAP_COUNT]
    packets = rdpcap(*rdpcap_args)
    analyse(packets)

if __name__ == '__main__':
    main()
