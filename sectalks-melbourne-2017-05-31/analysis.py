#!/usr/bin/python
import base64
from collections import Counter, OrderedDict
from operator import itemgetter
import re
import sys
import inspect

from tabulate import tabulate
from pprint import pprint, pformat

from scapy.all import *
from scapy.utils import rdpcap
from scapy.layers.l2 import Ether, Packet, Dot1Q
from scapy.layers.inet import TCP, UDP

# PCAP_FILE = 'Gateway.pcap'
# PCAP_FILE = 'httpd.pcap'
PCAP_FILE = 'CCNP-SWITCH-final.pcap'
PCAP_COUNT = 0
# PCAP_COUNT = 100

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
FIELD_STRINGS = SetStore()

def report_counts(counts, name="COUNTS"):
    response = "%s: " % name.upper()
    if counts:
        table = [(str(typ), qty) for typ, qty in counts.items()]
        table = sorted(table, key=itemgetter(1), reverse=True)
        response += "\n%s\n" % tabulate(table, headers=["TYPE", "QTY"])
    else:
        response += 'NONE'
    return response + "\n"

def populate_scapy_field_info():
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
    pprint(sorted(PACKET_FIELDS.items()))
    # pprint(sorted(FIELD_TYPES.items()))
    for field in ['type', 'proto']:
        if field in FIELD_TYPES:
            for pkt_class in FIELD_TYPES[field]:
                FIELD_STRINGS[field].add((pkt_class, r"{%s:%%%s%%}" % (pkt_class.__name__, field)))
    print report_counts(field_counts)
    # pprint(FIELD_STRINGS)

def get_packet_field(packet, field):
    # print "searching for field %s in packet %s" % (field, packet.summary())
    results = SetStore()
    layer_ptr = packet
    while layer_ptr:
        if hasattr(type(layer_ptr), 'fields_desc'):
            fields = [field_desc.name for field_desc in type(layer_ptr).fields_desc]
            # print "fields are %s" % fields
            if field in fields:
                get_result = getattr(layer_ptr, field)
                sprintf_result = layer_ptr.sprintf(r"%%%s%%" % field)
                results[type(layer_ptr)].add((get_result, sprintf_result))
        layer_ptr = layer_ptr.payload if hasattr(layer_ptr, 'payload') else None
    return results

    # if field in FIELD_STRINGS:
    #     for pkt_class, field_string in FIELD_STRINGS[field]:
    #         if pkt_class not in packet:
    #             layers = get_packet_layers(packet)
    #             print "class %s not in packet with layers: %s" % (pkt_class, layers)
    #             continue
    #         sprintf_result = packet.sprintf(field_string)
    #         print "sprintf_result", repr(sprintf_result)
    #         get_result = None
    #         if pkt_class in packet and hasattr(packet[pkt_class], field):
    #             get_result = getattr(packet[pkt_class], field)
    #         print "get_result", repr(get_result)
    #         results[pkt_class.__name__] = (sprintf_result, get_result)
    # print "returning results: \n", pformat(results)
    # return results

def get_packet_layers(packet):
    layers = []
    layer_ptr = packet
    while layer_ptr:
        layers.append(type(layer_ptr))
        # layers.append(str(type(layer_ptr)))
        try:
            layer_ptr = layer_ptr.payload
        except AttributeError:
            layer_ptr = None
    return layers

def flatten_result(result_components):
    response_compoments = []
    for cls, results in result_components.items():
        response_component = ""
        str_results = set()
        for result in results:
            if str(result[0]) == str(result[1]):
                str_results.add(str(result[0]))
            else:
                str_results.add("%s/%s" % (result[0], result[1]))
        response_component = "%s:%s" % (cls.__name__, " > ".join(list(str_results)))
        response_compoments.append(response_component)
    return " | ".join(response_compoments)

def analyse(packets):
    with open('analysis.txt', 'w') as analysis_file:

        cap_info = []
        count_dict = CountStore()
        observed_layers = set()

        for pkt in packets:
            pkt_info = OrderedDict()
            pkt_info['layers'] = list(set(get_packet_layers(pkt)))
            observed_layers.update(pkt_info['layers'])
            pkt_info['class_stack'] = " | ".join([layer.__name__ for layer in pkt_info['layers']])
            pkt_info['type'] = flatten_result(get_packet_field(pkt, 'type'))
            pkt_info['protocol'] = flatten_result(get_packet_field(pkt, 'proto'))
            # pkt_info['class proto'] = pkt_info['class_stack']
            # if pkt_info['protocol']:
            #     pkt_info['class proto'] = "(%s) %s" % (pkt_info['protocol'], pkt_info['class_stack'])
            # count_dict.increment('class proto', pkt_info['class proto'])
            pkt_info['dport'] = flatten_result(get_packet_field(pkt, 'dport'))
            pkt_info['bridgemac'] = flatten_result(get_packet_field(pkt, 'bridgemac'))
            pkt_info['bridgeid'] = flatten_result(get_packet_field(pkt, 'bridgeid'))
            pkt_info['vlan'] = ", ".join(["%s:%s" % (cls.__name__, list(results)[0][1]) for cls, results in get_packet_field(pkt, 'vlan').items()])
            if pkt_info['vlan'] and pkt_info['bridgeid'] and pkt_info['bridgemac']:
                pkt_info['vlan bridge'] = "%s -- %s @ %s" % (pkt_info['vlan'], pkt_info['bridgeid'], pkt_info['bridgemac'])
            for key in ['class_stack', 'type', 'protocol', 'dport', 'bridgemac', 'bridgeid', 'vlan', 'vlan bridge']:
                if key in pkt_info:
                    count_dict.increment(key, pkt_info[key])

            # if Dot1Q in pkt_info['layers']:
            #     dot1q_layer = pkt[Dot1Q]
            #     print "layer: %s, vlan: %s, id: %s, mysummary: %s, summary: %s" % (type(dot1q_layer), dot1q_layer.vlan, dot1q_layer.id, dot1q_layer.mysummary(), dot1q_layer.summary())
            #     pkt_info['.1q'] = dot1q_layer.mysummary()
            #     count_dict.increment('.1q', pkt_info['.1q'])

        for layer in sorted(observed_layers):
            print "layer %50s, fields %s" % (layer, PACKET_FIELDS.get(layer, set()))

        for pkt_class, fields in PACKET_FIELDS.items():
            if 'vlan' in fields:
                print pkt_class, "has vlan"

        for name, counts in count_dict.items():
            print "name %50s, counts %s" % (name, counts)
            analysis_file.write(report_counts(counts, name))

def main():
    populate_scapy_field_info()
    rdpcap_args = [PCAP_FILE]
    if PCAP_COUNT:
        rdpcap_args += [PCAP_COUNT]
    packets = rdpcap(*rdpcap_args)
    analyse(packets)

if __name__ == '__main__':
    main()
