
"""Ethernet defines how devices on the same local network send and receive data
by packaging data into frames and delivering those frames between devices

It uses MAC addresses to identify sender and receiver hardware.
"""
from scapy.layers.l2 import Ether


class Ethernet(Ether):
    def __init__(self,packet_data_storage):
        super().__init__()
        self.packet_data_storage = packet_data_storage
        self.mac_address_src = None
        self.mac_address_dst = None
        self.ethernet_type = None


    def process(self, packet):
        if Ether in packet:
            packet_storage_slot = self.packet_data_storage[id(packet)]
            packet_storage_slot['mac_address_src'] = packet[Ether].src
            packet_storage_slot['mac_address_dst'] = packet[Ether].dst
            packet_storage_slot['ethernet_type'] = packet[Ether].type


    @staticmethod
    def parse_ethernet_type(ethernet_type):
        response_map = {2048:'IPv4',
                               2054:'ARP',
                               32821:'PPPoE',
                               34525:'IPv6',
                               33024:'VLAN-tagged',
                               34958:'LLDP',
                               34916:'Q-in-Q VLAN',
                               34825:'Slow Protocols',
                               34826:'PPP',
                               34506:'IPv6',
                               33011:'AARP'}

        return response_map[ethernet_type]

