"""
DHCP is the network’s automatic address assigner that gives devices their IP addresses and other network settings,
so they can join and communicate on a network without manual configuration.
"""

from scapy.layers.dhcp import DHCP


class DynamicHostConfigurationProtocol(DHCP):
    def __init__(self, packet_data_storage):
        super().__init__()
        self.packet_data_storage = packet_data_storage
        self.options = None


    def process(self,packet):
        packet_storage_slot = self.packet_data_storage[id(packet)]

        if DHCP in packet:
            packet_storage_slot['dhcp_options'] = packet[DHCP].options
