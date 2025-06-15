"""
UDP is a simple, connectionless protocol that sends data quickly without guaranteeing delivery or order,
often used for real-time applications like video streaming or gaming.
"""

from scapy.layers.inet import UDP, TCP


class UserDatagramProtocol(UDP):
    def __init__(self,packet_data_storage):
        super().__init__()
        self.packet_data_storage=packet_data_storage

        self.source_port = None
        self.destination_port = None
        self.length = None
        self.checksum = None


    def process(self,packet):
        packet_storage_slot = self.packet_data_storage[id(packet)]

        if UDP in packet:
            packet_storage_slot['udp_source_port'] = packet[UDP].sport
            packet_storage_slot['udp_destination_port'] = packet[UDP].dport
            packet_storage_slot['udp_length'] = packet[UDP].len
            packet_storage_slot['udp_checksum'] = packet[UDP].chksum


