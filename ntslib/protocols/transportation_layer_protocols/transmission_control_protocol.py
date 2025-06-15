"""
TCP is connection-oriented protocol that ensures data is delivered in order and without errors by establishing
a connection between sender and receiver before data transfer.
"""

from scapy.layers.inet import TCP


class TransmissionControlProtocol(TCP):
    def __init__(self,packet_data_storage):
        super().__init__()
        self.packet_data_storage=packet_data_storage

        self.source_port = None
        self.destination_port = None
        self.sequence_number = None
        self.acknowledgement_number = None
        self.data_offset = None
        self.reserved = None
        self.control_flags = None
        self.window_size = None
        self.checksum = None
        self.urgent_pointer = None
        self.options = None


    def process(self,packet):
        packet_storage_slot = self.packet_data_storage[id(packet)]

        if TCP in packet:
            packet_storage_slot['source_port'] = packet[TCP].sport
            packet_storage_slot['destination_port'] = packet[TCP].dport
            packet_storage_slot['sequence_number'] = packet[TCP].seq
            packet_storage_slot['acknowledgement_number'] = packet[TCP].ack
            packet_storage_slot['data_offset'] = packet[TCP].dataofs
            packet_storage_slot['reserved'] = packet[TCP].reserved
            packet_storage_slot['control_flags'] = packet[TCP].flags
            packet_storage_slot['window_size'] = packet[TCP].window
            packet_storage_slot['tcp_checksum'] = packet[TCP].chksum
            packet_storage_slot['urgent_pointer'] = packet[TCP].urgptr
            packet_storage_slot['tcp_options'] = packet[TCP].options


