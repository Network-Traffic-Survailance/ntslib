"""
IP is the postal system of the internet.
It gives every device an address, and it helps data travel from sender to receiver across different networks.
"""

from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6

class InternetProtocol(IP):
    def __init__(self,packet_data_storage):
        super().__init__()
        self.packet_data_storage = packet_data_storage

        self.version = None  # IP version
        self.source_ip_address = None  # Source IP address
        self.destination_ip_address = None  # Destination IP address

        # IPV4 Fields
        self.internet_header_length = None  # IHL (Internet Header Length)
        self.type_of_service = None  # TOS (Type of Service)
        self.total_length = None  # Total length of the packet (header + data)
        self.identification = None  # Identification for fragmentation
        self.flags = None  # Flags (e.g., Don't Fragment, More Fragments)
        self.fragment_offset = None  # Fragment offset
        self.time_to_live = None  # TTL (Time To Live)
        self.protocol = None  # Protocol (e.g., TCP=6, UDP=17)
        self.header_checksum = None  # Header checksum
        self.options = None  # Optional headers

        # IPV6 fields
        self.traffic_class = None
        self.payload_length = None
        self.hop_limit = None
        self.next_header = None
        self.flow_label = None



    def process(self,packet):
        packet_storage_slot = self.packet_data_storage[id(packet)]

        ip_version = None
        if IP in packet:
            ip_version = IP
        if IPv6 in packet:
            ip_version = IPv6

        if ip_version:
            self.version = packet[ip_version].version
            if ip_version == IP:
                packet_storage_slot['ip_version'] = 'IPV4'
                packet_storage_slot['internet_header_length'] = packet[ip_version].ihl
                packet_storage_slot['type_of_service'] = packet[ip_version].tos
                packet_storage_slot['total_length'] = packet[ip_version].len
                packet_storage_slot['identification'] = packet[ip_version].id
                packet_storage_slot['flags'] = packet[ip_version].flags
                packet_storage_slot['fragment_offset'] = packet[ip_version].frag
                packet_storage_slot['time_to_live'] = packet[ip_version].ttl
                packet_storage_slot['protocol'] = packet[ip_version].proto
                packet_storage_slot['header_checksum'] = packet[ip_version].chksum
                packet_storage_slot['source_ip_address'] = packet[ip_version].src
                packet_storage_slot['destination_ip_address'] = packet[ip_version].dst
                packet_storage_slot['ipv4_options'] = packet[ip_version].options
            else:
                packet_storage_slot['ip_version'] = 'IPV6'
                packet_storage_slot['traffic_class'] = packet[ip_version].tc
                packet_storage_slot['payload_length'] = packet[ip_version].plen
                packet_storage_slot['hop_limit'] = packet[ip_version].hlim
                packet_storage_slot['next_header'] = packet[ip_version].nh
                packet_storage_slot['flow_label'] = packet[ip_version].fl
                packet_storage_slot['source_ip_address'] = packet[ip_version].src
                packet_storage_slot['destination_ip_address'] = packet[ip_version].dst

