"""
ICMP is like a messenger between computers and routers that says,
“Something went wrong with your packet,” or “Here’s a status update.”
"""

from scapy.layers.inet import ICMP

class InternetControlMessageProtocol(ICMP):
    def __init__(self,packet_data_storage):
        super().__init__()
        self.packet_data_storage = packet_data_storage
        self.message_type = "Internet Control Message Protocol (ICMP)"  # Specifies the type of ICMP message (e.g., 8 for Echo Request)
        self.code = None             # More specific context within the type (e.g., code 0 for Echo Request)
        self.checksum = None         # Error-checking checksum for the ICMP header and data
        self.identifier = None       # Used to match requests with replies (often a process ID)
        self.sequence_number = None  # Used to track the order of ICMP messages
        self.unused_field = None     # Field used in some ICMP message types but not others


    def process(self,packet):
        packet_storage_slot = self.packet_data_storage[id(packet)]
        if ICMP in packet:
            packet_storage_slot['icmp_message_type'] = packet[ICMP].type
            packet_storage_slot['code'] = packet[ICMP].code
            packet_storage_slot['icmp_checksum'] = packet[ICMP].chksum
            packet_storage_slot['identifier'] = packet[ICMP].id
            packet_storage_slot['sequence_number'] = packet[ICMP].seq
            packet_storage_slot['unused_field'] = packet[ICMP].unused

    @staticmethod
    def parse_message_type(message_type):
        response_map = {
            0:'Echo Reply',
            3:'Destination Unreachable',
            4:'Source Quench',
            5:'Redirect',
            8:'Echo Request',
            11:'Time Exceeded',
            12:'Parameter Problem',
            13:'Timestamp Request',
            14:'Timestamp Reply',
        }
        return response_map[message_type]

    @staticmethod
    def parse_icmp_code(code):
        response_map = {
            0:'Network unreachable',
            1:'Host unreachable',
            2:'Protocol unreachable',
            3:'Port unreachable',
            4:'Fragmentation needed'
        }

        return response_map[code]