"""
IGMP helps manage group memberships for devices that want to receive multicast traffic,
so the network only sends data to those who asked for it
"""

from scapy.contrib.igmp import IGMP

class InternetGroupManagementProtocol(IGMP):
    def __init__(self, packet_data_storage):
        super().__init__()
        self.packet_data_storage = packet_data_storage
        self.message_type = 'Internet Group Management Protocol'  # Type of IGMP message (e.g., Membership Query, Membership Report)
        self.max_response_code = None   # Maximum time allowed before sending a responding report (used in queries)
        self.checksum = None            # Error-checking checksum for the IGMP message
        self.group_address = None       # The multicast group address relevant to the message (224.0.0.0 to 239.255.255.255)


    def process(self,packet):
        packet_storage_slot = self.packet_data_storage[id(packet)]

        if IGMP in packet:
            packet_storage_slot['igmp_message_type'] = packet[IGMP].type
            packet_storage_slot['igmp_max_response_code'] = packet[IGMP].mrcode
            packet_storage_slot['igmp_checksum'] = packet[IGMP].chksum
            packet_storage_slot['igmp_group_address'] = packet[IGMP].gaddr



    @staticmethod
    def parse_igmp_message_type(message_type):

        response_map = {0x11: 'Membership query',
                        0x12: 'IGMPv1 Membership Report',
                        0x16: 'IGMPv2 Membership Report',
                        0x17: 'Leave Group (IGMPv2)',
                        0x22: 'IGMPv3 Membership Report'}

        return response_map[message_type]