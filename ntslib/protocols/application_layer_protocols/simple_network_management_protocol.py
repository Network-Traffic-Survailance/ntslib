"""
SNMP (Simple Network Management Protocol) is a protocol used by network administrators to monitor and manage network devices,
collecting data like status, performance, and configuration remotely.
"""

from scapy.layers.snmp import SNMP, SNMPget

class SimpleNetworkManagementProtocol:
    def __init__(self,packet_data_storage):
        self.packet_data_storage = packet_data_storage
        # SNMP
        self.version = None
        self.community = None

        # SNMPget,packet_data_storage

        self.id = None
        self.error = None
        self.error_index = None


    def process(self,packet):
        packet_storage_slot = self.packet_data_storage[id(packet)]

        if SNMP in packet:
            packet_storage_slot['snmp_version'] = packet[SNMP].version
            packet_storage_slot['snmp_community'] = packet[SNMP].community

        if SNMPget in packet:
            packet_storage_slot['snmp_id'] = packet[SNMP].id
            packet_storage_slot['snmp_error'] = packet[SNMP].error
            packet_storage_slot['snmp_error_index'] = packet[SNMP].error_index

