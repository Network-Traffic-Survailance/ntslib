"""
TLS is the protocol that encrypts internet communications to keep data private and secure between clients and servers,
protecting information like passwords, messages, and transactions from eavesdropping or tampering.
"""

from scapy.layers.tls.record import TLS


class TransportLayerSecurity(TLS):
    def __init__(self,packet_data_storage):
        super().__init__()
        self.packet_data_storage = packet_data_storage

        self.content_type = None
        self.protocol_version = None
        self.length = None
        self.initialization_vector = None
        self.message_payload = None
        self.message_authentication_code = None
        self.padding = None
        self.padding_length = None


    def process(self,packet):
        packet_storage_slot = self.packet_data_storage[id(packet)]

        if TLS in packet:
            packet_storage_slot['content_type'] = packet[TLS].type
            packet_storage_slot['protocol_version'] =packet[TLS].version
            packet_storage_slot['tls_length'] = packet[TLS].len
            packet_storage_slot['initialization_vector'] = packet[TLS].iv
            packet_storage_slot['message_payload'] = packet[TLS].msg
            packet_storage_slot['message_authentication_code'] = packet[TLS].mac
            packet_storage_slot['padding'] = packet[TLS].pad
            packet_storage_slot['padding_length'] = packet[TLS].padlen


    @staticmethod
    def parse_content_types(content_types):
        response_map = {
                20:'ChangeCipherSpec', # Signals change to new cypher specs
                21:'Alert', # Alert messages
                22:'Handshake', # Handshake protocol message
                23:'Application Data', # Encrypted application layer data
                24:'Heartbeat'}

        return response_map[content_types]