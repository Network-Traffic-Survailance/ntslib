"""
SCTP is designed to reliably transmit data with support for multiple streams and improved fault tolerance,
often used in telecommunications and signaling networks.
"""

from scapy.layers.sctp import SCTP


class StreamControlTransmissionProtocol(SCTP):
    def __init__(self):
        super().__init__()
        self.source_port = None
        self.destination_port = None
        self.verification_tag = None
        self.checksum = None


    def process(self,packet):
        if SCTP in packet:
            self.source_port = packet[SCTP].sport
            self.destination_port = packet[SCTP].dport
            self.verification_tag = packet[SCTP].tag
            self.checksum = packet[SCTP].chksum
