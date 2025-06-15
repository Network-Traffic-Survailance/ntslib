"""
DNS is the internet’s directory service that translates human-friendly domain names into IP addresses,
allowing devices to find and connect to websites and services easily.
"""

from scapy.layers.dns import DNS, DNSQR

class DomainNameSystemProtocol(DNS):
    def __init__(self,packet_data_storage):
        super().__init__()
        self.packet_data_storage = packet_data_storage
        # DNS
        self.identification = None
        self.query_flag = None
        self.operation_code = None
        self.authoritative_answer = None
        self.truncation_flag = None
        self.recursion_desired = None
        self.recursion_available = None
        self.reserved_fields = None
        self.authentication_data = None
        self.checking_disabled = None
        self.response_code = None
        self.question_count = None
        self.answer_record_count = None
        self.authority_record_count = None
        self.additional_record_count = None

        # DNSQR
        self.query_name = None
        self.query_type = None
        self.unicast_response_flag = None
        self.query_class = None



    def process(self,packet):
        packet_storage_slot = self.packet_data_storage[id(packet)]

        if DNS in packet:
            packet_storage_slot['dns_identification'] = packet[DNS].id
            packet_storage_slot['query_flag'] = packet[DNS].qr
            packet_storage_slot['operation_code'] = packet[DNS].opcode
            packet_storage_slot['authoritative_answer'] = packet[DNS].aa
            packet_storage_slot['truncation_flag'] = packet[DNS].tc
            packet_storage_slot['recursion_desired'] = packet[DNS].rd
            packet_storage_slot['recursion_available'] = packet[DNS].ra
            packet_storage_slot['reserved_fields'] = packet[DNS].z
            packet_storage_slot['authentication_data'] = packet[DNS].ad
            packet_storage_slot['checking_disabled'] = packet[DNS].cd
            packet_storage_slot['response_code'] = packet[DNS].rcode
            packet_storage_slot['question_count'] = packet[DNS].qdcount
            packet_storage_slot['answer_record_count'] = packet[DNS].ancount
            packet_storage_slot['authority_record_count'] = packet[DNS].nscount
            packet_storage_slot['additional_record_count'] = packet[DNS].arcount

        if DNSQR in packet:
            packet_storage_slot['query_name'] = packet[DNSQR].qname
            packet_storage_slot['query_type'] = packet[DNSQR].qtype
            packet_storage_slot['unicast_response_flag'] = packet[DNSQR].unicastresponse
            packet_storage_slot['query_class'] = packet[DNSQR].qclass

    @staticmethod
    def parse_query_flag(flag):
        return "Query" if not flag else "Response"


    @staticmethod
    def parse_operation_code(operation_code):
        response_map = {0:"Standard Query",
                        1:"Inverse Response",
                        2:"Server Status Request",}
        return response_map[operation_code]

    @staticmethod
    def parse_response_code(response_code):
        response_map = {
            0: "No Error",
            1: "Format Error",
            2: "Server Failure",
            3: "Name Error",
            4: "Not implemented",
            5: "Refused",
        }
        return response_map[response_code]

    @staticmethod
    def parse_query_type(query_type):
        response_map = {1:'A (IPV4)',
                        28:'AAAA (IPV6)',
                        15:'MX (Mail Exchange)',
                        16:'TXT (Text Records)',
                        2:'NS (name server)',
                        12:'PTR (PTR Exchange)'}
        return response_map[query_type]


    @staticmethod
    def parse_query_class(query_class):
        response_map = {
            1:'IN (Internet)',
            3:'CH (Chaos)',
            4:'HS (Hesiod)',
            255:'ANY (wildcard)',}
        return response_map[query_class]