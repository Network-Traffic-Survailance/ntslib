from scapy.contrib.igmp import IGMP
from scapy.layers.dhcp import DHCP
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.layers.sctp import SCTP
from scapy.layers.snmp import SNMP, SNMPget
from scapy.layers.tls.record import TLS


class DomainNameSystemProtocol:
    """
    DNS is the internet’s directory service that translates human-friendly domain names into IP addresses,
    allowing devices to find and connect to websites and services easily.
    """

    @classmethod
    def process(cls, packet, packet_data_storage):
        packet_storage_slot = packet_data_storage[id(packet)]

        if DNS in packet:
            packet_storage_slot["dns_identification"] = packet[DNS].id
            packet_storage_slot["query_flag"] = packet[DNS].qr
            packet_storage_slot["operation_code"] = packet[DNS].opcode
            packet_storage_slot["authoritative_answer"] = packet[DNS].aa
            packet_storage_slot["truncation_flag"] = packet[DNS].tc
            packet_storage_slot["recursion_desired"] = packet[DNS].rd
            packet_storage_slot["recursion_available"] = packet[DNS].ra
            packet_storage_slot["reserved_fields"] = packet[DNS].z
            packet_storage_slot["authentication_data"] = packet[DNS].ad
            packet_storage_slot["checking_disabled"] = packet[DNS].cd
            packet_storage_slot["response_code"] = packet[DNS].rcode
            packet_storage_slot["question_count"] = packet[DNS].qdcount
            packet_storage_slot["answer_record_count"] = packet[DNS].ancount
            packet_storage_slot["authority_record_count"] = packet[DNS].nscount
            packet_storage_slot["additional_record_count"] = packet[DNS].arcount

        if DNSQR in packet:
            packet_storage_slot["query_name"] = packet[DNSQR].qname
            packet_storage_slot["query_type"] = packet[DNSQR].qtype
            packet_storage_slot["unicast_response_flag"] = packet[DNSQR].unicastresponse
            packet_storage_slot["query_class"] = packet[DNSQR].qclass

    @staticmethod
    def parse_query_flag(flag):
        return "Query" if not flag else "Response"

    @staticmethod
    def parse_operation_code(operation_code):
        response_map = {
            0: "Standard Query",
            1: "Inverse Response",
            2: "Server Status Request",
        }
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
        response_map = {
            1: "A (IPV4)",
            28: "AAAA (IPV6)",
            15: "MX (Mail Exchange)",
            16: "TXT (Text Records)",
            2: "NS (name server)",
            12: "PTR (PTR Exchange)",
        }
        return response_map[query_type]

    @staticmethod
    def parse_query_class(query_class):
        response_map = {
            1: "IN (Internet)",
            3: "CH (Chaos)",
            4: "HS (Hesiod)",
            255: "ANY (wildcard)",
        }
        return response_map[query_class]


class DynamicHostConfigurationProtocol:
    """
    DHCP is the network’s automatic address assigner that gives devices their IP addresses and other network settings,
    so they can join and communicate on a network without manual configuration.
    """

    @classmethod
    def process(cls, packet, packet_data_storage):
        if DHCP in packet:
            packet_storage_slot = packet_data_storage[id(packet)]
            packet_storage_slot["dhcp_options"] = packet[DHCP].options


class SimpleNetworkManagementProtocol:
    """
    SNMP (Simple Network Management Protocol) is a protocol used by network administrators to monitor and manage network devices,
    collecting data like status, performance, and configuration remotely.
    """

    @classmethod
    def process(cls, packet, packet_data_storage):
        packet_storage_slot = packet_data_storage[id(packet)]

        if SNMP in packet:
            packet_storage_slot["snmp_version"] = packet[SNMP].version
            packet_storage_slot["snmp_community"] = packet[SNMP].community

        if SNMPget in packet:
            packet_storage_slot["snmp_id"] = packet[SNMP].id
            packet_storage_slot["snmp_error"] = packet[SNMP].error
            packet_storage_slot["snmp_error_index"] = packet[SNMP].error_index


class AddressResolutionProtocol:
    """
    ARP is used to find the Mac addresses on the local network via the IP address.
    It yells who knows the Mac address of this IP address, and tells the one that finds it, where to send it.
    """

    @classmethod
    def process(cls, packet, packet_data_storage):
        if ARP in packet:
            packet_storage_slot = packet_data_storage[id(packet)]
            packet_storage_slot["hardware_source_address"] = packet[ARP].hwsrc
            packet_storage_slot["hardware_destination_address"] = packet[ARP].hwdst
            packet_storage_slot["hardware_type"] = packet[ARP].hwtype
            packet_storage_slot["hardware_address_length"] = packet[ARP].hwlen
            packet_storage_slot["protocol_address_length"] = packet[ARP].plen
            packet_storage_slot["arp_operation"] = packet[ARP].op
            packet_storage_slot["protocol_source_address"] = packet[ARP].psrc
            packet_storage_slot["protocol_destination_address"] = packet[ARP].pdst

    @staticmethod
    def parse_arp_operation(arp_operation):
        response_map = {
            0: "Reserved",
            1: "REQUEST",
            2: "REPLY",
            3: "request Reverse",
            4: "reply Reverse",
            5: "DRARP-Request",
            6: "DRARP-Reply",
            7: "DRARP-Error",
            8: "InARP-Request",
            9: "InARP-Reply",
            10: "ARP-NAK",
            11: "MARS-Request",
            12: "MARS-Multi",
            13: "MARS-MServ",
            14: "MARS-Join",
            15: "MARS-Leave",
            16: "MARS-NAK",
            17: "MARS-Unserv",
            18: "MARS-SJoin",
            19: "MARS-SLeave",
            20: "MARS-Grouplist-Request",
            21: "MARS-Grouplist-Reply",
            22: "MARS-Redirect-Map",
            23: "MAPOS-UNARP",
            24: "OP_EXP1",
            25: "OP_EXP2",
            65535: "Reserved",
        }
        return response_map[arp_operation]

    @staticmethod
    def parse_hardware_type(hardware_type):
        response_map = {
            0: "Reserved",
            1: "Ethernet (10Mb)",
            2: "Experimental Ethernet (3Mb)",
            3: "Amateur Radio AX.25",
            4: "Proteon ProNET Token Ring",
            5: "Chaos",
            6: "IEEE 802 Networks",
            7: "ARCNET",
            8: "Hyperchannel",
            9: "Lanstar",
            10: "Autonet Short Address",
            11: "LocalTalk",
            12: "LocalNet (IBM PCNet or SYTEK LocalNET)",
            13: "Ultra link",
            14: "SMDS",
            15: "Frame Relay",
            16: "Asynchronous Transmission Mode (ATM)",
            17: "HDLC",
            18: "Fibre Channel",
            19: "Asynchronous Transmission Mode (ATM)",
            20: "Serial Line",
            21: "Asynchronous Transmission Mode (ATM)",
            22: "MIL-STD-188-220",
            23: "Metricom",
            24: "IEEE 1394.1995",
            25: "MAPOS",
            26: "Twinaxial",
            27: "EUI-64",
            28: "HIPARP",
            29: "IP and ARP over ISO 7816-3",
            30: "ARPSec",
            31: "IPsec tunnel",
            32: "InfiniBand (TM)",
            33: "TIA-102 Project 25 Common Air Interface (CAI)",
            34: "Wiegand Interface",
            35: "Pure IP",
            36: "HW_EXP1",
            37: "HFI",
            38: "Unified Bus (UB)",
            256: "HW_EXP2",
            257: "AEthernet",
            65535: "Reserved",
        }

        return response_map[hardware_type]


class Ethernet:
    """Ethernet defines how devices on the same local network send and receive data
    by packaging data into frames and delivering those frames between devices

    It uses MAC addresses to identify sender and receiver hardware.
    """

    @classmethod
    def process(cls, packet, packet_data_storage):
        if Ether in packet:
            packet_storage_slot = packet_data_storage[id(packet)]
            packet_storage_slot["mac_address_src"] = packet[Ether].src
            packet_storage_slot["mac_address_dst"] = packet[Ether].dst
            packet_storage_slot["ethernet_type"] = packet[Ether].type

    @staticmethod
    def parse_ethernet_type(ethernet_type):
        response_map = {
            2048: "IPv4",
            2054: "ARP",
            32821: "PPPoE",
            34525: "IPv6",
            33024: "VLAN-tagged",
            34958: "LLDP",
            34916: "Q-in-Q VLAN",
            34825: "Slow Protocols",
            34826: "PPP",
            34506: "IPv6",
            33011: "AARP",
        }

        return response_map[ethernet_type]


class InternetControlMessageProtocol:
    """
    ICMP is like a messenger between computers and routers that says,
    “Something went wrong with your packet,” or “Here’s a status update.”
    """

    @classmethod
    def process(cls, packet, packet_data_storage):
        if ICMP in packet:
            packet_storage_slot = packet_data_storage[id(packet)]
            packet_storage_slot["icmp_message_type"] = packet[ICMP].type
            packet_storage_slot["code"] = packet[ICMP].code
            packet_storage_slot["icmp_checksum"] = packet[ICMP].chksum
            packet_storage_slot["identifier"] = packet[ICMP].id
            packet_storage_slot["sequence_number"] = packet[ICMP].seq
            packet_storage_slot["unused_field"] = packet[ICMP].unused

    @staticmethod
    def parse_message_type(message_type):
        response_map = {
            0: "Echo Reply",
            3: "Destination Unreachable",
            4: "Source Quench",
            5: "Redirect",
            8: "Echo Request",
            11: "Time Exceeded",
            12: "Parameter Problem",
            13: "Timestamp Request",
            14: "Timestamp Reply",
        }
        return response_map[message_type]

    @staticmethod
    def parse_icmp_code(code):
        response_map = {
            0: "Network unreachable",
            1: "Host unreachable",
            2: "Protocol unreachable",
            3: "Port unreachable",
            4: "Fragmentation needed",
        }

        return response_map[code]


class InternetGroupManagementProtocol:
    """
    IGMP helps manage group memberships for devices that want to receive multicast traffic,
    so the network only sends data to those who asked for it
    """

    @classmethod
    def process(cls, packet, packet_data_storage):
        if IGMP in packet:
            packet_storage_slot = packet_data_storage[id(packet)]
            packet_storage_slot["igmp_message_type"] = packet[IGMP].type
            packet_storage_slot["igmp_max_response_code"] = packet[IGMP].mrcode
            packet_storage_slot["igmp_checksum"] = packet[IGMP].chksum
            packet_storage_slot["igmp_group_address"] = packet[IGMP].gaddr

    @staticmethod
    def parse_igmp_message_type(message_type):

        response_map = {
            0x11: "Membership query",
            0x12: "IGMPv1 Membership Report",
            0x16: "IGMPv2 Membership Report",
            0x17: "Leave Group (IGMPv2)",
            0x22: "IGMPv3 Membership Report",
        }

        return response_map[message_type]


class InternetProtocol:
    """
    IP is the postal system of the internet.
    It gives every device an address, and it helps data travel from sender to receiver across different networks.
    """

    @classmethod
    def process(cls, packet, packet_data_storage):
        ip_version = None
        if IP in packet:
            ip_version = IP
        if IPv6 in packet:
            ip_version = IPv6

        if ip_version:
            packet_storage_slot = packet_data_storage[id(packet)]
            if ip_version == IP:
                packet_storage_slot["ip_version"] = "IPV4"
                packet_storage_slot["internet_header_length"] = packet[ip_version].ihl
                packet_storage_slot["type_of_service"] = packet[ip_version].tos
                packet_storage_slot["total_length"] = packet[ip_version].len
                packet_storage_slot["identification"] = packet[ip_version].id
                packet_storage_slot["flags"] = packet[ip_version].flags
                packet_storage_slot["fragment_offset"] = packet[ip_version].frag
                packet_storage_slot["time_to_live"] = packet[ip_version].ttl
                packet_storage_slot["protocol"] = packet[ip_version].proto
                packet_storage_slot["header_checksum"] = packet[ip_version].chksum
                packet_storage_slot["source_ip_address"] = packet[ip_version].src
                packet_storage_slot["destination_ip_address"] = packet[ip_version].dst
                packet_storage_slot["ipv4_options"] = packet[ip_version].options
            else:
                packet_storage_slot["ip_version"] = "IPV6"
                packet_storage_slot["traffic_class"] = packet[ip_version].tc
                packet_storage_slot["payload_length"] = packet[ip_version].plen
                packet_storage_slot["hop_limit"] = packet[ip_version].hlim
                packet_storage_slot["next_header"] = packet[ip_version].nh
                packet_storage_slot["flow_label"] = packet[ip_version].fl
                packet_storage_slot["source_ip_address"] = packet[ip_version].src
                packet_storage_slot["destination_ip_address"] = packet[ip_version].dst


class TransportLayerSecurity:
    """
    TLS is the protocol that encrypts internet communications to keep data private and secure between clients and servers,
    protecting information like passwords, messages, and transactions from eavesdropping or tampering.
    """

    @classmethod
    def process(cls, packet, packet_data_storage):
        if TLS in packet:
            packet_storage_slot = packet_data_storage[id(packet)]
            packet_storage_slot["content_type"] = packet[TLS].type
            packet_storage_slot["protocol_version"] = packet[TLS].version
            packet_storage_slot["tls_length"] = packet[TLS].len
            packet_storage_slot["initialization_vector"] = packet[TLS].iv
            packet_storage_slot["message_payload"] = packet[TLS].msg
            packet_storage_slot["message_authentication_code"] = packet[TLS].mac
            packet_storage_slot["padding"] = packet[TLS].pad
            packet_storage_slot["padding_length"] = packet[TLS].padlen

    @staticmethod
    def parse_content_types(content_types):
        response_map = {
            20: "ChangeCipherSpec",  # Signals change to new cypher specs
            21: "Alert",  # Alert messages
            22: "Handshake",  # Handshake protocol message
            23: "Application Data",  # Encrypted application layer data
            24: "Heartbeat",
        }

        return response_map[content_types]


class StreamControlTransmissionProtocol:
    """
    SCTP is designed to reliably transmit data with support for multiple streams and improved fault tolerance,
    often used in telecommunications and signaling networks.
    """

    @classmethod
    def process(cls, packet, packet_data_storage):
        if SCTP in packet:
            packet_storage_slot = packet_data_storage[id(packet)]
            packet_storage_slot["sctp_source_port"] = packet[SCTP].sport
            packet_storage_slot["sctp_dest_port"] = packet[SCTP].dport
            packet_storage_slot["sctp_verification_tag"] = packet[SCTP].tag
            packet_storage_slot["sctp_checksum"] = packet[SCTP].chksum


class TransmissionControlProtocol:
    """
    TCP is connection-oriented protocol that ensures data is delivered in order and without errors by establishing
    a connection between sender and receiver before data transfer.
    """

    @classmethod
    def process(cls, packet, packet_data_storage):
        if TCP in packet:
            packet_storage_slot = packet_data_storage[id(packet)]
            packet_storage_slot["source_port"] = packet[TCP].sport
            packet_storage_slot["destination_port"] = packet[TCP].dport
            packet_storage_slot["sequence_number"] = packet[TCP].seq
            packet_storage_slot["acknowledgement_number"] = packet[TCP].ack
            packet_storage_slot["data_offset"] = packet[TCP].dataofs
            packet_storage_slot["reserved"] = packet[TCP].reserved
            packet_storage_slot["control_flags"] = packet[TCP].flags
            packet_storage_slot["window_size"] = packet[TCP].window
            packet_storage_slot["tcp_checksum"] = packet[TCP].chksum
            packet_storage_slot["urgent_pointer"] = packet[TCP].urgptr
            packet_storage_slot["tcp_options"] = packet[TCP].options


class UserDatagramProtocol:
    """
    UDP is a simple, connectionless protocol that sends data quickly without guaranteeing delivery or order,
    often used for real-time applications like video streaming or gaming.
    """

    @classmethod
    def process(cls, packet, packet_data_storage):
        if UDP in packet:
            packet_storage_slot = packet_data_storage[id(packet)]
            packet_storage_slot["udp_source_port"] = packet[UDP].sport
            packet_storage_slot["udp_destination_port"] = packet[UDP].dport
            packet_storage_slot["udp_length"] = packet[UDP].len
            packet_storage_slot["udp_checksum"] = packet[UDP].chksum
