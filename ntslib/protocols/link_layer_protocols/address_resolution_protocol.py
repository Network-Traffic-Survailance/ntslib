"""
ARP is used to find the Mac addresses on the local network via the IP address.
It yells who knows the Mac address of this IP address, and tells the one that finds it, where to send it.

"""
from scapy.layers.l2 import ARP


class AddressResolutionProtocol(ARP):
    def __init__(self,packet_data_storage):
        super().__init__()
        self.packet_data_storage = packet_data_storage
        # Hardware (MAC) source address
        self.hardware_source_address = None

        # Hardware (MAC) destination address
        self.hardware_destination_address = None

        # Hardware type (e.g., 1 for Ethernet)
        self.hardware_type = None

        # Hardware address length (e.g., 6 for MAC addresses)
        self.hardware_address_length = None

        # Protocol address length (e.g., 4 for IPv4)
        self.protocol_address_length = None

        # Operation (1 = request, 2 = reply)
        self.operation = None

        # Protocol (IP) source address
        self.protocol_source_address = None

        # Protocol (IP) destination address
        self.protocol_destination_address = None


    def process(self,packet):
        packet_storage_slot = self.packet_data_storage[id(packet)]
        if ARP in packet:
            packet_storage_slot['hardware_source_address'] = packet[ARP].hwsrc
            packet_storage_slot['hardware_destination_address'] = packet[ARP].hwdst
            packet_storage_slot['hardware_type'] = packet[ARP].hwtype
            packet_storage_slot['hardware_address_length'] = packet[ARP].hwlen
            packet_storage_slot['protocol_address_length'] = packet[ARP].plen
            packet_storage_slot['arp_operation'] =  packet[ARP].op
            packet_storage_slot['protocol_source_address'] = packet[ARP].psrc
            packet_storage_slot['protocol_destination_address'] = packet[ARP].pdst

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
            65535: "Reserved"
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
            65535: "Reserved"
        }

        return response_map[hardware_type]