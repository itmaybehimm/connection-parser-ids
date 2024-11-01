import re
from pyshark.packet.packet import Packet

from custom_types import PORT_SERVICE_MAP, Service


class Utils:

    @staticmethod
    def get_service(packet: Packet) -> Service:
        if hasattr(packet, "tcp"):
            return PORT_SERVICE_MAP[int(packet.tcp.dstport)]
        return Service.UNKNOWN

    @staticmethod
    def is_internal_ip(ip: str) -> bool:
        """Check if the IP address is internal (private or loopback)."""
        internal_ip_pattern = (
            r"^(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
            r"172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}|"
            r"192\.168\.\d{1,3}\.\d{1,3}|"
            r"127\.\d{1,3}\.\d{1,3}\.\d{1,3})$"
        )
        return re.match(internal_ip_pattern, ip) is not None

    @staticmethod
    def is_wrong_fragment(packet: Packet) -> bool:
        """Check if the given IP packet is a wrong fragment."""
        # Placeholder for future logic; currently returns False
        return False

    @staticmethod
    def packet_has_urg_flag(packet: Packet) -> bool:
        """Check if the TCP packet has the URG flag set."""
        return packet.tcp.flags_urg == "True"

    @staticmethod
    def packet_has_fin_flag(packet: Packet) -> bool:
        """Check if the TCP packet has the FIN flag set."""
        return packet.tcp.flags_fin == "True"

    @staticmethod
    def packet_has_rst_flag(packet: Packet) -> bool:
        """Check if the TCP packet has the RST flag set."""
        return packet.tcp.flags_reset == "True"

    @staticmethod
    def packet_has_mf_flag(packet: Packet) -> bool:
        """Check if the IP packet has the 'More Fragments' (MF) flag set."""
        return packet.ip.flags_mf == "True"

    @staticmethod
    def packet_has_df_flag(packet: Packet) -> bool:
        """Check if the IP packet has the 'Don't Fragment' (DF) flag set."""
        return packet.ip.flags_df == "True"
