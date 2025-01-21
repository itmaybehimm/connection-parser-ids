# import re
from __future__ import annotations

from pyshark.packet.packet import Packet

# from connection import Connection
from custom_types import PORT_SERVICE_MAP, Service


from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from connection import Connection


class Utils:

    @staticmethod
    def get_service(packet: Packet) -> Service:
        if hasattr(packet, "tcp"):
            return PORT_SERVICE_MAP[int(packet.tcp.dstport)]
        return Service.UNKNOWN

    @staticmethod
    def is_internal_ip(ip: str) -> bool:
        """Check if the IP address is internal (hardcoded for testing)."""
        # Hardcoded internal IPs
        internal_ips = ["192.168.31.212", "127.0.0.1"]
        return ip in internal_ips

    # @staticmethod
    # def is_internal_ip(ip: str) -> bool:
    #     """Check if the IP address is internal (private or loopback)."""
    #     internal_ip_pattern = (
    #         r"^(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
    #         r"172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}|"
    #         r"192\.168\.\d{1,3}\.\d{1,3}|"
    #         r"127\.\d{1,3}\.\d{1,3}\.\d{1,3})$"
    #     )
    #     return re.match(internal_ip_pattern, ip) is not None

    @staticmethod
    def is_wrong_fragment(packet: Packet) -> bool:
        """Check if the given IP packet is a wrong fragment."""
        # TODO Placeholder for future logic; currently returns False
        return False

    @staticmethod
    def packet_has_syn_flag(packet: Packet) -> bool:
        """Check if the TCP packet has the SYN flag set."""
        return packet.tcp.flags_syn == "True"

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


def serialize_connection(connection: Connection) -> dict:
    """
    Serialize the Connection object to extract features for real-time analysis.

    Args:
    - connection: The connection object to be serialized.

    Returns:
    - A dictionary with the features for the machine learning model.
    """

    # extract duration
    # TODO UDP ko close paxi duration napeko vayera close to 0? huna ta last 2 sec ko nikalxam
    duration = connection.duration

    # Extract protocol type
    protocol_type = connection.protocol.value

    # Infer service from destination port
    service = connection.service.value

    # Extract flags for TCP connections
    flag = connection.connection_flag.value

    # Get bytes sent from source and destination
    src_bytes = connection.src_bytes
    dst_bytes = connection.dst_bytes

    # Land feature: 1 if source and destination IP and ports are the same, else 0
    land = connection.is_land

    # Wrong fragments and urgent packets
    wrong_fragment = connection.wrong_fragments
    urgent = connection.urgent_packets

    # Number of connections (to be calculated based on connection_metric count)
    count = connection.count

    # Number of connections to the same service
    srv_count = connection.srv_count

    # Error rates
    serror_rate = connection.serror_rate
    srv_serror_rate = connection.srv_serror_rate
    rerror_rate = connection.rerror_rate
    srv_rerror_rate = connection.srv_rerror_rate

    # Same service rate and different service rate
    same_srv_rate = connection.same_srv_rate
    diff_srv_rate = connection.diff_srv_rate

    # Destination host related features
    dst_host_count = connection.dst_host_count
    dst_host_srv_count = connection.dst_host_srv_count
    dst_host_same_srv_rate = connection.dst_host_same_srv_rate
    dst_host_diff_srv_rate = connection.dst_host_diff_srv_rate
    dst_host_same_src_port_rate = connection.dst_host_same_src_port_rate
    dst_host_serror_rate = connection.dst_host_serror_rate
    dst_host_srv_serror_rate = connection.dst_host_srv_serror_rate
    dst_host_rerror_rate = connection.dst_host_rerror_rate
    dst_host_srv_rerror_rate = connection.dst_host_srv_rerror_rate

    # Connections to different hosts for the same service
    srv_diff_host_rate = connection.srv_diff_host_rate

    # Return the serialized features
    return {
        "duration": duration,
        "protocol_type": protocol_type,
        "service": service,
        "flag": flag,
        "src_bytes": src_bytes,
        "dst_bytes": dst_bytes,
        "land": land,
        "wrong_fragment": wrong_fragment,
        "urgent": urgent,
        "count": count,
        "srv_count": srv_count,
        "serror_rate": serror_rate,
        "srv_serror_rate": srv_serror_rate,
        "rerror_rate": rerror_rate,
        "srv_rerror_rate": srv_rerror_rate,
        "same_srv_rate": same_srv_rate,
        "diff_srv_rate": diff_srv_rate,
        "dst_host_count": dst_host_count,
        "dst_host_srv_count": dst_host_srv_count,
        "dst_host_same_srv_rate": dst_host_same_srv_rate,
        "dst_host_diff_srv_rate": dst_host_diff_srv_rate,
        "dst_host_same_src_port_rate": dst_host_same_src_port_rate,
        "dst_host_serror_rate": dst_host_serror_rate,
        "dst_host_srv_serror_rate": dst_host_srv_serror_rate,
        "dst_host_rerror_rate": dst_host_rerror_rate,
        "dst_host_srv_rerror_rate": dst_host_srv_rerror_rate,
        "srv_diff_host_rate": srv_diff_host_rate,
    }
