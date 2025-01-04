from __future__ import annotations

from pyshark.packet.packet import Packet
from custom_types import ConnectionFlag, Protocol

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from connection import Connection


def assign_connection_flag_inplace(connection: Connection) -> ConnectionFlag:
    """
    Check and assign the correct flag based on connection state and packet flags.
    """
    if connection.protocol != Protocol.TCP:
        # Already initialized at other place
        return connection.connection_flag

    if connection.connection_flag != ConnectionFlag.OTH:
        return connection.connection_flag

    # Use utility methods to check flag types
    if is_sf_flag(connection):
        connection.connection_flag = ConnectionFlag.SF
    elif is_s0_flag(connection):
        connection.connection_flag = ConnectionFlag.S0
    elif is_s1_flag(connection):
        connection.connection_flag = ConnectionFlag.S1
    elif is_s2_flag(connection):
        connection.connection_flag = ConnectionFlag.S2
    elif is_s3_flag(connection):
        connection.connection_flag = ConnectionFlag.S3
    elif is_rej_flag(connection):
        connection.connection_flag = ConnectionFlag.REJ
    else:
        connection.connection_flag = ConnectionFlag.OTH

    return connection.connection_flag


def assign_connection_rst_flag_inplace(connection: Connection, packet: Packet):
    """
    Check for various RST-related flags and update the connection flag.
    """
    if is_rstr_flag(connection, packet):
        connection.connection_flag = ConnectionFlag.RSTR
    elif is_sh_flag(connection, packet):
        connection.connection_flag = ConnectionFlag.SH
    elif is_rsto_flag(connection, packet):
        connection.connection_flag = ConnectionFlag.RSTO
    elif is_rstos0_flag(connection, packet):
        connection.connection_flag = ConnectionFlag.RSTOS0


# Utility functions to check flags
def is_sf_flag(connection: Connection):
    """
    Normal Connection closed gracefully
    """
    return (
        # connection.pyshark_flags.flags_syn
        # and
        connection.pyshark_flags.flags_syn_ack
        and connection.pyshark_flags.flags_fin
        and not connection.pyshark_flags.flags_reset
    )


def is_s0_flag(connection: Connection):
    """
    Connection attempt seen but no reply
    """
    return (
        # connection.pyshark_flags.flags_syn
        # and
        not connection.pyshark_flags.flags_syn_ack
        and not connection.pyshark_flags.flags_fin
        and not connection.pyshark_flags.flags_reset
    )


def is_s1_flag(connection: Connection) -> bool:
    """
    Connection established not terminated

    NOTE Fixing src_bytes to have just payload may be better
    """
    return (
        # connection.pyshark_flags.flags_syn_ack  # SYN-ACK flag is set
        # and
        connection.pyshark_flags.flags_syn  # SYN flag is set
        and connection.src_bytes == 0  # No bytes sent from source
        and connection.dst_bytes == 0  # No bytes sent to destination
        and not (  # Ensure no RST or FIN flags are set
            connection.pyshark_flags.flags_reset  # RST flag is not set
            or connection.pyshark_flags.flags_fin  # FIN flag is not set
        )
    )


def is_s2_flag(connection: Connection) -> bool:
    """
    Connection established and closed attempt by originator but no reply from responder
    """
    pass


def is_s3_flag(connection: Connection) -> bool:
    """
    Connection established and closed attempt by responder but no reply from originator
    """
    pass


def is_rej_flag(connection: Connection):
    """
    Connection attempt rejected
    """
    # Check for a SYN packet immediately followed by a RST packet,
    # and ensure no other flags are set
    return (
        # connection.pyshark_flags.flags_syn
        # and
        connection.pyshark_flags.flags_reset
        and not (
            connection.pyshark_flags.flags_ack
            or connection.pyshark_flags.flags_syn_ack
            or connection.pyshark_flags.flags_fin
        )
    )


def is_rstr_flag(connection: Connection, packet: Packet) -> bool:
    """
    Check if the packet indicates a reset connection from the source.
    """
    return (
        connection.pyshark_flags.flags_reset
        and packet.ip.src == connection.src_ip
        and (
            int(packet.tcp.srcport) == connection.src_port
            or int(packet.tcp.dstport) == connection.dst_port
        )
    )


def is_sh_flag(connection: Connection, packet: Packet) -> bool:
    """
    Originator sent a SYN followed by FIN, we never saw SYN_ACK from responder
    """
    return (
        # connection.pyshark_flags.flags_syn  # SYN flag is set
        # and
        (connection.pyshark_flags.flags_fin)  # RST flag is set
        and connection.src_ip == packet.ip.src  # Source IP matches
        and not (
            connection.pyshark_flags.flags_syn_ack  # SYN-ACK flag is not set
            # or connection.pyshark_flags.flags_ack  # ACK flag is not set
        )
    )


def is_rsto_flag(connection: Connection, packet: Packet) -> bool:
    """
    Connection reset by originator
    """
    return (
        connection.pyshark_flags.flags_reset  # RST flag is set
        and connection.src_ip
        == packet.ip.dst  # Source IP matches the destination of the packet
        and connection.src_port == int(packet.tcp.dstport)
    )


def is_rstos0_flag(connection: Connection, packet: Packet) -> bool:
    """
    Originator sent a SYN followed by RST, we never saw SYN_ACK from responder
    """
    return (
        # connection.pyshark_flags.flags_syn  # SYN flag is set
        # and
        connection.pyshark_flags.flags_reset  # RST flag is set
        and connection.src_ip == packet.ip.src  # Source IP matches
        and not (
            connection.pyshark_flags.flags_ack  # ACK flag is not set
            or connection.pyshark_flags.flags_fin  # FIN flag is not set
            or connection.pyshark_flags.flags_syn_ack  # SYN-ACK flag is not set
        )
    )
