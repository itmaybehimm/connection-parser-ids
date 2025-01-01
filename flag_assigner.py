from pyshark.packet.packet import Packet

from connection import Connection
from custom_types import ConnectionFlag, Protocol


class FlagUtils:
    @staticmethod
    def check_flags(connection: Connection) -> ConnectionFlag:
        """
        Check and assign the correct flag based on connection state and packet flags.
        """
        if connection.protocol != Protocol.TCP:
            # Already initialized at other place
            return connection.connection_flag

        if connection.connection_flag != ConnectionFlag.OTH:
            return connection.connection_flag

        # Use utility methods to check flag types
        if FlagUtils._is_SF_flag(connection):
            connection.connection_flag = ConnectionFlag.SF
        elif FlagUtils._is_S0_flag(connection):
            connection.connection_flag = ConnectionFlag.S0
        elif FlagUtils._is_S1_flag(connection):
            connection.connection_flag = ConnectionFlag.S1
        elif FlagUtils._is_S2_flag(connection):
            connection.connection_flag = ConnectionFlag.S2
        elif FlagUtils._is_S3_flag(connection):
            connection.connection_flag = ConnectionFlag.S3
        elif FlagUtils._is_REJ_flag(connection):
            connection.connection_flag = ConnectionFlag.REJ
        else:
            connection.connection_flag = ConnectionFlag.OTH

        return connection.connection_flag

    @staticmethod
    def check_rst_flags(connection: Connection, packet: Packet):
        """
        Check for various RST-related flags and update the connection flag.
        """
        if FlagUtils._is_RSTR_flag(connection, packet):
            connection.connection_flag = ConnectionFlag.RSTR
        elif FlagUtils._is_SH_flag(connection, packet):
            connection.connection_flag = ConnectionFlag.SH
        elif FlagUtils._is_RSTO_flag(connection, packet):
            connection.connection_flag = ConnectionFlag.RSTO
        elif FlagUtils._is_RSTOS0_flag(connection, packet):
            connection.connection_flag = ConnectionFlag.RSTOS0

    # Utility methods to check flags
    @staticmethod
    def _is_SF_flag(self):
        """
        Normal Connection closed gracefully
        """
        return (
            # self.pyshark_flags.flags_syn
            # and
            self.pyshark_flags.flags_syn_ack
            and self.pyshark_flags.flags_fin
            and not self.pyshark_flags.flags_reset
        )

    @staticmethod
    def _is_S0_flag(self):
        """
        Connection attempt seen but no reply
        """
        return (
            # self.pyshark_flags.flags_syn
            # and
            not self.pyshark_flags.flags_syn_ack
            and not self.pyshark_flags.flags_fin
            and not self.pyshark_flags.flags_reset
        )

    @staticmethod
    def _is_S1_flag(self) -> bool:
        """
        Connection eastablished not terminated

        NOTE Fixing src_bytes to have just payload may be better
        """
        return (
            # self.pyshark_flags.flags_syn_ack  # SYN-ACK flag is set
            # and
            self.pyshark_flags.flags_syn  # SYN flag is set
            and self.src_bytes == 0  # No bytes sent from source
            and self.dst_bytes == 0  # No bytes sent to destination
            and not (  # Ensure no RST or FIN flags are set
                self.pyshark_flags.flags_reset  # RST flag is not set
                or self.pyshark_flags.flags_fin  # FIN flag is not set
            )
        )

    @staticmethod
    def _is_S2_flag(self) -> bool:
        """
        Connection established and closed attempt by originator but no reply from responder
        """
        pass

    @staticmethod
    def _is_S3_flag(self) -> bool:
        """
        Connection established and closed attempt by respomder but no reply from originator
        """
        pass

    @staticmethod
    def _is_REJ_flag(self):
        """
        Connection attempt rejected
        """
        # Check for a SYN packet immediately followed by a RST packet,
        # and ensure no other flags are set
        return (
            # self.pyshark_flags.flags_syn
            # and
            self.pyshark_flags.flags_reset
            and not (
                self.pyshark_flags.flags_ack
                or self.pyshark_flags.flags_syn_ack
                or self.pyshark_flags.flags_fin
            )
        )

    @staticmethod
    def _is_RSTR_flag(self, packet: Packet) -> bool:
        """
        Check if the packet indicates a reset connection from the source.
        """
        return (
            self.pyshark_flags.flags_reset
            and packet.ip.src == self.src_ip
            and (
                int(packet.tcp.srcport) == self.src_port
                or int(packet.tcp.dstport) == self.dst_port
            )
        )

    @staticmethod
    def _is_SH_flag(self, packet: Packet) -> bool:
        """
        Originator sent a SYN followed by FIN, we never saw SYN_ACK from responder
        """
        return (
            # self.pyshark_flags.flags_syn  # SYN flag is set
            # and
            (self.pyshark_flags.flags_fin)  # RST flag is set
            and self.src_ip == packet.ip.src  # Source IP matches
            and not (
                self.pyshark_flags.flags_syn_ack  # SYN-ACK flag is not set
                # or self.pyshark_flags.flags_ack  # ACK flag is not set
            )
        )

    @staticmethod
    # Connection Reset from source
    def _is_RSTO_flag(self, packet: Packet) -> bool:
        """
        Connection reset by originator
        """
        return (
            self.pyshark_flags.flags_reset  # RST flag is set
            and self.src_ip
            == packet.ip.dst  # Source IP matches the destination of the packet
            and self.src_port == int(packet.tcp.dstport)
        )

    @staticmethod
    def _is_RSTOS0_flag(self, packet: Packet) -> bool:
        """
        Originator sent a SYN followed by RST, we never saw SYN_ACK from responder
        """
        return (
            # self.pyshark_flags.flags_syn  # SYN flag is set
            # and
            self.pyshark_flags.flags_reset  # RST flag is set
            and self.src_ip == packet.ip.src  # Source IP matches
            and not (
                self.pyshark_flags.flags_ack  # ACK flag is not set
                or self.pyshark_flags.flags_fin  # FIN flag is not set
                or self.pyshark_flags.flags_syn_ack  # SYN-ACK flag is not set
            )
        )
