import datetime
from typing import Optional, Tuple, List  # noqa: F401
from pyshark.packet.packet import Packet
from connection_metrics import ConnectionMetric
from pyshark_flags import PysharkFlags
from custom_types import (
    PORT_SERVICE_MAP,
    ConnectionFlag,
    InvalidPacketTypeError,
    Protocol,
    Service,
)
from utils import Utils


class Connection:
    def __init__(self, packet: Packet, connection_metric: ConnectionMetric) -> None:

        # Compositon pattern for utils
        self.utils = Utils()

        # Compostion pattern for connection metrics
        self.connection_metric = connection_metric

        # Intiitalize ip, protocols  and ports
        self._initialize_ip_port_protocol_service(packet=packet)

        self.start_time: datetime.datetime = datetime.datetime.now()
        self.last_activity: datetime.datetime = self.start_time
        self.is_closed: bool = False

        # Initialize bytes counters
        self.src_bytes: int = int(packet.length)  # Initialize with the packet length
        self.dst_bytes: int = 0  # No bytes sent to the destination initially

        # Initalize Flags
        self._initialize_flags(packet=packet)

        # Connection metrics evaluated when the connection is closed
        self._initialize_closing_metrics()

        self.update_activity(packet=packet, is_internal_src_ip=False)
        self.check_close(packet=packet)

    """
        Updating connection attributes on each packet
    """

    def update_activity(
        self,
        packet: Packet,
        is_internal_src_ip: bool,
    ) -> None:

        current_time = datetime.datetime.now()

        # Move to a update tcp wala method
        if self.protocol == Protocol.TCP:
            self.wrong_fragments += int(self.utils.is_wrong_fragment(packet))

        self.connection_metric.update(
            packet=packet, service=self.service, current_time=current_time
        )

        self._update_pyshark_flags(packet=packet)

        self.last_activity = current_time

        self._update_data_bytes(packet=packet, is_internal_src_ip=is_internal_src_ip)

        self.check_close(packet)

    def _update_pyshark_flags(self, packet: Packet) -> None:
        if self.protocol != Protocol.TCP:
            return

        self.pyshark_flags.update_flags(packet)
        self.urgent_packets += int(self.utils.packet_has_urg_flag(packet=packet))

        if self.pyshark_flags.flags_reset:
            self.is_closed = True
            self._check_rst_flags(packet)

        if self.pyshark_flags.flags_fin:
            self.is_closed = True

    def _update_data_bytes(self, packet: Packet, is_internal_src_ip: bool) -> None:
        if not is_internal_src_ip:
            self.src_bytes += int(packet.length)
        else:
            self.dst_bytes += int(packet.length)

    """
        Conenction Parameter Initalizing methods
    """

    def _initialize_ip_port_protocol_service(self, packet: Packet) -> None:
        self.src_ip = packet.ip.src
        self.dst_ip = packet.ip.dst

        if hasattr(packet, "tcp"):
            self.src_port = int(packet.tcp.srcport)
            self.dst_port = int(packet.tcp.dstport)
            self.protocol: str = Protocol.TCP
        elif hasattr(packet, "udp"):
            self.src_port = int(packet.udp.srcport)
            self.dst_port = int(packet.udp.dstport)
            self.protocol: str = Protocol.UDP
        elif hasattr(packet, "icmp"):
            self.src_port = -1
            self.dst_port = -1
            self.protocol: str = Protocol.ICMP
        else:
            raise InvalidPacketTypeError("Invalid packet type")

        self.service: Service = PORT_SERVICE_MAP.get(self.dst_port, Service.UNKNOWN)

    def _initialize_flags(self, packet: Packet):
        # Initialize connection flag
        self.connection_flag: ConnectionFlag = ConnectionFlag.OTH

        if self.protocol == Protocol.TCP:
            # Initialize flags using PysharkFlags object
            self.pyshark_flags = PysharkFlags(packet)

            # Initalize urgent counter
            self.urgent_packets: int = int(
                self.utils.packet_has_urg_flag(packet=packet)
            )

    def _initialize_closing_metrics(self):
        # Initalize wrong fragment counter; in dataset udp and icmp also have 0 values
        self.wrong_fragments = 0

        # Check land attack
        self.is_land: bool = (self.src_ip == self.dst_ip) and (
            self.src_port == self.dst_port
        )

        # number of connections is past 2 seconds
        self.count = None

        # number of connections to same service is past 2 seconds
        self.srv_count = None

        # Rate of SYN errors.
        self.serror_rate = None

        self.srv_serror_rate = None

        self.duration: float = 0.0

    """
        Connection Close handling methods
    """

    def check_close(self, packet: Packet) -> bool:
        if self.protocol == Protocol.TCP:
            if self.utils.packet_has_fin_flag(packet) or self.utils.packet_has_rst_flag(
                packet
            ):
                self.is_closed = True
                return True
        elif self.protocol == Protocol.ICMP:
            self.is_closed = True
            return True
        return False

    def close_connection(self):
        current_time = datetime.datetime.now()

        # calculate duration
        self.duration = (self.last_activity - self.start_time).total_seconds()

        # TODO consider sending last activity think about it

        # get the count of connections
        self.count = self.connection_metric.count.get_count(current_time=current_time)

        # get the count of same service connections
        self.srv_count = self.connection_metric.srv_count[self.service].get_count(
            current_time=current_time
        )

        # check for SYN error the connection must be tcp to check if syn error occured howver for udp there may be connection metrics giving syn error rate
        if self._is_syn_error():
            # TODO consider sending last activity think about it
            self.connection_metric.increment_syn_error(
                current_time=current_time, service=self.service
            )

        self.serror_rate = self.connection_metric.get_serror_rate()
        self.srv_serror_rate = self.connection_metric.get_srv_serror_rate(self.service)

        # Check for REJ error (based on RST flag in TCP)
        if self._is_rerror():
            # Increment REJ error in connection metrics
            self.connection_metric.increment_rerror(
                current_time=current_time, service=self.service
            )

        # Calculate error rates
        self.rerror_rate = self.connection_metric.get_rerror_rate()
        self.srv_rerror_rate = self.connection_metric.get_srv_rerror_rate(self.service)

        # assign connection flag
        self.assign_flag()

    """
        Below are methods for checking TCP flags at end of connections

        NOTE since its an IDS we consider incoming request but for testing in home network almost always orginator is from inside so first SYN 
        packet is always discarded and hence SYN flags are commented out for now
    """

    # will be called when connection is fully closed either due to timeout or reset
    def assign_flag(self) -> ConnectionFlag:
        if self.protocol != Protocol.TCP:
            # Already initalized at other
            return self.connection_flag

        if self.connection_flag != ConnectionFlag.OTH:
            return self.connection_flag
        if self._is_SF_flag():
            self.connection_flag = ConnectionFlag.SF
        elif self._is_S0_flag():
            self.connection_flag = ConnectionFlag.S0
        elif self._is_S1_flag():
            self.connection_flag = ConnectionFlag.S1
        elif self._is_S2_flag():
            self.connection_flag = ConnectionFlag.S2
        elif self._is_S3_flag():
            self.connection_flag = ConnectionFlag.S3
        elif self._is_REJ_flag():
            self.connection_flag = ConnectionFlag.REJ
        else:
            self.connection_flag = ConnectionFlag.OTH

        return self.connection_flag

    def _check_rst_flags(self, packet):
        if self._is_RSTR_flag(packet):
            self.connection_flag = ConnectionFlag.RSTR
        elif self._is_SH_flag(packet):
            self.connection_flag = ConnectionFlag.SH
        elif self._is_RSTO_flag(packet):
            self.connection_flag = ConnectionFlag.RSTO
        elif self._is_RSTOS0_flag(packet):
            self.connection_flag = ConnectionFlag.RSTOS0

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

    def _is_S2_flag(self) -> bool:
        """
        Connection established and closed attempt by originator but no reply from responder
        """
        pass

    def _is_S3_flag(self) -> bool:
        """
        Connection established and closed attempt by respomder but no reply from originator
        """
        pass

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

    """
        Below are methods for checking TCP errors at end of connections

        NOTE since its an IDS we consider incoming request but for testing in home network almost always orginator is from inside so first SYN 
        packet is always discarded and hence SYN flags are commented out for now
    """

    def _is_syn_error(self) -> bool:
        """
        Checks if the given packet represents a SYN error (SYN flag set, ACK flag not set).
        """
        if self.protocol != Protocol.TCP:
            return False

        # Check if SYN flag is set and ACK flag is not set
        return self.pyshark_flags.flags_syn and not self.pyshark_flags.flags_ack

    def _is_rerror(self) -> bool:
        """
        Check if the packet represents a REJ error (TCP RST flag).
        """
        return self.pyshark_flags.flags_reset  # RST flag is set
