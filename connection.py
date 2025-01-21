import datetime
from typing import Optional, Tuple, List  # noqa: F401
from pyshark.packet.packet import Packet
from connection_metrics import ConnectionMetric
from flag_utils import (
    assign_connection_flag_inplace,
    assign_connection_rst_flag_inplace,
)
from host_connection_metrics import HostConnectionMetric
from pyshark_flags import PysharkFlags
from custom_types import (
    PORT_SERVICE_MAP,
    ConnectionFlag,
    InvalidPacketTypeError,
    Protocol,
    Service,
)
from service_connection_metrics import ServiceConnectionMetric
from utils import Utils


class Connection:
    def __init__(
        self,
        packet: Packet,
        connection_metric: ConnectionMetric,
        dst_host_connection_metric: HostConnectionMetric,
        service_connection_metric: ServiceConnectionMetric,
    ) -> None:

        # Compositon pattern for utils
        self.utils = Utils()

        # Compostion pattern for connection metrics
        self.connection_metric = connection_metric
        self.dst_host_connection_metric = dst_host_connection_metric
        self.service_connection_metric = service_connection_metric

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

        self.dst_host_connection_metric.update(
            packet=packet,
            service=self.service,
            current_time=current_time,
            src_port=self.src_port,
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
            assign_connection_rst_flag_inplace(self, packet)

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
            self.protocol: Protocol = Protocol.TCP
        elif hasattr(packet, "udp"):
            self.src_port = int(packet.udp.srcport)
            self.dst_port = int(packet.udp.dstport)
            self.protocol: Protocol = Protocol.UDP
        elif hasattr(packet, "icmp"):
            self.src_port = -1
            self.dst_port = -1
            self.protocol: Protocol = Protocol.ICMP
        else:
            raise InvalidPacketTypeError("Invalid packet type")

        self.service: Service = PORT_SERVICE_MAP.get(self.dst_port, Service.UNKNOWN)

    def _initialize_flags(self, packet: Packet):
        # Initialize connection flag
        self.connection_flag: ConnectionFlag = ConnectionFlag.OTH
        self.urgent_packets = 0

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

        self.duration: float = 0.0

        # Check land attack
        self.is_land: bool = (self.src_ip == self.dst_ip) and (
            self.src_port == self.dst_port
        )

        # number of connections is past 2 seconds
        self.count = None
        # number of connections is past 2 seconds
        self.dst_host_count = None

        # number of connections to same service is past 2 seconds
        self.srv_count = None
        # number of connections to same service is past 2 seconds
        self.dst_host_srv_count = None

        # Rate of SYN errors.
        self.serror_rate = None
        self.srv_serror_rate = None

        self.dst_host_serror_rate = None
        self.dst_host_srv_serror_rate = None

        # Rate of REJ errors.
        self.rerror_rate = None
        self.srv_rerror_rate = None

        self.dst_host_rerror_rate = None
        self.dst_host_srv_rerror_rate = None

        # Rate of connections to the same service and different service
        self.same_srv_rate = None
        self.diff_srv_rate = None

        # Rate of connections to the same service and different service of same dst host
        self.dst_host_same_srv_rate = None
        self.dst_host_diff_srv_rate = None
        self.dst_host_same_src_port_rate = None

        # Connections to different hosts for the same service.
        self.srv_diff_host_rate = None

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
        self.count = self.connection_metric.count.get_count()

        # get the count of connections to same dst host
        self.dst_host_count = self.dst_host_connection_metric.count.get_count()

        # get the count of same service connections
        self.srv_count = self.connection_metric.srv_count[self.service].get_count(
            current_time=current_time
        )

        # get the count of same service connections to same dst host
        self.dst_host_srv_count = self.dst_host_connection_metric.srv_count[
            self.service
        ].get_count(current_time=current_time)

        # check for SYN error the connection must be tcp to check if syn error occured howver for udp there may be connection metrics giving syn error rate
        if self._is_syn_error():
            # TODO consider sending last activity think about it
            self.connection_metric.increment_syn_error(
                current_time=current_time, service=self.service
            )

            self.dst_host_connection_metric.increment_syn_error(
                current_time=current_time, service=self.service
            )

        self.serror_rate = self.connection_metric.get_serror_rate()
        self.srv_serror_rate = self.connection_metric.get_srv_serror_rate(self.service)

        self.dst_host_serror_rate = self.dst_host_connection_metric.get_serror_rate()
        self.dst_host_srv_serror_rate = (
            self.dst_host_connection_metric.get_srv_serror_rate(self.service)
        )

        # Check for REJ error (based on RST flag in TCP)
        if self._is_rerror():
            # Increment REJ error in connection metrics
            self.connection_metric.increment_rerror(
                current_time=current_time, service=self.service
            )
            self.dst_host_connection_metric.increment_rerror(
                current_time=current_time, service=self.service
            )

        # Calculate error rates
        self.rerror_rate = self.connection_metric.get_rerror_rate()
        self.srv_rerror_rate = self.connection_metric.get_srv_rerror_rate(self.service)

        self.dst_host_rerror_rate = self.dst_host_connection_metric.get_rerror_rate()
        self.dst_host_srv_rerror_rate = (
            self.dst_host_connection_metric.get_srv_rerror_rate(self.service)
        )

        self.same_srv_rate = self.connection_metric.get_same_srv_rate(self.service)
        self.diff_srv_rate = self.connection_metric.get_diff_srv_rate(self.service)

        self.dst_host_same_srv_rate = self.dst_host_connection_metric.get_same_srv_rate(
            self.service
        )
        self.dst_host_diff_srv_rate = self.dst_host_connection_metric.get_diff_srv_rate(
            self.service
        )
        self.dst_host_same_src_port_rate = (
            self.dst_host_connection_metric.get_same_src_port_rate(self.src_port)
        )

        # assign connection flag
        assign_connection_flag_inplace(self)

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
        if self.protocol != Protocol.TCP:
            return False

        return self.pyshark_flags.flags_reset  # RST flag is set
