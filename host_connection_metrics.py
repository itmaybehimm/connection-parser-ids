import datetime
from count import Count
from custom_types import Service

from pyshark.packet.packet import Packet


class HostConnectionMetric:
    def __init__(self, dst_ip: str):
        self.dst_ip = dst_ip

        self.count = Count()

        # Hold time stamps accroding to service type
        self.srv_count: dict[Service, Count] = {}

        # Hold time stamps accroding to port
        self.src_port_count: dict[int, Count] = {}

        # SYN error count
        self.serror_count = Count()

        # Same service SYN error rate
        self.srv_serror_count: dict[Service, Count] = {}

        self.rerror_count = Count()

        # Same service SYN error rate
        self.srv_rerror_count: dict[Service, Count] = {}

    def update(
        self,
        packet: Packet,
        service: Service,
        current_time: datetime,
        src_port: int,
    ) -> None:
        self.update_timestamps(
            service=service, current_time=current_time, src_port=src_port
        )

    def update_timestamps(
        self,
        service: Service,
        current_time: datetime,
        src_port: int,
    ) -> None:
        self.count.update_timestamps(current_time=current_time)

        # NOTE during testing since random ports of our pc are dst_ports service is usally other and same_srv count is same
        if service in self.srv_count:
            self.srv_count[service].update_timestamps(current_time=current_time)
        else:
            self.srv_count[service] = Count()
            self.srv_count[service].update_timestamps(current_time=current_time)

        if src_port not in self.src_port_count:
            self.src_port_count[src_port] = Count()
        self.src_port_count[src_port].update_timestamps(current_time=current_time)

    def get_same_srv_rate(self, service: Service) -> float:
        """
        Calculate the same service rate based on the count of connections to each service.
        """
        total_connections = self.count.get_count()
        same_service_connections = self.srv_count.get(service, Count()).get_count()

        if total_connections == 0:
            return 0.0

        return same_service_connections / total_connections

    def get_diff_srv_rate(self, service: Service) -> float:
        """
        Calculate the different service rate based on the count of connections to different services.
        """
        total_connections = self.count.get_count()
        same_service_connections = self.srv_count.get(service, Count()).get_count()

        if total_connections == 0:
            return 0.0

        return (total_connections - same_service_connections) / total_connections

    def get_same_src_port_rate(self, src_port: int) -> float:
        """
        Calculate the same source port rate based on the count of connections from the source port.
        """
        total_connections = self.count.get_count()
        same_src_port_connections = self.src_port_count.get(
            src_port, Count()
        ).get_count()

        return (
            same_src_port_connections / total_connections if total_connections else 0.0
        )

    def increment_syn_error(self, service: Service, current_time: datetime) -> None:
        """
        Update SYN error count for a specific service.
        """
        self.serror_count.update_timestamps(current_time=current_time)

        # Update service-specific SYN error count
        if service in self.srv_serror_count:
            self.srv_serror_count[service].update_timestamps(current_time=current_time)
        else:
            self.srv_serror_count[service] = Count()
            self.srv_serror_count[service].update_timestamps(current_time=current_time)

    def get_serror_rate(self) -> float:
        """
        Calculate the overall SYN error rate for the connection.
        """
        total_connections = self.count.get_count()
        if total_connections == 0:
            return 0.0
        return self.serror_count.get_count() / total_connections

    def get_srv_serror_rate(self, service: Service) -> float:
        """
        Calculate the SYN error rate specific to a given service.
        """
        total_service_connections = self.srv_count.get(service, Count()).get_count()
        if total_service_connections == 0:
            return 0.0
        return (
            self.srv_serror_count.get(service, Count()).get_count()
            / total_service_connections
        )

    def increment_rerror(self, service: Service, current_time: datetime) -> None:
        """
        Update REJ error count for a specific service and overall.
        """
        self.rerror_count.update_timestamps(current_time=current_time)

        # Update service-specific REJ error count
        if service in self.srv_rerror_count:
            self.srv_rerror_count[service].update_timestamps(current_time=current_time)
        else:
            self.srv_rerror_count[service] = Count()
            self.srv_rerror_count[service].update_timestamps(current_time=current_time)

    def get_rerror_rate(self) -> float:
        """
        Calculate the overall REJ error rate for the connection.
        """
        total_connections = self.count.get_count()
        if total_connections == 0:
            return 0.0
        return self.rerror_count.get_count() / total_connections

    def get_srv_rerror_rate(self, service: Service) -> float:
        """
        Calculate the REJ error rate specific to a given service.
        """
        total_service_connections = self.srv_count.get(service, Count()).get_count()
        if total_service_connections == 0:
            return 0.0
        return (
            self.srv_rerror_count.get(service, Count()).get_count()
            / total_service_connections
        )
