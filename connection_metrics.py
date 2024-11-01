import datetime
from count import Count
from pyshark.packet.packet import Packet

from custom_types import Service


class ConnectionMetric:
    def __init__(self, src_ip: str, dst_ip: str):
        self.src_ip = src_ip
        self.dst_ip = dst_ip

        self.count = Count()

        # Hold time stamps accroding to service type
        self.srv_count: dict[Service, Count] = {}

    def update(self, packet: Packet, service: Service) -> None:
        self.update_timestamps(service)

    def update_timestamps(self, service: Service) -> None:
        current_time = datetime.datetime.now()
        self.count.update_timestamps(current_time=current_time)

        # NOTE during testing since random ports of our pc are dst_ports service is usally other and same_srv count is same
        if service in self.srv_count:
            self.srv_count[service].update_timestamps(current_time=current_time)
        else:
            self.srv_count[service] = Count()
            self.srv_count[service].update_timestamps(current_time=current_time)
