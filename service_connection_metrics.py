from __future__ import annotations
from datetime import datetime
from count import Count
from custom_types import Service


class ServiceConnectionMetric:
    def __init__(self, service: Service):
        self.service = service
        self.count = Count()

    def update(
        self,
        current_time: datetime,
    ) -> None:
        self.count.update_timestamps(current_time=current_time)

    def get_srv_diff_host_rate(
        self, service_connection_metrics: dict[Service, "ServiceConnectionMetric"]
    ):
        current_service_host_count = self.count.get_count()

        total_other_services_host_count = sum(
            service_connection_metrics[service].count.get_count()
            for service in service_connection_metrics
            if service != self.service
        )

        if (current_service_host_count + total_other_services_host_count) == 0:
            return 0

        rate = current_service_host_count / (
            current_service_host_count + total_other_services_host_count
        )

        return rate
