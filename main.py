import pyshark
import datetime
import threading
import time
from typing import List, Tuple
from connection_metrics import ConnectionMetric
from const import TIMEOUT_DURATION_UDP, TIMEOUT_DURATION_TCP, CLEANUP_INTERVAL
from custom_types import PORT_SERVICE_MAP, Protocol, InvalidPacketTypeError, Service
from connection import Connection
from host_connection_metrics import HostConnectionMetric
from service_connection_metrics import ServiceConnectionMetric
from utils import Utils, serialize_connection


def push_to_output(
    connection: Connection,
    output_connections: List[Connection],
    output_connections_lock: threading.Lock,
) -> None:
    connection.close_connection()
    with output_connections_lock:
        output_connections.append(connection)
        serialize_connection(connection)


def check_and_cleanup_connection(
    connection: Connection,
    active_connections: dict[Tuple[str, str, int, int], Connection],
    output_connections: List[Connection],
    active_connections_lock: threading.Lock,
    output_connections_lock: threading.Lock,
) -> None:
    if connection.is_closed:
        key = (
            connection.src_ip,
            connection.dst_ip,
            connection.src_port,
            connection.dst_port,
        )
        with active_connections_lock:
            closed_connection = active_connections.pop(key, None)
        if closed_connection:
            print(f"Connection closed {closed_connection.protocol.value}: {key}")
            push_to_output(
                closed_connection, output_connections, output_connections_lock
            )


def cleanup_connections(
    active_connections: dict[Tuple[str, str, int, int], Connection],
    output_connections: List[Connection],
    stop_event: threading.Event,
    active_connections_lock: threading.Lock,
    output_connections_lock: threading.Lock,
) -> None:
    while not stop_event.is_set():
        current_time = datetime.datetime.now()
        to_remove = []

        with active_connections_lock:
            for key, connection in active_connections.items():
                inactive_seconds = (
                    current_time - connection.last_activity
                ).total_seconds()

                if (
                    connection.is_closed
                    or (
                        connection.protocol == Protocol.TCP
                        and inactive_seconds > TIMEOUT_DURATION_TCP
                    )
                    or (
                        connection.protocol == Protocol.UDP
                        and inactive_seconds > TIMEOUT_DURATION_UDP
                    )
                ):
                    connection.is_closed = True
                    to_remove.append(key)

        for key in to_remove:
            with active_connections_lock:
                closed_connection = active_connections.pop(key, None)
            if closed_connection:
                print(
                    f"Connection timed out or closed {closed_connection.protocol.value}: {key}"
                )
                push_to_output(
                    closed_connection, output_connections, output_connections_lock
                )

        time.sleep(CLEANUP_INTERVAL)


def get_connection_metric(
    src_ip: str,
    dst_ip: str,
    connection_metrics: dict[Tuple[str, str], ConnectionMetric],
    connection_metrics_lock: threading.Lock,
) -> ConnectionMetric:
    key = (src_ip, dst_ip)
    with connection_metrics_lock:
        metric = connection_metrics.get(key)
        if metric is None:
            metric = ConnectionMetric(src_ip=src_ip, dst_ip=dst_ip)
            connection_metrics[key] = metric
    return metric


def get_dst_host_connection_metric(
    dst_ip: str,
    dst_host_connection_metrics: dict[str, HostConnectionMetric],
    dst_host_connection_metrics_lock: threading.Lock,
) -> HostConnectionMetric:
    key = dst_ip
    with dst_host_connection_metrics_lock:
        metric = dst_host_connection_metrics.get(key)
        if metric is None:
            metric = HostConnectionMetric(dst_ip=dst_ip)
            dst_host_connection_metrics[key] = metric
    return metric


def get_service_connection_metric(
    service: Service,
    service_connection_metrics: dict[Service, ServiceConnectionMetric],
    service_connection_metrics_lock: threading.Lock,
) -> ServiceConnectionMetric:
    key = service
    with service_connection_metrics_lock:
        metric = service_connection_metrics.get(key)
        if metric is None:
            metric = ServiceConnectionMetric(service=service)
            service_connection_metrics[key] = metric
    return metric


def main():
    capture = pyshark.LiveCapture(interface="Wi-Fi")
    active_connections: dict[Tuple[str, str, int, int], Connection] = {}
    output_connections: List[Connection] = []
    connection_metrics: dict[Tuple[str, str], ConnectionMetric] = {}
    dst_host_connection_metrics: dict[str, HostConnectionMetric] = {}
    service_connection_metrics: dict[Service, ServiceConnectionMetric] = {}

    utils = Utils()

    # Separate locks for each shared resource
    active_connections_lock = threading.Lock()
    output_connections_lock = threading.Lock()
    connection_metrics_lock = threading.Lock()
    dst_host_connection_metrics_lock = threading.Lock()
    service_connection_metrics_lock = threading.Lock()
    stop_event = threading.Event()

    # Start the cleanup thread
    cleanup_thread = threading.Thread(
        target=cleanup_connections,
        args=(
            active_connections,
            output_connections,
            stop_event,
            active_connections_lock,
            output_connections_lock,
        ),
    )
    cleanup_thread.start()

    try:
        for packet in capture.sniff_continuously():
            if "IP" not in packet:
                continue

            try:
                connection = None
                is_internal_src_ip = False
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst

                if hasattr(packet, "tcp"):
                    src_port = int(packet.tcp.srcport)
                    dst_port = int(packet.tcp.dstport)
                elif hasattr(packet, "udp"):
                    src_port = int(packet.udp.srcport)
                    dst_port = int(packet.udp.dstport)
                elif hasattr(packet, "icmp"):
                    src_port = -1
                    dst_port = -1
                else:
                    continue

                if utils.is_internal_ip(src_ip):
                    src_ip, dst_ip = dst_ip, src_ip
                    src_port, dst_port = dst_port, src_port
                    is_internal_src_ip = True

                key = (src_ip, dst_ip, src_port, dst_port)

                with active_connections_lock:
                    if key not in active_connections:
                        if not is_internal_src_ip and (
                            not hasattr(packet, "tcp")
                            or utils.packet_has_syn_flag(packet)
                        ):
                            connection = Connection(
                                packet=packet,
                                connection_metric=get_connection_metric(
                                    src_ip,
                                    dst_ip,
                                    connection_metrics,
                                    connection_metrics_lock,
                                ),
                                dst_host_connection_metric=get_dst_host_connection_metric(
                                    dst_ip,
                                    dst_host_connection_metrics,
                                    dst_host_connection_metrics_lock,
                                ),
                                service_connection_metric=get_service_connection_metric(
                                    PORT_SERVICE_MAP.get(dst_port, Service.UNKNOWN),
                                    service_connection_metrics,
                                    service_connection_metrics_lock,
                                ),
                            )
                            active_connections[key] = connection
                            print(
                                f"Connection opened {connection.protocol.value} :{key}"
                            )
                    else:
                        connection = active_connections[key]
                        connection.update_activity(
                            packet=packet,
                            is_internal_src_ip=is_internal_src_ip,
                        )

                # Check and cleanup after activity update
                if connection:
                    connection.srv_diff_host_rate = (
                        connection.service_connection_metric.get_srv_diff_host_rate(
                            service_connection_metrics=service_connection_metrics
                        )
                    )
                    check_and_cleanup_connection(
                        connection,
                        active_connections,
                        output_connections,
                        active_connections_lock,
                        output_connections_lock,
                    )

            except InvalidPacketTypeError as e:
                print(f"Invalid packet: {e}")

    except KeyboardInterrupt:
        print("Stopping packet capture...")

    finally:
        # Stop the cleanup thread
        stop_event.set()
        cleanup_thread.join()
        print("Cleanup thread stopped.")


if __name__ == "__main__":
    main()
