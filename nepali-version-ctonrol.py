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
from utils import Utils

# TODO implement threading.lock as python dict is not thread safe


# TODO conenctions withour SYN are orignated from within the netwrok so discard them for now ask sir once but
def push_to_output(
    connection: Connection,
    output_connections: List[Connection],
) -> None:

    connection.close_connection()
    output_connections.append(connection)


def check_and_cleanup_connection(
    connection: Connection,
    active_connections: dict[Tuple[str, str, int, int], Connection],
    output_connections: List[Connection],
) -> None:
    """
    Check if a connection is closed and perform cleanup if it is.
    """
    if connection.is_closed:
        key = (
            connection.src_ip,
            connection.dst_ip,
            connection.src_port,
            connection.dst_port,
        )
        closed_connection = active_connections.pop(key, None)
        if closed_connection is not None:
            print(f"Connection closed: {key}")
            push_to_output(closed_connection, output_connections)


def cleanup_connections(
    active_connections: dict[Tuple[str, str, int, int], Connection],
    output_connections: dict[Tuple[str, str, int, int], Connection],
    stop_event: threading.Event,
    lock: threading.Lock,
) -> None:
    """
    Continuously cleanup idle connections in a separate thread.
    """

    while not stop_event.is_set():
        current_time = datetime.datetime.now()
        for key, connection in list(active_connections.items()):
            closed_connection = None

            if connection.is_closed:
                closed_connection = active_connections.pop(key)

            inactive_seconds = (current_time - connection.last_activity).total_seconds()

            # ICMP Packet are closed
            if (
                connection.protocol == Protocol.TCP
                and inactive_seconds > TIMEOUT_DURATION_TCP
            ):

                print(f"TCP Connection timed out: {key}")
                closed_connection = active_connections.pop(key)
                # Make method
                closed_connection.is_closed = True

            # UDP closing happens if its idle for some amount of
            elif (
                connection.protocol == Protocol.UDP
                and inactive_seconds > TIMEOUT_DURATION_UDP
            ):

                print(f"UDP Connection closed: {key}")
                closed_connection = active_connections.pop(key)

                # Make method
                closed_connection.is_closed = True

            if closed_connection is not None:
                push_to_output(closed_connection, output_connections)

        # Wait before next cleanup cycle
        time.sleep(CLEANUP_INTERVAL)


def get_connection_metric(
    src_ip: str,
    dst_ip: str,
    connection_metrics: dict[Tuple[str, str], ConnectionMetric],
) -> ConnectionMetric:
    key = (src_ip, dst_ip)
    metric = connection_metrics.get(key)
    if metric is None:
        metric = ConnectionMetric(src_ip=src_ip, dst_ip=dst_ip)
        connection_metrics[key] = metric
    return metric


def get_dst_host_connection_metric(
    dst_ip: str,
    dst_host_connection_metrics: dict[str, HostConnectionMetric],
) -> HostConnectionMetric:
    key = dst_ip
    metric = dst_host_connection_metrics.get(key)
    if metric is None:
        metric = HostConnectionMetric(dst_ip=dst_ip)
        dst_host_connection_metrics[key] = metric
    return metric


def get_service_connection_metric(
    service: Service,
    service_connection_metrics: dict[Service, ServiceConnectionMetric],
) -> ServiceConnectionMetric:
    key = service
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

    utils: Utils = Utils()
    lock = threading.Lock()

    # Create a stop event for the cleanup thread
    stop_event = threading.Event()

    # Start the cleanup thread
    cleanup_thread = threading.Thread(
        target=cleanup_connections,
        args=(active_connections, output_connections, stop_event, lock),
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

                connection_metric = get_connection_metric(
                    src_ip, dst_ip, connection_metrics
                )

                dst_host_connection_metric = get_dst_host_connection_metric(
                    dst_ip, dst_host_connection_metrics
                )

                service = PORT_SERVICE_MAP.get(dst_port, Service.UNKNOWN)

                service_connection_metric = get_service_connection_metric(
                    service=service,
                    service_connection_metrics=service_connection_metrics,
                )

                key = (src_ip, dst_ip, src_port, dst_port)

                # Check if the connection is already active
                with lock:
                    if key not in active_connections:
                        if (
                            not is_internal_src_ip
                        ):  # Only start a new connection if the source is external
                            connection = Connection(
                                packet=packet,
                                connection_metric=connection_metric,
                                dst_host_connection_metric=dst_host_connection_metric,
                                service_connection_metric=service_connection_metric,
                            )
                            active_connections[key] = connection
                            print(f"Connection opened {key}")
                    else:
                        # Update the existing connection if it’s already active
                        connection = active_connections[key]
                        connection.update_activity(
                            packet=packet,
                            is_internal_src_ip=is_internal_src_ip,
                        )

                # Check and cleanup if the connection is closed after update_activity
                if connection:
                    # TODO make it inside somehow but for now leave it
                    # TODO Also closing ma only calculate
                    connection.srv_diff_host_rate = (
                        connection.service_connection_metric.get_srv_diff_host_rate(
                            service_connection_metrics=service_connection_metrics
                        )
                    )
                    check_and_cleanup_connection(
                        connection, active_connections, output_connections
                    )

            except InvalidPacketTypeError as e:
                print(f"Invalid packet: {e}")

    except KeyboardInterrupt:
        print("Stopping packet capture...")

    finally:
        # Signal the cleanup thread to stop and wait for it to finish
        stop_event.set()
        cleanup_thread.join()
        print("Cleanup thread stopped.")


if __name__ == "__main__":
    main()
