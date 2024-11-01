import pyshark
import datetime
import threading
import time
from typing import List, Tuple
from connection_metrics import ConnectionMetric
from const import TIMEOUT_DURATION_UDP, TIMEOUT_DURATION_TCP, CLEANUP_INTERVAL
from custom_types import Protocol, InvalidPacketTypeError
from connection import Connection
from utils import Utils


# TODO conenctions withour SYN are orignated from within the netwrok so discard them for now ask sir once but
def push_to_output(
    connection: Connection,
    output_connections: List[Connection],
) -> None:
    # Roughly handling first internal request outside, i.e with no SYN flag
    # if connection.protocol == Protocol.TCP and not connection.pyshark_flags.flags_syn:
    #     return
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


def main():
    capture = pyshark.LiveCapture(interface="Wi-Fi")
    active_connections: dict[Tuple[str, str, int, int], Connection] = {}
    output_connections: List[Connection] = []
    connection_metrics: dict[Tuple[str, str], ConnectionMetric] = {}
    utils: Utils = Utils()

    # Create a stop event for the cleanup thread
    stop_event = threading.Event()

    # Start the cleanup thread
    cleanup_thread = threading.Thread(
        target=cleanup_connections,
        args=(active_connections, output_connections, stop_event),
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

                key = (src_ip, dst_ip, src_port, dst_port)

                # Check if the connection is already active
                if key not in active_connections:
                    if (
                        not is_internal_src_ip
                    ):  # Only start a new connection if the source is external
                        connection = Connection(
                            packet=packet, connection_metric=connection_metric
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
