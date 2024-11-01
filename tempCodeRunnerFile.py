import pyshark
import time
import threading

# Define a connection dictionary to keep track of active connections
connections = {}

# Define a timeout duration (in seconds)
TIMEOUT_DURATION = 30

capture = pyshark.LiveCapture(interface="Wi-Fi")


# Can't do this right now because current time is too forward
# Function to check for timed-out connections
def check_for_timeouts():
    while True:
        current_time = time.time()
        for conn_id, details in list(connections.items()):
            # Check for timeout
            if current_time - details["last_activity"] > TIMEOUT_DURATION:
                print(f"Connection timed out: {conn_id}")
                del connections[conn_id]
        time.sleep(5)  # Check every 5 seconds


def manage_connections(packet):
    if "IP" in packet and "TCP" in packet:
        src_ip = packet.ip.src
        dst_ip = packet.ip.dst
        src_port = packet.tcp.srcport
        dst_port = packet.tcp.dstport
        timestamp = float(packet.sniff_time.timestamp())  # Current timestamp

        conn_id = (src_ip, dst_ip, src_port, dst_port)

        is_fin = packet.tcp.flags_fin == "True"
        is_rst = packet.tcp.flags_reset == "True"
        # is_ack = packet.tcp.flags_ack

        # Check if the packet is a FIN or RST packet
        # packet.pretty_print()
        # print(packet.tcp.flags)

        if is_fin or is_rst:
            # Connection closure - remove from active connections
            if conn_id in connections:
                print(f"Connection closed: {conn_id}")
                del connections[conn_id]
        else:
            # Manage active connections
            if conn_id not in connections:
                # New connection
                connections[conn_id] = {
                    "start_time": timestamp,
                    "last_activity": timestamp,
                }
                print(f"New connection: {conn_id}")

            # Update last activity time for the connection
            connections[conn_id]["last_activity"] = timestamp


# Start managing connections in a separate thread
timeout_thread = threading.Thread(target=check_for_timeouts)
timeout_thread.start()

# Start the live capture and manage connections
for packet in capture.sniff_continuously():
    manage_connections(packet)
