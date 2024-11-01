import threading
import time
from scapy.all import *
import pyshark


# Function to create and send fragmented packets
def send_fragmented_packet():
    # Create the original IP packet with a larger payload to ensure fragmentation
    original_packet = (
        IP(dst="192.168.1.254")
        / TCP()
        / Raw(load="This is a fragmented packet" * 500)  # Increased payload size
    )

    # Fragment the packet
    fragments = fragment(original_packet)

    # Send the fragmented packets
    sendp(
        fragments, iface="en0", verbose=True  # Change "en0" to your network interface
    )


# Function to capture packets using Pyshark
def capture_packets():
    print("Capturing packets...")
    # Start a live capture on the specified interface
    capture = pyshark.LiveCapture(
        interface="Wi-Fi",
        display_filter="icmp",  # Change "Wi-Fi" to your network interface
    )

    for packet in capture.sniff_continuously(packet_count=10):
        print(packet)


if __name__ == "__main__":
    # Start capturing packets in a separate thread
    capture_thread = threading.Thread(target=capture_packets)
    capture_thread.start()

    # Allow some time for the sniffer to start
    time.sleep(2)

    # Send fragmented packet
    send_fragmented_packet()

    # Wait for capture thread to finish
    capture_thread.join()
