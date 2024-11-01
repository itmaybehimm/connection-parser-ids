from pyshark.packet.packet import Packet


class PysharkFlags:
    def __init__(self, packet: Packet) -> None:
        # TCP flags initialized to boolean values based on packet data
        self.flags_ae = packet.tcp.flags_ae == "True"
        self.flags_cwr = packet.tcp.flags_cwr == "True"
        self.flags_ece = packet.tcp.flags_ece == "True"
        self.flags_fin = packet.tcp.flags_fin == "True"
        self.flags_push = packet.tcp.flags_push == "True"
        # Reserved Flag
        self.flags_res = packet.tcp.flags_res == "True"

        # RST Flag
        self.flags_reset = packet.tcp.flags_reset == "True"
        self.flags_urg = packet.tcp.flags_urg == "True"

        # Initialize syn and ack flags
        self.flags_syn_ack = False
        self.flags_syn = False
        self.flags_ack = False

        # Check the TCP flags
        if packet.tcp.flags_syn == "True" and packet.tcp.flags_ack == "True":
            self.flags_syn_ack = True  # Both SYN and ACK are set
        else:
            self.flags_syn = packet.tcp.flags_syn == "True"  # Only SYN
            self.flags_ack = packet.tcp.flags_ack == "True"  # Only ACK

    def update_flags(self, packet: Packet) -> None:
        # Update flags based on new packet data

        # Check for SYN and ACK flags
        if packet.tcp.flags_syn == "True" and packet.tcp.flags_ack == "True":
            self.flags_syn_ack = True  # Both SYN and ACK are present
            self.flags_syn = packet.tcp.flags_syn == "True"
            self.flags_ack = packet.tcp.flags_ack == "True"
        else:
            self.flags_syn = self.flags_syn or (packet.tcp.flags_syn == "True")
            self.flags_ack = self.flags_ack or (packet.tcp.flags_ack == "True")

        # Update other flags
        self.flags_ae = self.flags_ae or (packet.tcp.flags_ae == "True")
        self.flags_cwr = self.flags_cwr or (packet.tcp.flags_cwr == "True")
        self.flags_ece = self.flags_ece or (packet.tcp.flags_ece == "True")
        self.flags_fin = self.flags_fin or (packet.tcp.flags_fin == "True")
        self.flags_push = self.flags_push or (packet.tcp.flags_push == "True")
        self.flags_res = self.flags_res or (packet.tcp.flags_res == "True")
        self.flags_reset = self.flags_reset or (packet.tcp.flags_reset == "True")
        self.flags_urg = self.flags_urg or (packet.tcp.flags_urg == "True")
