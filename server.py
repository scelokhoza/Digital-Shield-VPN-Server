import pyfiglet
from vpn_server import VPNServer



class CLIServer:
    def __init__(self, vpn: VPNServer) -> None:
        self.vpn_font = pyfiglet.figlet_format("Digital-Shield-VPN Server")
        self.vpn = vpn


    def welcome_message(self):
        print(self.vpn_font)


    def show_status(self):
        print("VPN Server Status")
        print(f"Server Address: {self.vpn.server_address}")
        print(f"Port: {self.vpn.port}")
        print(f"Connected Clients: {self.vpn.get_clients()}")
        print(f"Total Traffic In: {self.vpn.get_traffic_in()} bytes")
        print(f"Total Traffic Out: {self.vpn.get_traffic_out()} bytes")
        print(f"Packet Loss: {self.vpn.get_packet_loss()}%")


    def admin_commands(self):
        self.show_status()