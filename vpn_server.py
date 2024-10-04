import ssl
import toml
import socket
import psutil
import logging
import pyfiglet
import ipaddress
import geocoder
import threading
from dataclasses import dataclass
from urllib.parse import urlparse
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet



# Setup logging
logging.basicConfig(level=logging.INFO)



@dataclass
class VPNData:
    server_address: str
    certfile: str
    keyfile: str
    port: int


class Configuration:
    def __init__(self, target_file: str) -> None:
        """
        Initialize a Configuration object with the path to a configuration file.

        :param target_file: Path to the configuration file
        :type target_file: str
        """
        self.file = target_file

    def read_config_file(self, file) -> dict:
        """
        Reads a configuration file from disk and returns its contents as a Python dictionary.

        :param file: The path to the configuration file to read.
        :type file: str
        :return: A dictionary containing the configuration data.
        :rtype: dict
        """
        try:
            with open(file, 'r') as config_file:
                config_data: dict = toml.load(config_file)
            return config_data
        except FileNotFoundError as e:
            logging.error(f"Config file not found: {e}")

    def load_config(self) -> VPNData:
        """
        Load the configuration data from the specified file and return it as a VPNData object.

        :return: VPNData object containing the server address, certificate file, key file, and port.
        :rtype: VPNData
        """
        config_data: dict = self.read_config_file(self.file)
        try:
            return VPNData(
                server_address=config_data['server']['server_address'],
                certfile=config_data['server']['certfile'],
                keyfile=config_data['server']['keyfile'],
                port=int(config_data['server']['port'])
            )
        except KeyError as e:
            logging.error(f"Missing key in config file: {e}")


class VPNServer:
    def __init__(self, config_file: str) -> None:
        """
        Initialize a VPNServer with the given configuration file.

        :param config_file: The path to the configuration file
        :type config_file: str
        """
        self.server_config: Configuration = Configuration(config_file)
        self.configuration: VPNData = self.server_config.load_config()
        self.server_address: str = self.configuration.server_address
        self.port: int = self.configuration.port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.certfile: str = self.configuration.certfile
        self.keyfile: str = self.configuration.keyfile
        self.clients: dict = {}
        self.packet_loss: int = 0
        self.client_traffic: dict = {}
        self.client_traffic_out: dict  = {}
        self.client_packet_count: dict = {}

        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()
        self.public_pem: bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Create SSL context
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(certfile=self.certfile, keyfile=self.keyfile)


    def get_traffic_in(self) -> int:
        """
        Returns the total traffic in for all clients.

        :return: The total traffic in for all clients
        :rtype: int
        """
        return sum(self.client_traffic.values())


    def get_traffic_out(self) -> int:
        """
        Returns the total traffic out for all clients.

        :return: The total traffic out for all clients
        :rtype: int
        """
        return sum(self.client_traffic_out.values())

    def get_clients(self) -> int:
        """
        Returns the number of connected clients.

        :return: The number of connected clients
        :rtype: int
        """
        return len(self.clients)


    def get_packet_loss(self) -> int:
        """
        Returns the packet loss percentage for the VPN server.

        :return: The packet loss percentage
        :rtype: int
        """
        return self.packet_loss

    def calculate_packet_loss(self, client_address: tuple) -> int:
        """
        Calculate the packet loss percentage for a given client address.

        :param client_address: The IP address and port of the client
        :type client_address: tuple
        :return: The packet loss percentage for the client. Returns -1 if no packet data is available,
                and 0 if no packets were sent to the client.
        :rtype: int
        """
        client_stats = self.client_packet_count.get(client_address)
        if not client_stats:
            logging.error(f"No packet data for client {client_address}")
            return -1

        sent = client_stats['sent']
        received = client_stats['received']
        if sent==0:
            logging.warning(f"No packet data for client {client_address}")
            return 0

        packet_loss = ((sent - received) / sent) * 100
        logging.info(f"Packet loss for client {client_address}: {packet_loss}%")
        return packet_loss

    def start_vpn(self) -> None:
        """
        Start the VPN server and listen for incoming connections.

        This function binds the server socket to the specified server address and port,
        and starts listening for incoming connections. It enters an infinite loop to
        accept incoming connections and start handling them in separate threads.

        The function wraps each incoming client socket with the SSL context and
        starts a new thread to handle the client connection. The function keeps track
        of the number of connected clients and their traffic statistics.

        If an exception occurs during the operation, it is logged and the server socket
        is closed.

        This function does not take any parameters and does not return anything.
        """
        try:
            self.server_socket.bind((self.server_address, self.port))
            self.server_socket.listen(5)
            logging.info(f"Server started on {self.server_address}:{self.port}")

            # threading.Thread(target=self.admin_commands).start()

            while True:
                client_socket, client_address = self.server_socket.accept()
                self.clients[client_address] = client_socket
                self.client_traffic[client_address[0]] = 0
                self.client_traffic_out[client_address[0]] = 0
                self.client_packet_count[client_address[0]] = {'sent': 0, 'recv': 0}
                logging.info(f"Connection from {client_address}")

                # Wrap the socket with SSL context
                ssl_client_socket = self.context.wrap_socket(client_socket, server_side=True)
                client_thread = threading.Thread(target=self.handle_client, args=(ssl_client_socket, client_address))
                client_thread.start()

        except PermissionError as e:
            logging.error(f"Permission denied: {e}")
        except Exception as e:
            logging.error(f"An error occurred: {e}")
        finally:
            self.server_socket.close()


    def handle_client(self, ssl_client_socket, client_address: tuple) -> None:
        """
        Handle the client connection and traffic.

        This function accepts an SSL-wrapped client socket and its address as parameters.
        It establishes a secure connection with the client by sending the server's public
        key and receiving the client's symmetric key. It then enters a loop to receive
        encrypted data from the client, decrypt it, forward it to the destination server,
        receive the response, encrypt it, and send it back to the client.

        The function keeps track of the traffic statistics for each client and calculates
        the packet loss. It also handles exceptions that may occur during the operation.

        Parameters:
        - ssl_client_socket (ssl.SSLSocket): The SSL-wrapped client socket.
        - client_address (tuple): The client's address.

        Returns:
        None
        """
        try:
            ssl_client_socket.settimeout(100)

            # Send the server's public key to the client
            ssl_client_socket.sendall(self.public_pem)
            self.client_packet_count[client_address[0]]['sent'] +=1

            # Receive the encrypted symmetric key from the client
            encrypted_symmetric_key = ssl_client_socket.recv(4096)
            self.client_packet_count[client_address[0]]['received'] += 1
            symmetric_key = self.private_key.decrypt(
                encrypted_symmetric_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            cipher = Fernet(symmetric_key)

            while True:
                try:
                    encrypted_data = ssl_client_socket.recv(4096)
                    if not encrypted_data:
                        break
                    self.client_packet_count[client_address[0]]['received'] += 1

                    data: bytes = cipher.decrypt(encrypted_data)
                    self.client_traffic[client_address[0]] += len(data)
                    logging.info(f"Data received from {client_address}: {len(data)} bytes")

                    response = self.forward_to_destination(data, client_address)
                    encrypted_response = cipher.encrypt(response)
                    ssl_client_socket.sendall(encrypted_response)
                    self.client_packet_count[client_address[0]]['sent'] += 1
                    self.client_traffic_out[client_address[0]] += len(response)
                    self.packet_loss = self.calculate_packet_loss(client_address[0])
                except socket.timeout:
                    logging.warning("Socket timed out. Closing connection.")
                    break
                except ssl.SSLError as e:
                    logging.error(f"SSL error: {e}")
                    break
                except Exception as e:
                    logging.error(f"An error occurred while handling client data: {e}")
                    break

        except ssl.SSLError as e:
            logging.error(f"SSL error during initial handshake: {e}")
        except socket.timeout:
            logging.warning("Initial socket connection timed out. Closing connection.")
        except Exception as e:
            logging.error(f"An error occurred during client handling: {e}")
        finally:
            ssl_client_socket.close()
            del self.clients[client_address]


    def forward_to_destination(self, data, client_address) ->bytes:
        """
        Forward the received data to the destination server based on the headers.

        This function takes in the received data from the client and forwards it to the
        appropriate destination server based on the headers. If the data is a CONNECT
        request, it establishes a tunnel by sending an HTTP 200 Connection Established
        response and then forwards the data to the destination server. If the data is not
        a CONNECT request, it forwards the data to the destination server after parsing
        the headers to determine the destination URL.

        Parameters:
        - data (bytes): The received data from the client.
        - client_address (tuple): The client's address.

        Returns:
        - bytes: The response data from the destination server, or an empty bytes object
                if an error occurred.
        """
        try:
            # Handle CONNECT requests
            if data.startswith(b'CONNECT'):
                # This is a CONNECT request, which is used to establish a tunnel
                headers = data.split(b'\r\n')
                host_header = next((h for h in headers if b'Host:' in h), None)
                if not host_header:
                    raise ValueError("No Host header found")

                host = host_header.split(b' ')[1].decode('utf-8')
                url = urlparse(f'https://{host}')
                port = url.port or 443

                destination_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                destination_socket.settimeout(30)

                context = ssl.create_default_context()
                destination_socket = context.wrap_socket(destination_socket, server_hostname=url.hostname)

                destination_socket.connect((url.hostname, port))

                # Send 200 Connection Established response
                response = b"HTTP/1.1 200 Connection Established\r\n\r\n"
                self.ssl_client_socket.sendall(response)

                # Read the data from the client and forward it to the destination
                while True:
                    client_data = self.ssl_client_socket.recv(4096)
                    if not client_data:
                        break
                    destination_socket.sendall(client_data)
                    self.client_packet_count[client_address[0]]['sent'] += 1

                    response_data = destination_socket.recv(4096)
                    if not response_data:
                        break
                    self.ssl_client_socket.sendall(response_data)
                    self.client_packet_count[client_address[0]]['received'] += 1

                destination_socket.close()
                return b""
            else:
                headers = data.split(b'\r\n')
                host_header = next((h for h in headers if b'Host:' in h), None)
                if not host_header:
                    raise ValueError("No Host header found")

                host = host_header.split(b' ')[1].decode('utf-8')
                url = urlparse(f'http://{host}')
                port = url.port or 80
                if port == 443:
                    url = urlparse(f'https://{host}')

                destination_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                destination_socket.settimeout(30)

                if url.scheme == 'https':
                    context = ssl.create_default_context()
                    destination_socket = context.wrap_socket(destination_socket, server_hostname=url.hostname)

                destination_socket.connect((url.hostname, port))
                destination_socket.sendall(data)
                self.client_packet_count[client_address[0]]['sent'] += 1

                response_data = b""
                while True:
                    chunk = destination_socket.recv(4096)
                    if not chunk:
                        break
                    response_data += chunk
                    self.client_packet_count[client_address[0]]['received'] += 1

                destination_socket.close()
                return response_data

        except Exception as e:
            logging.error(f"Error forwarding data to destination: {e}")
            return b""

    def show_status(self):
        print("VPN Server Status")
        print(f"Server Address: {self.server_address}")
        print(f"Port: {self.port}")
        print(f"Connected Clients: {self.get_clients()}")
        print(f"Total Traffic In: {self.get_traffic_in()} bytes")
        print(f"Total Traffic Out: {self.get_traffic_out()} bytes")
        print(f"Packet Loss: {self.get_packet_loss()}%")


    def commands_options(self):
        self.commands: dict = {
            "1": "list clients",
            "2": "show status",
            "3": "traffic <client_ip>",
            "4": "disconnect <client_ip>",
            "5": "show memory usage",
            "6": "is private? <client_ip>",
            "7": "location <client_ip>",
            "8": "packet loss",
            "9": "quit",
        }
        for i, command in self.commands.items():
            print(f"{i}. {command}")


    def admin_commands(self):
        print(pyfiglet.figlet_format("Digital-Shield-VPN Server"))
        self.show_status()
        while True:
            command = input("choose option: ").strip().lower()
            self.commands_options()
            if command == "1":
                self.list_clients()
            elif command=="2":
                self.show_status()
            elif command=="3":
                option: str = input("press <ENTER> for all traffic or enter IP address or specific traffic")
                if (option == ""):
                    self.show_traffic()
                else:
                    self.show_traffic(option)
            elif command=="4":
                address: str = input("Enter IP address to disconnect: ").strip()
                self.disconnect_client(address)
            elif command == "5":
                self.show_memory_usage()
            elif command == "6":
                address: str = input("Enter IP address: ").strip()
                self.ip_is_private(address)
            elif command == "7":
                address: str = input("Enter IP address: ").strip()
                self.location(address)
            elif command == "8":
                self.get_packet_loss()
            elif command == "9":
                option: str = input("Are you sure you want to quit? (y/n): ").strip().lower()
                if option == "y":
                    self.quit_server()
                    break
            else:
                logging.warning("Unknown command")


    def list_clients(self):
        if self.clients:
            logging.info("Connected clients:")
            for client_address in self.clients.keys():
                logging.info(client_address)
        else:
            logging.info("No connected clients.")


    def show_traffic(self, client_ip=None):
        if (client_ip is None):
            for client, traffic in self.client_traffic.items():
                logging.info(f"Traffic for {client}: {traffic} bytes")
        else:
            traffic = self.client_traffic.get(client_ip, None)
            if traffic is not None:
                logging.info(f"Traffic for {client_ip}: {traffic} bytes")
            else:
                logging.warning(f"No traffic data for {client_ip}")


    def disconnect_client(self, client_ip):
        for client_address, client_socket in list(self.clients.items()):
            if client_address[0] == client_ip:
                client_socket.close()
                del self.clients[client_address]
                logging.info(f"Disconnected client {client_ip}")
                return
        logging.warning(f"No client found with IP {client_ip}")


    def ip_is_private(self, ip):
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except ValueError:
            return False

    def show_memory_usage(self):
        memory = psutil.virtual_memory()
        logging.info(f"Memory usage: {memory.percent}%")


    def location(self, ip: str):
        g = geocoder(ip)
        logging.info(g.latlng)
        logging.info(g.city)

    def quit_server(self):
        logging.info("Shutting down server...")
        for client_socket in self.clients.values():
            client_socket.close()
        self.server_socket.close()
        logging.info("Server shut down.")


if __name__ == '__main__':
    server = VPNServer('config.toml')
    server.start_vpn()


