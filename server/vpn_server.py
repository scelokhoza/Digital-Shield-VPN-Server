import ssl
import toml
import socket
import threading
import logging
from urllib.parse import urlparse
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet
from dataclasses import dataclass


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
        self.file = target_file
        
    
    def load_config(self) -> VPNData:
        with open(self.file, 'r') as config_file:
            config_data: dict = toml.load(config_file)
            
        return VPNData(
            server_address=config_data['server']['address'],
            certfile=config_data['server']['certfile'],
            keyfile=config_data['server']['keyfile'],
            port=config_data['server']['port']
        )
    

class VPNServer:
    def __init__(self, config_file: str) -> None:
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
        return sum(self.client_traffic.values())
    
    
    def get_traffic_out(self) -> int:
        return sum(self.client_traffic_out.values())
    
    
    def get_clients(self) -> dict:
        return self.clients
    
    def get_packet_loss(self) -> int:
        return self.packet_loss
    
    
    def calculate_packet_loss(self, client_address: tuple) -> int:
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
        try:
            self.server_socket.bind((self.server_address, self.port))
            self.server_socket.listen(5)
            logging.info(f"Server started on {self.server_address}:{self.port}")

            threading.Thread(target=self.admin_commands).start()

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
    

    def admin_commands(self):
        while True:
            command = input("Enter command: ").strip().lower()
            if command == "list clients":
                self.list_clients()
            elif command.startswith("show traffic"):
                _, client_ip = command.split()
                self.show_traffic(client_ip)
            elif command.startswith("disconnect"):
                _, client_ip = command.split()
                self.disconnect_client(client_ip)
            elif command == "quit":
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


    def show_traffic(self, client_ip):
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


    def quit_server(self):
        logging.info("Shutting down server...")
        for client_socket in self.clients.values():
            client_socket.close()
        self.server_socket.close()
        logging.info("Server shut down.")


if __name__ == '__main__':
    server = VPNServer()
    server.start_vpn()


