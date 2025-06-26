import paramiko

class SSHTunnel:
    def __init__(self, ssh_server, ssh_port, ssh_username, ssh_password=None, ssh_key_filepath=None):
        self.ssh_server = ssh_server
        self.ssh_port = ssh_port
        self.ssh_username = ssh_username
        self.ssh_password = ssh_password
        self.ssh_key_filepath = ssh_key_filepath
        self.client = None

    def connect(self):
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            if self.ssh_key_filepath:
                k = paramiko.RSAKey.from_private_key_file(self.ssh_key_filepath)
                self.client.connect(
                    self.ssh_server,
                    port=self.ssh_port,
                    username=self.ssh_username,
                    pkey=k
                )
            elif self.ssh_password:
                self.client.connect(
                    self.ssh_server,
                    port=self.ssh_port,
                    username=self.ssh_username,
                    password=self.ssh_password
                )
            else:
                # Attempt to connect without password or key (e.g., using SSH agent)
                self.client.connect(
                    self.ssh_server,
                    port=self.ssh_port,
                    username=self.ssh_username
                )
            print(f"Successfully connected to SSH server: {self.ssh_server}")
            return True
        except paramiko.AuthenticationException:
            print("Authentication failed. Please check your credentials or key.")
            return False
        except paramiko.SSHException as sshException:
            print(f"Unable to establish SSH connection: {sshException}")
            return False
        except FileNotFoundError:
            print(f"SSH key file not found: {self.ssh_key_filepath}")
            return False
        except Exception as e:
            print(f"An unexpected error occurred during SSH connection: {e}")
            return False

    def disconnect(self):
        if self.client:
            self.client.close()
            print("Disconnected from SSH server.")

    def execute_command(self, command):
        if not self.client:
            print("Not connected to SSH server.")
            return None, None, None

        stdin, stdout, stderr = self.client.exec_command(command)
        return stdin, stdout, stderr

    def start_socks_proxy(self, local_host='127.0.0.1', local_port=1080):
        if not self.client or not self.client.get_transport() or not self.client.get_transport().is_active():
            print("SSH client not connected or transport not active. Cannot start SOCKS proxy.")
            return

        self.socks_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socks_server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.socks_server_socket.bind((local_host, local_port))
        except Exception as e:
            print(f"Failed to bind SOCKS proxy to {local_host}:{local_port}: {e}")
            return

        self.socks_server_socket.listen(5)
        print(f"SOCKS5 proxy started on {local_host}:{local_port}")
        self.running = True # Flag to control the server loop

        try:
            while self.running:
                try:
                    # Use a timeout for select to allow checking self.running periodically
                    readable, _, _ = select.select([self.socks_server_socket], [], [], 0.5)
                    if not self.running: # Check immediately after select returns
                        break
                    if readable:
                        client_socket, client_address = self.socks_server_socket.accept()
                        if not self.running: # Check again before starting thread
                            client_socket.close()
                            break
                        print(f"SOCKS: Accepted connection from {client_address}")
                        handler_thread = threading.Thread(
                            target=self._handle_socks_client,
                            args=(client_socket, client_address)
                        )
                        handler_thread.daemon = True
                        handler_thread.start()
                except socket.timeout: # select timed out, loop and check self.running
                    continue
                except KeyboardInterrupt: # Should be caught in main.py, but as a fallback
                    print("SOCKS proxy server loop interrupted.")
                    self.running = False
                    break
        finally:
            if hasattr(self, 'socks_server_socket') and self.socks_server_socket:
                print("Closing SOCKS server socket.")
                self.socks_server_socket.close()
            print("SOCKS proxy server loop ended.")


    def stop_socks_proxy(self):
        print("Stopping SOCKS proxy...")
        self.running = False
        # The server socket is closed in the `finally` block of `start_socks_proxy`
        # Existing client handler threads will complete or exit when they check self.running or encounter errors.

    def _handle_socks_client(self, client_socket, client_address):
        try:
            # SOCKS5 handshake: version identification and method selection
            client_socket.settimeout(10) # Timeout for socket operations
            version_nmethods = client_socket.recv(2)
            if not version_nmethods: return
            version, nmethods = struct.unpack('!BB', version_nmethods)

            if version != 5:
                print(f"SOCKS: Unsupported SOCKS version {version} from {client_address}")
                return

            methods_bytes = client_socket.recv(nmethods)
            if not methods_bytes: return
            methods = list(methods_bytes) # Convert bytes to list of ints for easier checking

            if 0x00 not in methods: # 0x00: NO AUTHENTICATION REQUIRED
                print(f"SOCKS: Client {client_address} does not support NO AUTH method.")
                client_socket.sendall(struct.pack('!BB', 5, 0xFF)) # 0xFF: no acceptable methods
                return

            client_socket.sendall(struct.pack('!BB', 5, 0x00)) # Select NO AUTH

            # SOCKS5 request
            header = client_socket.recv(4)
            if not header or len(header) < 4: return
            ver, cmd, rsv, atyp = struct.unpack('!BBBB', header)

            if ver != 5: return

            if cmd == 1:  # CONNECT
                target_host = ""
                if atyp == 1:  # IPv4
                    ipv4_bytes = client_socket.recv(4)
                    if not ipv4_bytes or len(ipv4_bytes) < 4: return
                    target_host = socket.inet_ntoa(ipv4_bytes)
                elif atyp == 3:  # Domain name
                    domain_len_byte = client_socket.recv(1)
                    if not domain_len_byte: return
                    domain_len = domain_len_byte[0]
                    domain_bytes = client_socket.recv(domain_len)
                    if not domain_bytes or len(domain_bytes) < domain_len: return
                    target_host = domain_bytes.decode('utf-8', errors='ignore')
                elif atyp == 4: # IPv6
                    ipv6_bytes = client_socket.recv(16)
                    if not ipv6_bytes or len(ipv6_bytes) < 16: return
                    target_host = socket.inet_ntop(socket.AF_INET6, ipv6_bytes)
                else:
                    print(f"SOCKS: Unknown address type {atyp} from {client_address}")
                    client_socket.sendall(struct.pack('!BBBBIH', 5, 8, 0, 1, 0, 0)) # REP: X'08' Address type not supported
                    return

                port_bytes = client_socket.recv(2)
                if not port_bytes or len(port_bytes) < 2: return
                target_port = struct.unpack('!H', port_bytes)[0]

                print(f"SOCKS: Client {client_address} requests CONNECT to {target_host}:{target_port}")

                if not self.client or not self.client.get_transport() or not self.client.get_transport().is_active():
                    print("SOCKS: SSH client not connected. Cannot fulfill request.")
                    client_socket.sendall(struct.pack('!BBBBIH', 5, 1, 0, 1, 0, 0)) # REP: X'01' general SOCKS server failure
                    return

                ssh_channel = None
                try:
                    ssh_channel = self.client.get_transport().open_channel(
                        'direct-tcpip',
                        (target_host, target_port),
                        client_address
                    )
                    print(f"SOCKS: SSH channel opened to {target_host}:{target_port}")

                    # BND.ADDR and BND.PORT should be the address and port on the SOCKS server
                    # that the client should use for the connection. For direct-tcpip,
                    # we can often just return 0s as the client is already connected to us.
                    # Some clients might be more strict. Let's use the SSH channel's source addr if available, else 0s.
                    # However, `getpeername()` on the channel would be the remote SSH server, not what we need here.
                    # For simplicity and common behavior, 0.0.0.0:0 is often accepted.
                    bound_addr_ip = '0.0.0.0'
                    bound_port_num = 0
                    bound_addr_bytes = socket.inet_aton(bound_addr_ip)

                    reply = b'\x05\x00\x00\x01' + bound_addr_bytes + struct.pack('!H', bound_port_num)
                    client_socket.sendall(reply)

                    self._relay_data(client_socket, ssh_channel)

                except paramiko.SSHException as e:
                    print(f"SOCKS: Failed to open SSH channel to {target_host}:{target_port}: {e}")
                    # REP: X'04' Host unreachable (or other appropriate error based on e)
                    # Determine a more specific error if possible, e.g., from channel open failure reasons
                    rep_code = 4 # Default to host unreachable
                    if "Administratively prohibited" in str(e): # Example, might need to check specific exception types from Paramiko
                        rep_code = 2 # Connection not allowed by ruleset
                    elif "Connection refused" in str(e):
                        rep_code = 5 # Connection refused
                    client_socket.sendall(struct.pack('!BBBBIH', 5, rep_code, 0, 1, 0, 0))
                except Exception as e:
                    print(f"SOCKS: Error during SSH channel opening or relay setup: {e}")
                    client_socket.sendall(struct.pack('!BBBBIH', 5, 1, 0, 1, 0, 0)) # General failure
                finally:
                    if ssh_channel:
                        ssh_channel.close()
            else: # Other commands like BIND or UDP ASSOCIATE
                print(f"SOCKS: Unsupported command {cmd} from {client_address}")
                client_socket.sendall(struct.pack('!BBBBIH', 5, 7, 0, 1, 0, 0)) # REP: X'07' Command not supported

        except socket.timeout:
            print(f"SOCKS: Timeout with client {client_address}")
        except socket.error as e:
            # Avoid printing error if it's because the proxy is shutting down and self.running is false
            if self.running:
                 print(f"SOCKS: Socket error with {client_address}: {e}")
        except struct.error as e:
            if self.running:
                print(f"SOCKS: Struct packing/unpacking error with {client_address}: {e}")
        except Exception as e:
            if self.running:
                print(f"SOCKS: Unexpected error handling client {client_address}: {e}")
        finally:
            client_socket.close()
            # print(f"SOCKS: Closed connection from {client_address}") # Can be noisy

    def _relay_data(self, client_socket, ssh_channel):
        try:
            while self.running and ssh_channel.active and not ssh_channel.closed:
                # Check if either socket has data or if the channel is closed by remote
                r, w, x = select.select([client_socket, ssh_channel], [], [], 0.1) # Short timeout
                if not self.running: break

                if client_socket in r:
                    data = client_socket.recv(4096)
                    if not data: break # Client closed connection
                    ssh_channel.sendall(data)

                if ssh_channel in r:
                    if ssh_channel.recv_ready():
                        data = ssh_channel.recv(4096)
                        if not data: break # SSH channel closed by remote
                        client_socket.sendall(data)

                    # It's important to check if the channel was closed after a recv
                    if ssh_channel.closed:
                        # print("SOCKS Relay: SSH channel closed by remote after recv.")
                        break

                    if ssh_channel.recv_stderr_ready():
                        error_data = ssh_channel.recv_stderr(4096)
                        # print(f"SOCKS: SSH channel stderr: {error_data.decode(errors='ignore')}")

        except socket.error as e:
            # if self.running or ("Connection reset by peer" not in str(e) and "Broken pipe" not in str(e)):
            # Filter out common errors that happen during normal close
            if self.running and not isinstance(e, (ConnectionResetError, BrokenPipeError)):
                 print(f"SOCKS Relay: Socket error: {e}")
        except Exception as e:
            if self.running:
                print(f"SOCKS Relay: Unexpected error: {e}")
        finally:
            # print("SOCKS: Relay loop ended.")
            if ssh_channel and not ssh_channel.closed:
                ssh_channel.close()
            # client_socket is closed in _handle_socks_client's finally block
            pass

import socket
import threading
import select
import struct
import logging
import paramiko
import socket # Already present
import threading # Already present
import select # Already present
import struct # Already present

try:
    from scapy.layers.tls.handshake import TLSClientHello, TLSServerHello
    from scapy.layers.tls.extensions import TLSExtension, TLSExtServerNameIndication, ServerName, ServerNameIndicationHostName
    from scapy.layers.tls.record import TLS
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    # This will be logged by the logger passed in or the default one if used directly
    # print("WARNING: Scapy is not installed or TLS layers are missing. SNI customization will not be available.")
    # print("Install scapy with TLS support (e.g., pip install scapy[tls] or pip install scapy cryptography)")


# Default logger if none is provided by the main application
default_logger = logging.getLogger(__name__)
if not default_logger.handlers: # Avoid adding multiple handlers if this module is reloaded
    default_logger.addHandler(logging.NullHandler()) # Prevents "No handler found" warnings


class SSHTunnel:
    """
    Manages an SSH connection and can establish a SOCKS5 proxy server
    that tunnels traffic through the SSH connection.
    """
    def __init__(self, ssh_server, ssh_port, ssh_username,
                 ssh_password=None, ssh_key_filepath=None, logger=None, custom_sni=None):
        """
        Initializes the SSHTunnel configuration.

        Args:
            ssh_server (str): The hostname or IP address of the SSH server.
            ssh_port (int): The port number of the SSH server.
            ssh_username (str): The username for SSH authentication.
            ssh_password (str, optional): The password for SSH authentication. Defaults to None.
            ssh_key_filepath (str, optional): Path to the private key file for SSH authentication.
                                             Defaults to None.
            logger (logging.Logger, optional): An external logger instance.
                                               If None, a default module logger is used.
            custom_sni (str, optional): A custom SNI value to inject into TLS handshakes.
                                        Defaults to None (no SNI modification).
        """
        self.ssh_server = ssh_server
        self.ssh_port = ssh_port
        self.ssh_username = ssh_username
        self.ssh_password = ssh_password
        self.ssh_key_filepath = ssh_key_filepath
        self.client = None
        self.running = False  # For SOCKS proxy state
        self.logger = logger if logger else default_logger
        self.custom_sni = custom_sni

        if self.custom_sni and not SCAPY_AVAILABLE:
            self.logger.warning("Custom SNI specified, but Scapy is not available. SNI customization will be disabled.")
            self.custom_sni = None # Disable if scapy is missing

    def is_ssh_connected(self):
        """Checks if the SSH client is connected and the transport is active."""
        return self.client and self.client.get_transport() and self.client.get_transport().is_active()

    def connect(self):
        """
        Establishes the SSH connection to the server using provided credentials.

        Supports password, private key, or SSH agent-based authentication.

        Returns:
            bool: True if connection is successful, False otherwise.
        """
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            self.logger.info(f"Attempting to connect to SSH server {self.ssh_server}:{self.ssh_port} as {self.ssh_username}...")
            if self.ssh_key_filepath:
                self.logger.debug(f"Using private key: {self.ssh_key_filepath}")
                # Ensure key permissions are appropriate on POSIX systems (e.g., 600)
                # Paramiko might raise an error if key is too open, or it might depend on SSH server config.
                # Consider adding a check or note for user.
                try:
                    k = paramiko.PKey.from_private_key_file(self.ssh_key_filepath)
                except paramiko.PasswordRequiredException:
                    self.logger.error(f"Private key file {self.ssh_key_filepath} is encrypted and requires a password. This is not currently supported.")
                    # TODO: Optionally, prompt for key password here if desired in future.
                    return False
                except paramiko.SSHException as e:
                    self.logger.error(f"Error loading private key {self.ssh_key_filepath}: {e}. Ensure it's a valid private key format (e.g., RSA, Ed25519).")
                    return False

                self.client.connect(
                    self.ssh_server,
                    port=self.ssh_port,
                    username=self.ssh_username,
                    pkey=k,
                    timeout=10 # Added connection timeout
                )
            elif self.ssh_password:
                self.logger.debug("Using password authentication.")
                self.client.connect(
                    self.ssh_server,
                    port=self.ssh_port,
                    username=self.ssh_username,
                    password=self.ssh_password,
                    timeout=10 # Added connection timeout
                )
            else:
                self.logger.debug("Attempting connection without explicit password or key (e.g., using SSH agent).")
                self.client.connect(
                    self.ssh_server,
                    port=self.ssh_port,
                    username=self.ssh_username,
                    allow_agent=True, # Explicitly allow SSH agent
                    look_for_keys=True, # Explicitly look for discoverable keys
                    timeout=10 # Added connection timeout
                )
            self.logger.info(f"Successfully connected to SSH server: {self.ssh_server}")
            return True
        except paramiko.AuthenticationException as e:
            self.logger.error(f"SSH Authentication failed for {self.ssh_username}@{self.ssh_server}: {e}. Check credentials or key.")
            return False
        except paramiko.SSHException as e: # Catches a broader range of SSH errors including HostKeyUnknownError, NoValidConnectionsError
            self.logger.error(f"SSH connection error to {self.ssh_server}: {e}")
            return False
        except FileNotFoundError:
            self.logger.error(f"SSH private key file not found: {self.ssh_key_filepath}")
            return False
        except socket.timeout:
            self.logger.error(f"SSH connection to {self.ssh_server}:{self.ssh_port} timed out.")
            return False
        except socket.error as e: # For other network errors like "Connection refused"
            self.logger.error(f"Network error connecting to SSH server {self.ssh_server}:{self.ssh_port}: {e}")
            return False
        except Exception as e:
            self.logger.exception(f"An unexpected error occurred during SSH connection to {self.ssh_server}: {e}")
            return False

    def disconnect(self):
        """Closes the SSH connection if it is active."""
        if self.client:
            self.logger.info("Disconnecting from SSH server.")
            try:
                self.client.close()
            except Exception as e:
                self.logger.error(f"Error while closing SSH client: {e}")
            self.client = None # Ensure it's reset

    def execute_command(self, command):
        """
        Executes a command on the remote SSH server.

        Args:
            command (str): The command string to execute.

        Returns:
            tuple: (stdin, stdout, stderr) paramiko channels for the command,
                   or (None, None, None) if not connected or an error occurs.
        """
        if not self.is_ssh_connected():
            self.logger.warning("Cannot execute command: Not connected to SSH server.")
            return None, None, None

        self.logger.debug(f"Executing command on SSH server: {command}")
        try:
            stdin, stdout, stderr = self.client.exec_command(command, timeout=10) # Added timeout
            return stdin, stdout, stderr
        except paramiko.SSHException as e:
            self.logger.error(f"Failed to execute command '{command}': {e}")
            return None, None, None
        except socket.timeout:
            self.logger.error(f"Timeout executing command '{command}' on SSH server.")
            return None, None, None


    def start_socks_proxy(self, local_host='127.0.0.1', local_port=1080):
        """
        Starts the SOCKS5 proxy server on a local host and port.

        The server listens for incoming SOCKS client connections and handles them
        in separate threads. Traffic is tunneled through the active SSH connection.

        Args:
            local_host (str, optional): The local IP address to bind the SOCKS proxy to.
                                        Defaults to '127.0.0.1'.
            local_port (int, optional): The local port to bind the SOCKS proxy to.
                                        Defaults to 1080.
        """
        if not self.is_ssh_connected():
            self.logger.error("SSH client not connected or transport not active. Cannot start SOCKS proxy.")
            self.running = False # Ensure running is False if we can't start
            return

        self.socks_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socks_server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.logger.info(f"Binding SOCKS proxy to {local_host}:{local_port}...")
            self.socks_server_socket.bind((local_host, local_port))
            self.socks_server_socket.listen(10) # Increased backlog slightly
            self.logger.info(f"SOCKS5 proxy started and listening on {local_host}:{local_port}")
            self.running = True
        except socket.error as e:
            self.logger.error(f"Failed to bind/listen for SOCKS proxy on {local_host}:{local_port}: {e}")
            self.running = False # Ensure running is False
            if hasattr(self, 'socks_server_socket') and self.socks_server_socket:
                 self.socks_server_socket.close() # Clean up the socket if bind failed but socket was created
            return # Important to return here

        try:
            while self.running:
                try:
                    readable, _, _ = select.select([self.socks_server_socket], [], [], 0.5)
                    if not self.running:
                        break
                    if readable:
                        client_socket, client_address = self.socks_server_socket.accept()
                        if not self.running:
                            client_socket.close()
                            break
                        self.logger.debug(f"SOCKS: Accepted connection from {client_address}")
                        handler_thread = threading.Thread(
                            target=self._handle_socks_client,
                            args=(client_socket, client_address)
                        )
                        handler_thread.daemon = True
                        handler_thread.start()
                except socket.timeout:
                    continue
                except OSError as e: # Catch errors like "[Errno 9] Bad file descriptor" if socket is closed abruptly
                    if self.running: # Only log if we weren't expecting it to close
                        self.logger.error(f"SOCKS proxy server socket error: {e}")
                    self.running = False # Stop the loop
                    break
                except Exception as e: # General catch for unexpected errors in accept loop
                    if self.running:
                        self.logger.exception(f"SOCKS proxy server unexpected error in accept loop: {e}")
                    self.running = False
                    break
        finally: # This finally block is for the `try` that starts after successful bind/listen
            if hasattr(self, 'socks_server_socket') and self.socks_server_socket:
                self.logger.debug("Closing SOCKS server listening socket.")
                self.socks_server_socket.close()
            self.logger.info("SOCKS proxy server loop ended.")


    def stop_socks_proxy(self):
        """
        Signals the SOCKS proxy server and its active handler threads to stop.
        Sets the `self.running` flag to False.
        """
        self.logger.info("Stopping SOCKS proxy...")
        self.running = False # Signal all loops and threads to stop
        # The server listening socket is closed in the `finally` block of `start_socks_proxy` loop.
        # Active client handler threads will see `self.running` as False and should exit.

    def _handle_socks_client(self, client_socket, client_address):
        """
        Handles an individual SOCKS client connection.

        This method performs the SOCKS5 handshake, processes the client's
        request (currently only CONNECT), establishes a tunneled connection
        via SSH, and then relays data.

        Args:
            client_socket (socket.socket): The socket for the connected SOCKS client.
            client_address (tuple): The address (host, port) of the SOCKS client.
        """
        self.logger.debug(f"SOCKS: Handling client {client_address}")
        ssh_channel = None # Ensure ssh_channel is defined for the finally block
        try:
            client_socket.settimeout(10)

            # SOCKS5 handshake
            version_nmethods_bytes = client_socket.recv(2)
            if not version_nmethods_bytes or len(version_nmethods_bytes) < 2:
                self.logger.warning(f"SOCKS: Client {client_address} sent incomplete version/nmethods. Closing.")
                return
            version, nmethods = struct.unpack('!BB', version_nmethods_bytes)

            if version != 5:
                self.logger.warning(f"SOCKS: Unsupported SOCKS version {version} from {client_address}")
                return

            methods_bytes = client_socket.recv(nmethods)
            if not methods_bytes or len(methods_bytes) < nmethods:
                self.logger.warning(f"SOCKS: Client {client_address} sent incomplete methods list. Closing.")
                return
            methods = list(methods_bytes)

            if 0x00 not in methods:
                self.logger.warning(f"SOCKS: Client {client_address} does not support NO AUTH method. Sending 0xFF.")
                client_socket.sendall(struct.pack('!BB', 5, 0xFF))
                return
            client_socket.sendall(struct.pack('!BB', 5, 0x00))
            self.logger.debug(f"SOCKS: Handshake completed with {client_address} (NO AUTH).")

            # SOCKS5 request
            header = client_socket.recv(4)
            if not header or len(header) < 4:
                self.logger.warning(f"SOCKS: Client {client_address} sent incomplete request header. Closing.")
                return
            ver, cmd, rsv, atyp = struct.unpack('!BBBB', header)

            if ver != 5:
                self.logger.warning(f"SOCKS: Invalid SOCKS version in request from {client_address} after handshake. Closing.")
                return

            if cmd == 1:  # CONNECT
                target_host = ""
                if atyp == 1:  # IPv4
                    ipv4_bytes = client_socket.recv(4)
                    if not ipv4_bytes or len(ipv4_bytes) < 4: return self.logger.warning(f"SOCKS: Incomplete IPv4 addr from {client_address}")
                    target_host = socket.inet_ntoa(ipv4_bytes)
                elif atyp == 3:  # Domain name
                    domain_len_byte = client_socket.recv(1)
                    if not domain_len_byte: return self.logger.warning(f"SOCKS: No domain length from {client_address}")
                    domain_len = domain_len_byte[0]
                    if domain_len == 0: return self.logger.warning(f"SOCKS: Zero length domain from {client_address}")
                    domain_bytes = client_socket.recv(domain_len)
                    if not domain_bytes or len(domain_bytes) < domain_len: return self.logger.warning(f"SOCKS: Incomplete domain from {client_address}")
                    target_host = domain_bytes.decode('utf-8', errors='ignore')
                elif atyp == 4: # IPv6
                    ipv6_bytes = client_socket.recv(16)
                    if not ipv6_bytes or len(ipv6_bytes) < 16: return self.logger.warning(f"SOCKS: Incomplete IPv6 addr from {client_address}")
                    target_host = socket.inet_ntop(socket.AF_INET6, ipv6_bytes)
                else:
                    self.logger.warning(f"SOCKS: Unknown address type {atyp} from {client_address}")
                    client_socket.sendall(struct.pack('!BBBBIH', 5, 8, 0, 1, 0, 0))
                    return

                port_bytes = client_socket.recv(2)
                if not port_bytes or len(port_bytes) < 2: return self.logger.warning(f"SOCKS: Incomplete port from {client_address}")
                target_port = struct.unpack('!H', port_bytes)[0]

                self.logger.info(f"SOCKS: Client {client_address} requests CONNECT to {target_host}:{target_port}")

                if not self.is_ssh_connected():
                    self.logger.error("SOCKS: SSH client not connected. Cannot fulfill CONNECT request.")
                    client_socket.sendall(struct.pack('!BBBBIH', 5, 1, 0, 1, 0, 0))
                    return

                try:
                    self.logger.debug(f"SOCKS: Opening SSH 'direct-tcpip' channel to {target_host}:{target_port} for {client_address}")
                    ssh_channel = self.client.get_transport().open_channel(
                        'direct-tcpip',
                        (target_host, target_port),
                        client_address,
                        timeout=10 # Timeout for channel opening
                    )
                    if not ssh_channel: # Should raise exception if failed, but as a safeguard
                        raise paramiko.SSHException("Failed to open channel, reason unknown (open_channel returned None)")

                    self.logger.info(f"SOCKS: SSH channel successfully opened to {target_host}:{target_port} for {client_address}")

                    bound_addr_ip = '0.0.0.0'
                    bound_port_num = 0
                    bound_addr_bytes = socket.inet_aton(bound_addr_ip)
                    reply = b'\x05\x00\x00\x01' + bound_addr_bytes + struct.pack('!H', bound_port_num)
                    client_socket.sendall(reply)
                    self.logger.debug(f"SOCKS: Sent CONNECT success reply to {client_address}")

                    # SNI Modification Point
                    if self.custom_sni and SCAPY_AVAILABLE:
                        self.logger.debug(f"SOCKS: SNI modification active for {client_address}. Custom SNI: {self.custom_sni}")
                        # Try to peek at the first packet for TLS ClientHello
                        # client_socket must be non-blocking for peeking, or use select
                        client_socket.setblocking(False)
                        initial_data = b""
                        try:
                            # Wait for data for a very short time (e.g., up to 0.1 seconds)
                            # This is a simple way to peek; a more robust way might involve select with timeout
                            ready_to_read, _, _ = select.select([client_socket], [], [], 0.1)
                            if ready_to_read:
                                initial_data = client_socket.recv(4096, socket.MSG_PEEK) # Peek at data

                            if initial_data:
                                self.logger.debug(f"SOCKS: Peeked {len(initial_data)} bytes for SNI processing from {client_address}")
                                # Basic check for TLS ClientHello (Content Type 22, Handshake Type 1)
                                if initial_data[0] == 0x16 and initial_data[5] == 0x01: # TLS Handshake, ClientHello
                                    self.logger.debug(f"SOCKS: Detected potential TLS ClientHello from {client_address}")
                                    actual_client_hello_data = client_socket.recv(len(initial_data)) # Consume the peeked data

                                    modified_hello = self._modify_sni_in_clienthello(actual_client_hello_data, self.custom_sni, client_address)
                                    if modified_hello:
                                        self.logger.info(f"SOCKS: SNI modified for {client_address}. Sending modified ClientHello to SSH channel.")
                                        ssh_channel.sendall(modified_hello)
                                    else:
                                        self.logger.debug(f"SOCKS: SNI not modified (or failed), sending original ClientHello from {client_address} to SSH channel.")
                                        ssh_channel.sendall(actual_client_hello_data)
                                else:
                                    self.logger.debug(f"SOCKS: Initial data from {client_address} does not appear to be TLS ClientHello. Forwarding as is.")
                                    # No need to consume here as it wasn't a ClientHello we are modifying
                            else:
                            self.logger.debug(f"SOCKS: No initial data peeked from {client_address_info} for SNI mod within timeout. Proceeding to relay.")
                        except BlockingIOError:
                            # This is expected if client doesn't send data immediately
                            self.logger.debug(f"SOCKS: No initial data immediately available from {client_address} for SNI (BlockingIOError). Proceeding to relay.")
                        except socket.timeout:
                            self.logger.debug(f"SOCKS: Socket timeout while peeking/receiving initial data for SNI from {client_address_info}. Proceeding to relay.")
                        except socket.error as sock_err:
                            self.logger.error(f"SOCKS: Socket error during SNI initial data recv for {client_address_info}: {sock_err}. Proceeding to relay.")
                        except Exception as sni_e:
                            self.logger.exception(f"SOCKS: Unexpected error during SNI processing for {client_address_info}: {sni_e}. Forwarding any consumed data if possible.")
                            # If actual_client_hello_data was populated and an error happened after,
                            # it's already sent in the _modify_sni_in_clienthello fallback.
                            # If error was before/during recv, nothing to send here.
                        finally:
                             client_socket.setblocking(True) # Restore blocking mode for relay

                    self._relay_data(client_socket, ssh_channel, client_address)

                except paramiko.ChannelException as e: # Specific exception for channel open failures
                    self.logger.error(f"SOCKS: Paramiko ChannelException opening channel to {target_host}:{target_port} for {client_address}: Code {e.code}, Text: {e.text}")
                    rep_code = 1 # General SOCKS server failure by default
                    # Paramiko ChannelException codes:
                    # 1: Administratively prohibited
                    # 2: Connect failed
                    # 3: Unknown channel type
                    # 4: Resource shortage
                    if e.code == 1: rep_code = 2 # Connection not allowed by ruleset
                    elif e.code == 2: rep_code = 5 # Connection refused (or 4 if host unreachable)
                    elif e.code == 4: rep_code = 1 # General failure (or could be mapped to a more specific SOCKS error if applicable)
                    else: rep_code = 1
                    client_socket.sendall(struct.pack('!BBBBIH', 5, rep_code, 0, 1, 0, 0))
                except socket.timeout: # Timeout during channel open
                    self.logger.error(f"SOCKS: Timeout opening SSH channel to {target_host}:{target_port} for {client_address}")
                    client_socket.sendall(struct.pack('!BBBBIH', 5, 4, 0, 1, 0, 0)) # Host unreachable (closest match)
                except paramiko.SSHException as e: # Other SSH errors during channel setup
                    self.logger.error(f"SOCKS: SSHException opening channel to {target_host}:{target_port} for {client_address}: {e}")
                    client_socket.sendall(struct.pack('!BBBBIH', 5, 1, 0, 1, 0, 0))
                except Exception as e:
                    self.logger.exception(f"SOCKS: Unexpected error for {client_address} during SSH channel to {target_host}:{target_port}: {e}")
                    try: # Try to send a generic error if possible
                        client_socket.sendall(struct.pack('!BBBBIH', 5, 1, 0, 1, 0, 0))
                    except: pass # If sending fails, nothing more to do
            else:
                self.logger.warning(f"SOCKS: Unsupported command {cmd} from {client_address}")
                client_socket.sendall(struct.pack('!BBBBIH', 5, 7, 0, 1, 0, 0))

        except socket.timeout:
            self.logger.warning(f"SOCKS: Timeout during handshake/request with client {client_address}")
        except socket.error as e:
            if self.running: # Avoid logging errors if proxy is shutting down
                 self.logger.warning(f"SOCKS: Socket error with client {client_address}: {e}")
        except struct.error as e:
            if self.running:
                self.logger.error(f"SOCKS: Struct packing/unpacking error with client {client_address}: {e}")
        except Exception as e:
            if self.running:
                self.logger.exception(f"SOCKS: Unexpected error handling client {client_address}: {e}")
        finally:
            if ssh_channel and not ssh_channel.closed:
                ssh_channel.close()
            client_socket.close()
            self.logger.debug(f"SOCKS: Closed connection from {client_address}")

    def _relay_data(self, client_socket, ssh_channel, client_address_info): # Added client_address_info for logging
        self.logger.debug(f"SOCKS Relay: Starting data relay for {client_address_info} <=> SSH channel {ssh_channel.get_id()}")
        active_relay = True
        try:
            while self.running and active_relay and ssh_channel.active and not ssh_channel.closed:
                r, w, x = select.select([client_socket, ssh_channel], [], [client_socket, ssh_channel], 0.1)
                if not self.running: break

                if x: # Check for errors on sockets
                    self.logger.warning(f"SOCKS Relay: Socket error reported by select() for {client_address_info}. Ending relay.")
                    active_relay = False; break

                if client_socket in r:
                    try:
                        data = client_socket.recv(4096)
                        if not data:
                            self.logger.debug(f"SOCKS Relay: Client {client_address_info} closed connection.")
                            active_relay = False; break
                        ssh_channel.sendall(data)
                        self.logger.log(logging.getLevelName("TRACE") if hasattr(logging, "TRACE") else logging.DEBUG - 5,
                                        f"SOCKS Relay: C->S {len(data)} bytes for {client_address_info}")
                    except socket.error as e:
                        self.logger.warning(f"SOCKS Relay: Socket error receiving from client {client_address_info}: {e}")
                        active_relay = False; break

                if ssh_channel in r:
                    try:
                        if ssh_channel.recv_ready():
                            data = ssh_channel.recv(4096)
                            if not data:
                                self.logger.debug(f"SOCKS Relay: SSH channel {ssh_channel.get_id()} closed by remote.")
                                active_relay = False; break
                            client_socket.sendall(data)
                            self.logger.log(logging.getLevelName("TRACE") if hasattr(logging, "TRACE") else logging.DEBUG - 5,
                                            f"SOCKS Relay: S->C {len(data)} bytes for {client_address_info}")

                        if ssh_channel.closed: # Check again after recv
                            self.logger.debug(f"SOCKS Relay: SSH channel {ssh_channel.get_id()} found closed after recv.")
                            active_relay = False; break

                        if ssh_channel.recv_stderr_ready():
                            error_data = ssh_channel.recv_stderr(4096)
                            self.logger.warning(f"SOCKS Relay: SSH channel {ssh_channel.get_id()} stderr for {client_address_info}: {error_data.decode(errors='ignore')}")
                    except socket.error as e: # Error sending to client
                        self.logger.warning(f"SOCKS Relay: Socket error sending to client {client_address_info}: {e}")
                        active_relay = False; break

        except socket.error as e:
            if self.running and active_relay: # Only log if unexpected
                 self.logger.warning(f"SOCKS Relay: Socket error during relay for {client_address_info}: {e}")
        except Exception as e:
            if self.running and active_relay:
                self.logger.exception(f"SOCKS Relay: Unexpected error during relay for {client_address_info}: {e}")
        finally:
            self.logger.debug(f"SOCKS Relay: Ending data relay for {client_address_info} <=> SSH channel {ssh_channel.get_id()}. Active: {active_relay}, Running: {self.running}")
            if ssh_channel and not ssh_channel.closed:
                ssh_channel.close()
            # client_socket is closed by _handle_socks_client's finally block
            pass

    def _modify_sni_in_clienthello(self, client_hello_bytes, custom_sni_value, client_address_info):
        """
        Parses a TLS ClientHello byte string, modifies its SNI extension, and returns the modified bytes.
        Uses Scapy for parsing and building.

        Args:
            client_hello_bytes (bytes): The original ClientHello packet bytes.
            custom_sni_value (str): The custom SNI hostname to set.
            client_address_info (tuple): Client's address for logging.

        Returns:
            bytes: The modified ClientHello packet bytes, or the original bytes if modification fails
                   or SNI is not present. Returns None on critical parsing failure.
        """
        if not SCAPY_AVAILABLE or not self.custom_sni: # Should be checked before calling, but as a safeguard
            self.logger.debug(f"SOCKS: _modify_sni_called for {client_address_info} but Scapy unavailable or no custom_sni.")
            return client_hello_bytes

        try:
            tls_record = TLS(client_hello_bytes)

            if not tls_record.haslayer(TLSClientHello):
                self.logger.warning(f"SOCKS: Scapy parsed record from {client_address_info} as TLS, but no ClientHello layer found. Original len: {len(client_hello_bytes)}. Forwarding as is.")
                if self.logger.isEnabledFor(logging.DEBUG):
                    self.logger.debug(f"Record summary for {client_address_info}: {tls_record.summary()}")
                    if tls_record.msg and len(tls_record.msg) > 0:
                       self.logger.debug(f"Actual handshake type for {client_address_info}: {type(tls_record.msg[0])}")
                return client_hello_bytes

            client_hello_pkt = tls_record[TLSClientHello]
            modified = False

            if client_hello_pkt.extensions:
                for i, ext in enumerate(client_hello_pkt.extensions):
                    if ext.type == 0: # server_name (SNI)
                        original_sni_value = "NotDecoded"
                        try:
                            # Attempt to decode existing SNI for logging, handle potential errors
                            if ext.servernames and ext.servernames[0].data:
                                original_sni_value = ext.servernames[0].data.decode('utf-8', 'ignore')
                        except Exception:
                            pass # Ignore if decoding fails, will just log "NotDecoded"

                        self.logger.info(f"SOCKS: Found SNI '{original_sni_value}' for {client_address_info}. Modifying to '{custom_sni_value}'.")

                        # Create new ServerNameIndication data
                        sni_field_data = ServerNameIndicationHostName(servername=custom_sni_value.encode('utf-8'))
                        # Replace the entire SNI extension object
                        client_hello_pkt.extensions[i] = TLSExtServerNameIndication(servernames=[sni_field_data])

                        modified = True
                        break
                if not modified:
                     self.logger.debug(f"SOCKS: SNI extension field (type 0) not found in ClientHello from {client_address_info}, though other extensions might exist. SNI not modified.")
            else:
                self.logger.debug(f"SOCKS: No extensions field found in ClientHello from {client_address_info}. Cannot modify SNI.")

            if modified:
                self.logger.debug(f"SOCKS: Rebuilding TLS record for {client_address_info} after SNI modification.")
                modified_bytes = bytes(tls_record)
                self.logger.info(f"SOCKS: SNI modification successful for {client_address_info}. Original len: {len(client_hello_bytes)}, New len: {len(modified_bytes)}")
                return modified_bytes
            else:
                self.logger.debug(f"SOCKS: No SNI modification performed for {client_address_info}. Forwarding original ClientHello.")
                return client_hello_bytes

        except Exception as e:
            # Catching a broad exception here because Scapy can raise various things on malformed packets.
            self.logger.error(f"SOCKS: Scapy parsing/building error during SNI modification for {client_address_info}: {e}")
            if self.logger.isEnabledFor(logging.DEBUG):
                 self.logger.debug(f"Problematic ClientHello bytes for {client_address_info} (hex): {client_hello_bytes.hex() if client_hello_bytes else 'None'}")
            return client_hello_bytes # Return original on error

    def _relay_data(self, client_socket, ssh_channel, client_address_info):
        """
        Relays data between a SOCKS client and an SSH channel.

        Uses `select.select` for non-blocking I/O between the two sockets.
        Stops relaying if `self.running` becomes False or if either connection closes.

        Args:
            client_socket (socket.socket): The SOCKS client's socket.
            ssh_channel (paramiko.channel.Channel): The Paramiko SSH channel.
            client_address_info (tuple): Client's address (host, port) for logging.
        """
        self.logger.debug(f"SOCKS Relay: Starting data relay for {client_address_info} <=> SSH channel {ssh_channel.get_id()}")
        active_relay = True
        try:
            while self.running and active_relay and ssh_channel.active and not ssh_channel.closed:
                r, w, x = select.select([client_socket, ssh_channel], [], [client_socket, ssh_channel], 0.1)
                if not self.running: break

                if x: # Check for errors on sockets
                    self.logger.warning(f"SOCKS Relay: Socket error reported by select() for {client_address_info}. Ending relay.")
                    active_relay = False; break

                if client_socket in r:
                    try:
                        data = client_socket.recv(4096)
                        if not data:
                            self.logger.debug(f"SOCKS Relay: Client {client_address_info} closed connection.")
                            active_relay = False; break
                        ssh_channel.sendall(data)
                        self.logger.log(logging.getLevelName("TRACE") if hasattr(logging, "TRACE") else logging.DEBUG - 5,
                                        f"SOCKS Relay: C->S {len(data)} bytes for {client_address_info}")
                    except socket.error as e:
                        self.logger.warning(f"SOCKS Relay: Socket error receiving from client {client_address_info}: {e}")
                        active_relay = False; break

                if ssh_channel in r:
                    try:
                        if ssh_channel.recv_ready():
                            data = ssh_channel.recv(4096)
                            if not data:
                                self.logger.debug(f"SOCKS Relay: SSH channel {ssh_channel.get_id()} closed by remote.")
                                active_relay = False; break
                            client_socket.sendall(data)
                            self.logger.log(logging.getLevelName("TRACE") if hasattr(logging, "TRACE") else logging.DEBUG - 5,
                                            f"SOCKS Relay: S->C {len(data)} bytes for {client_address_info}")

                        if ssh_channel.closed: # Check again after recv
                            self.logger.debug(f"SOCKS Relay: SSH channel {ssh_channel.get_id()} found closed after recv.")
                            active_relay = False; break

                        if ssh_channel.recv_stderr_ready():
                            error_data = ssh_channel.recv_stderr(4096)
                            self.logger.warning(f"SOCKS Relay: SSH channel {ssh_channel.get_id()} stderr for {client_address_info}: {error_data.decode(errors='ignore')}")
                    except socket.error as e: # Error sending to client
                        self.logger.warning(f"SOCKS Relay: Socket error sending to client {client_address_info}: {e}")
                        active_relay = False; break

        except socket.error as e:
            if self.running and active_relay: # Only log if unexpected
                 self.logger.warning(f"SOCKS Relay: Socket error during relay for {client_address_info}: {e}")
        except Exception as e:
            if self.running and active_relay:
                self.logger.exception(f"SOCKS Relay: Unexpected error during relay for {client_address_info}: {e}")
        finally:
            self.logger.debug(f"SOCKS Relay: Ending data relay for {client_address_info} <=> SSH channel {ssh_channel.get_id()}. Active: {active_relay}, Running: {self.running}")
            if ssh_channel and not ssh_channel.closed:
                ssh_channel.close()
            # client_socket is closed by _handle_socks_client's finally block
            pass

if __name__ == '__main__':
    # Example Usage (replace with your actual SSH server details)
    # Note: For a real application, avoid hardcoding credentials.
    # Use environment variables, config files, or prompt the user.

    # Option 1: Password authentication
    # tunnel_password = SSHTunnel("your_server_ip", 22, "your_username", ssh_password="your_password")
    # if tunnel_password.connect():
    #     stdin, stdout, stderr = tunnel_password.execute_command("ls -l")
    #     if stdout:
    #         print("Command output:")
    #         print(stdout.read().decode())
    #     if stderr:
    #         error = stderr.read().decode()
    #         if error:
    #             print("Command error:")
    #             print(error)
    #     tunnel_password.disconnect()

    # Option 2: Key-based authentication
    # Make sure your private key is available and permissions are correct (e.g., chmod 600 your_key)
    # tunnel_key = SSHTunnel("your_server_ip", 22, "your_username", ssh_key_filepath="/path/to/your/private_key")
    # if tunnel_key.connect():
    #     stdin, stdout, stderr = tunnel_key.execute_command("pwd")
    #     if stdout:
    #         print("Command output:")
    #         print(stdout.read().decode())
    #     if stderr:
    #         error = stderr.read().decode()
    #         if error:
    #             print("Command error:")
    #             print(error)
    #     tunnel_key.disconnect()

    print("SSH Tunnel module. Run this with a main script or uncomment example usage.")
