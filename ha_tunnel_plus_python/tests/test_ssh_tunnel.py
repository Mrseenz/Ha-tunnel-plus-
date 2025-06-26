import unittest
from unittest.mock import patch, MagicMock, mock_open
import logging
import socket
import struct # For SOCKS tests if any

# Assuming ssh_tunnel.py is in the parent directory or PYTHONPATH is set up
from ha_tunnel_plus_python.ssh_tunnel import SSHTunnel
import paramiko # For exceptions

# Disable logging for tests unless specifically needed for debugging a test
logging.disable(logging.CRITICAL) # Disable all logging output during tests

class TestSSHTunnel(unittest.TestCase):
    """
    Unit tests for the SSHTunnel class.
    Mocks external dependencies like paramiko and sockets to test
    connection logic, SOCKS proxy setup, and error handling.
    """

    def setUp(self):
        """Set up common test variables and a null logger."""
        # Basic logger for tests, can be overridden if a test needs specific log checks
        self.logger = logging.getLogger("test_ssh_tunnel")
        self.logger.addHandler(logging.NullHandler()) # Ensure no output from logger during tests

        self.ssh_server = "dummy.server.com"
        self.ssh_port = 22
        self.ssh_user = "testuser"
        self.ssh_pass = "testpass"
        self.ssh_key_file = "/fake/path/to/key"

    @patch('ha_tunnel_plus_python.ssh_tunnel.paramiko.SSHClient')
    def test_connect_password_success(self, MockSSHClient):
        mock_client_instance = MockSSHClient.return_value
        mock_client_instance.get_transport.return_value.is_active.return_value = True

        tunnel = SSHTunnel(self.ssh_server, self.ssh_port, self.ssh_user, ssh_password=self.ssh_pass, logger=self.logger)
        self.assertTrue(tunnel.connect())
        mock_client_instance.set_missing_host_key_policy.assert_called_with(paramiko.AutoAddPolicy())
        mock_client_instance.connect.assert_called_with(
            self.ssh_server,
            port=self.ssh_port,
            username=self.ssh_user,
            password=self.ssh_pass,
            timeout=10
        )
        self.assertTrue(tunnel.is_ssh_connected())

    @patch('ha_tunnel_plus_python.ssh_tunnel.paramiko.SSHClient')
    @patch('ha_tunnel_plus_python.ssh_tunnel.paramiko.PKey.from_private_key_file')
    def test_connect_key_success(self, MockPKeyFromFile, MockSSHClient):
        mock_client_instance = MockSSHClient.return_value
        mock_pkey_instance = MockPKeyFromFile.return_value
        mock_client_instance.get_transport.return_value.is_active.return_value = True

        tunnel = SSHTunnel(self.ssh_server, self.ssh_port, self.ssh_user, ssh_key_filepath=self.ssh_key_file, logger=self.logger)
        self.assertTrue(tunnel.connect())
        MockPKeyFromFile.assert_called_with(self.ssh_key_file)
        mock_client_instance.connect.assert_called_with(
            self.ssh_server,
            port=self.ssh_port,
            username=self.ssh_user,
            pkey=mock_pkey_instance,
            timeout=10
        )
        self.assertTrue(tunnel.is_ssh_connected())

    @patch('ha_tunnel_plus_python.ssh_tunnel.paramiko.SSHClient')
    def test_connect_authentication_failure(self, MockSSHClient):
        mock_client_instance = MockSSHClient.return_value
        mock_client_instance.connect.side_effect = paramiko.AuthenticationException("Auth failed")

        tunnel = SSHTunnel(self.ssh_server, self.ssh_port, self.ssh_user, ssh_password=self.ssh_pass, logger=self.logger)
        self.assertFalse(tunnel.connect())
        self.assertFalse(tunnel.is_ssh_connected())

    @patch('ha_tunnel_plus_python.ssh_tunnel.paramiko.SSHClient')
    def test_connect_ssh_exception(self, MockSSHClient):
        mock_client_instance = MockSSHClient.return_value
        mock_client_instance.connect.side_effect = paramiko.SSHException("Connection error")

        tunnel = SSHTunnel(self.ssh_server, self.ssh_port, self.ssh_user, ssh_password=self.ssh_pass, logger=self.logger)
        self.assertFalse(tunnel.connect())
        self.assertFalse(tunnel.is_ssh_connected())

    @patch('ha_tunnel_plus_python.ssh_tunnel.paramiko.SSHClient')
    def test_connect_socket_timeout(self, MockSSHClient):
        mock_client_instance = MockSSHClient.return_value
        mock_client_instance.connect.side_effect = socket.timeout("Connection timed out")

        tunnel = SSHTunnel(self.ssh_server, self.ssh_port, self.ssh_user, ssh_password=self.ssh_pass, logger=self.logger)
        self.assertFalse(tunnel.connect())
        self.assertFalse(tunnel.is_ssh_connected())

    @patch('ha_tunnel_plus_python.ssh_tunnel.paramiko.SSHClient')
    @patch('ha_tunnel_plus_python.ssh_tunnel.paramiko.PKey.from_private_key_file')
    def test_connect_key_file_not_found(self, MockPKeyFromFile, MockSSHClient):
        MockPKeyFromFile.side_effect = FileNotFoundError("Key file not found")

        tunnel = SSHTunnel(self.ssh_server, self.ssh_port, self.ssh_user, ssh_key_filepath=self.ssh_key_file, logger=self.logger)
        self.assertFalse(tunnel.connect())
        self.assertFalse(tunnel.is_ssh_connected())
        # Check that SSHClient.connect was not called because key loading failed first
        MockSSHClient.return_value.connect.assert_not_called()

    @patch('ha_tunnel_plus_python.ssh_tunnel.paramiko.SSHClient')
    @patch('ha_tunnel_plus_python.ssh_tunnel.paramiko.PKey.from_private_key_file')
    def test_connect_key_password_required(self, MockPKeyFromFile, MockSSHClient):
        MockPKeyFromFile.side_effect = paramiko.PasswordRequiredException("Key is encrypted")

        tunnel = SSHTunnel(self.ssh_server, self.ssh_port, self.ssh_user, ssh_key_filepath=self.ssh_key_file, logger=self.logger)
        self.assertFalse(tunnel.connect())
        self.assertFalse(tunnel.is_ssh_connected())
        MockSSHClient.return_value.connect.assert_not_called()


    @patch('ha_tunnel_plus_python.ssh_tunnel.paramiko.SSHClient')
    def test_disconnect_when_connected(self, MockSSHClient):
        mock_client_instance = MockSSHClient.return_value
        mock_client_instance.get_transport.return_value.is_active.return_value = True # Simulate connected state initially

        tunnel = SSHTunnel(self.ssh_server, self.ssh_port, self.ssh_user, ssh_password=self.ssh_pass, logger=self.logger)
        tunnel.client = mock_client_instance # Manually set client for this test

        tunnel.disconnect()
        mock_client_instance.close.assert_called_once()
        self.assertIsNone(tunnel.client) # Check if client is reset

    def test_disconnect_when_not_connected(self):
        tunnel = SSHTunnel(self.ssh_server, self.ssh_port, self.ssh_user, logger=self.logger)
        # No mock SSHClient needed as tunnel.client is None initially
        # We just want to ensure it doesn't crash
        tunnel.disconnect()
        self.assertIsNone(tunnel.client)


    @patch('ha_tunnel_plus_python.ssh_tunnel.paramiko.SSHClient')
    def test_execute_command_success(self, MockSSHClient):
        mock_client_instance = MockSSHClient.return_value
        mock_client_instance.get_transport.return_value.is_active.return_value = True

        mock_stdin = MagicMock()
        mock_stdout = MagicMock()
        mock_stderr = MagicMock()
        mock_client_instance.exec_command.return_value = (mock_stdin, mock_stdout, mock_stderr)

        tunnel = SSHTunnel(self.ssh_server, self.ssh_port, self.ssh_user, logger=self.logger)
        tunnel.client = mock_client_instance # Assume connected

        cmd = "ls -l"
        stdin, stdout, stderr = tunnel.execute_command(cmd)

        mock_client_instance.exec_command.assert_called_with(cmd, timeout=10)
        self.assertEqual(stdin, mock_stdin)
        self.assertEqual(stdout, mock_stdout)
        self.assertEqual(stderr, mock_stderr)

    @patch('ha_tunnel_plus_python.ssh_tunnel.paramiko.SSHClient')
    def test_execute_command_not_connected(self, MockSSHClient):
        # Ensure get_transport() is None or is_active() is False
        mock_client_instance = MockSSHClient.return_value
        mock_client_instance.get_transport.return_value = None # Simulate not connected

        tunnel = SSHTunnel(self.ssh_server, self.ssh_port, self.ssh_user, logger=self.logger)
        # tunnel.client is None or not active
        if tunnel.client: # If SSHTunnel constructor created one
             tunnel.client.get_transport.return_value.is_active.return_value = False
        else: # If constructor didn't assign (e.g. if connect wasn't called)
            tunnel.client = mock_client_instance # to have a client to check is_active on
            mock_client_instance.get_transport.return_value.is_active.return_value = False


        stdin, stdout, stderr = tunnel.execute_command("ls -l")

        self.assertIsNone(stdin)
        self.assertIsNone(stdout)
        self.assertIsNone(stderr)
        mock_client_instance.exec_command.assert_not_called()

    # --- SOCKS Proxy Related Tests (very basic, mostly for structure) ---
    # Full SOCKS proxy testing is complex and would require mocking socket interactions heavily
    # or setting up a mock client/server.

    @patch('ha_tunnel_plus_python.ssh_tunnel.socket.socket')
    @patch('ha_tunnel_plus_python.ssh_tunnel.paramiko.SSHClient') # To ensure SSH connection is mocked
    def test_start_socks_proxy_bind_failure(self, MockSSHClient, MockSocket):
        # Simulate SSH connection success
        mock_ssh_client_instance = MockSSHClient.return_value
        mock_ssh_client_instance.get_transport.return_value.is_active.return_value = True

        mock_socket_instance = MockSocket.return_value
        mock_socket_instance.bind.side_effect = socket.error("Port already in use")

        tunnel = SSHTunnel(self.ssh_server, self.ssh_port, self.ssh_user, logger=self.logger)
        tunnel.client = mock_ssh_client_instance # Assume connected

        # This method normally runs a loop in a thread; we are testing the setup part.
        # For a unit test, we might not call start_socks_proxy directly if it starts a thread,
        # or we'd need to control the thread. Here, we're checking the initial setup.
        tunnel.start_socks_proxy('127.0.0.1', 1080)

        self.assertFalse(tunnel.running) # Should be false if bind failed
        mock_socket_instance.bind.assert_called_once()
        mock_socket_instance.listen.assert_not_called()


    @patch('ha_tunnel_plus_python.ssh_tunnel.socket.socket')
    @patch('ha_tunnel_plus_python.ssh_tunnel.paramiko.SSHClient')
    def test_start_socks_proxy_ssh_not_connected(self, MockSSHClient, MockSocket):
        mock_ssh_client_instance = MockSSHClient.return_value
        mock_ssh_client_instance.get_transport.return_value.is_active.return_value = False # SSH not connected

        tunnel = SSHTunnel(self.ssh_server, self.ssh_port, self.ssh_user, logger=self.logger)
        tunnel.client = mock_ssh_client_instance

        tunnel.start_socks_proxy('127.0.0.1', 1080)

        self.assertFalse(tunnel.running)
        MockSocket.return_value.bind.assert_not_called() # Socket operations should not occur

    # A very simplified test for SOCKS client handling (CONNECT part)
    # This would need much more extensive mocking for real SOCKS protocol logic.
    @patch('ha_tunnel_plus_python.ssh_tunnel.SSHTunnel._relay_data') # Mock the relay part
    @patch('ha_tunnel_plus_python.ssh_tunnel.paramiko.SSHClient')
    def test_handle_socks_client_connect_basic(self, MockSSHClient, mock_relay_data):
        # Setup SSH Client mock
        mock_ssh_transport = MagicMock()
        mock_ssh_channel = MagicMock()
        mock_ssh_transport.open_channel.return_value = mock_ssh_channel

        mock_ssh_client_instance = MockSSHClient.return_value
        mock_ssh_client_instance.get_transport.return_value = mock_ssh_transport
        mock_ssh_client_instance.get_transport.return_value.is_active.return_value = True

        tunnel = SSHTunnel(self.ssh_server, self.ssh_port, self.ssh_user, logger=self.logger)
        tunnel.client = mock_ssh_client_instance
        tunnel.running = True # Assume proxy is running

        mock_client_socket = MagicMock(spec=socket.socket)

        # SOCKS5 handshake: version + nmethods (1 method)
        # Method: 0x00 (no auth)
        handshake_part1 = struct.pack('!BB', 5, 1) + struct.pack('!B', 0)
        # SOCKS5 request: VER, CMD(CONNECT), RSV, ATYP(IPv4), DST.ADDR, DST.PORT
        # Target: 1.2.3.4:80
        target_ip_bytes = socket.inet_aton("1.2.3.4")
        target_port_bytes = struct.pack('!H', 80)
        request_part = struct.pack('!BBBB', 5, 1, 0, 1) + target_ip_bytes + target_port_bytes

        mock_client_socket.recv.side_effect = [
            handshake_part1[:2], # VER, NMETHODS
            handshake_part1[2:], # METHODS
            request_part[:4],    # VER, CMD, RSV, ATYP
            target_ip_bytes,     # DST.ADDR (IPv4)
            target_port_bytes    # DST.PORT
        ]

        client_address = ('127.0.0.1', 12345)
        tunnel._handle_socks_client(mock_client_socket, client_address)

        # Check NO AUTH response
        mock_client_socket.sendall.assert_any_call(struct.pack('!BB', 5, 0x00))

        # Check SSH channel open call
        mock_ssh_transport.open_channel.assert_called_with(
            'direct-tcpip',
            ("1.2.3.4", 80),
            client_address,
            timeout=10
        )

        # Check SOCKS CONNECT success reply
        # VER(5), REP(0=success), RSV(0), ATYP(1=IPv4), BND.ADDR(0.0.0.0), BND.PORT(0)
        expected_success_reply = b'\x05\x00\x00\x01' + socket.inet_aton('0.0.0.0') + struct.pack('!H', 0)
        mock_client_socket.sendall.assert_any_call(expected_success_reply)

        # Check if relay_data was called
        mock_relay_data.assert_called_with(mock_client_socket, mock_ssh_channel, client_address)
        mock_client_socket.close.assert_called_once()


if __name__ == '__main__':
    unittest.main()

# To run these tests:
# Ensure you are in the directory containing `ha_tunnel_plus_python`
# Then run: python -m unittest discover ha_tunnel_plus_python
# Or: python -m unittest ha_tunnel_plus_python.tests.test_ssh_tunnel
# (PYTHONPATH might need to include the parent directory of ha_tunnel_plus_python
#  if running from elsewhere, or if ha_tunnel_plus_python is not installed as a package)
# Example: PYTHONPATH=$PYTHONPATH:. python -m unittest ha_tunnel_plus_python.tests.test_ssh_tunnel
