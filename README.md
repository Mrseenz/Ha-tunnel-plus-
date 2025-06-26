HA Tunnel Plus is a free VPN (Virtual Private Network) application for devices developed by Art Of Tunnel. It uses SSH tunneling to create a secure connection, routing your internet traffic through a proxy server to protect your privacy and enhance security while browsing. It allows users to customize their connection with various protocols and settings, including SNI (Server Name Indication) for bypassing restrictions imposed by internet providers. 
Here's a more detailed breakdown:
Functionality:
HA Tunnel Plus acts as a VPN, encrypting your internet traffic and routing it through a secure tunnel, making it harder for others to track your online activity. 
SSH Tunneling:
It utilizes SSH (Secure Shell) protocol, specifically SSH2.0, to establish a secure connection between your device and a remote server. 
Customization:
The app allows for customization of the connection, including the ability to choose different protocols (TCP, UDP, ICMP, IGMP) and configure SNI settings. 
Security:
It encrypts all traffic between the client and the server, enhancing security and privacy.

---

## HA Tunnel Plus - Python Implementation (Proof of Concept)

This project is a Python-based proof-of-concept inspired by HA Tunnel Plus, aiming to provide similar SOCKS proxy functionality over an SSH tunnel. It allows you to route your TCP traffic through an SSH server, effectively acting as a SOCKS5 proxy.

**Current Features:**

*   Establishes an SSH connection to a specified server using username/password or key-based authentication.
*   Runs a local SOCKS5 proxy server.
*   Forwards TCP traffic from applications configured to use the local SOCKS proxy through the SSH tunnel.
*   Basic command-line interface for configuration.
*   **SNI (Server Name Indication) Customization:** Allows spoofing the SNI in TLS handshakes.
*   Logging for operational messages and errors.
*   Basic unit tests for core SSH functionality and SNI modification logic.

**Functionality Breakdown:**

1.  **SSH Connection (`ssh_tunnel.py`):**
    *   Uses the `paramiko` library to manage SSH connections.
    *   Supports password, public key, and SSH agent-based authentication.
2.  **SOCKS5 Proxy (`ssh_tunnel.py`):**
    *   Implements a basic SOCKS5 server that listens on a local port (e.g., `127.0.0.1:1080`).
    *   Handles the SOCKS5 handshake (NO AUTHENTICATION method) and the `CONNECT` command for TCP.
    *   For each `CONNECT` request, it opens a `direct-tcpip` channel through the established SSH connection to the target host and port.
    *   Relays data between the client application and the remote target via the SSH channel.
3.  **CLI (`main.py`):**
    *   Provides a command-line interface using `argparse` to specify:
        *   SSH server details (host, port, user).
        *   Authentication method (password, key file).
        *   Local SOCKS proxy host and port.
        *   Verbose logging option.
    *   Custom SNI value for spoofing.
4.  **SNI Customization (`ssh_tunnel.py`):**
    *   If a custom SNI value is provided and `scapy` is installed:
        *   The SOCKS proxy attempts to peek at the initial data of outgoing TCP connections.
        *   If the data appears to be a TLS ClientHello message, it's parsed using Scapy.
        *   The SNI field in the ClientHello is replaced with the custom SNI value.
        *   The modified ClientHello is then sent through the SSH tunnel.
        *   If Scapy is not available or parsing/modification fails, the original data is forwarded.

**Installation:**

1.  **Clone the repository (if applicable) or download the source files.**
2.  **Install dependencies:**
    *   **Core:** `paramiko` is required for SSH functionality.
        ```bash
        pip install paramiko
        ```
    *   **For SNI Customization:** `scapy` is required. If you intend to use the SNI spoofing feature, install Scapy (which might also need `cryptography` or other dependencies depending on your system for full TLS support).
        ```bash
        pip install scapy
        # or potentially: pip install scapy[tls]
        ```
        If Scapy is not installed, SNI customization will be disabled (a warning will be logged if you try to use the feature).

**Usage:**

Run the `main.py` script from the `ha_tunnel_plus_python` directory with the required arguments.

**Required Arguments:**

*   `--server SSH_SERVER_IP_OR_HOSTNAME`: Your SSH server's address.
*   `--user SSH_USERNAME`: Your username on the SSH server.

**Optional Arguments for Authentication:**

*   `--password SSH_PASSWORD`: Your SSH password. If not provided and `--key` is not used, you will be prompted.
*   `--key /path/to/your/private_key`: Path to your SSH private key file.

**Optional Arguments for SOCKS Proxy:**

*   `--socks-host LOCAL_SOCKS_HOST`: The local IP address for the SOCKS proxy to listen on (default: `127.0.0.1`).
*   `--socks-port LOCAL_SOCKS_PORT`: The local port for the SOCKS proxy (default: `1080`).

**Other Optional Arguments:**

*   `--port SSH_PORT`: The SSH server port (default: `22`).
*   `--spoof-sni SPOOFED_HOSTNAME`: The hostname to use as the SNI value for all outgoing TLS connections. Requires Scapy to be installed.
*   `-v`, `--verbose`: Enable verbose debug logging.

**Example Usage:**

1.  **Using Key-Based Authentication:**
    ```bash
    python ha_tunnel_plus_python/main.py --server your.ssh.server.com --user myuser --key ~/.ssh/id_rsa
    ```

2.  **Using Password Authentication (will prompt for password):**
    ```bash
    python ha_tunnel_plus_python/main.py --server your.ssh.server.com --user myuser
    ```

3.  **Specifying SOCKS proxy port and enabling verbose logging:**
    ```bash
    python ha_tunnel_plus_python/main.py --server your.ssh.server.com --user myuser --socks-port 11080 -v
    ```
4.  **Using SNI Spoofing:**
    ```bash
    # Make sure scapy is installed: pip install scapy
    python ha_tunnel_plus_python/main.py --server your.ssh.server.com --user myuser --key ~/.ssh/id_rsa --spoof-sni fake.domain.com
    ```
    When connecting to an HTTPS site via the proxy, the TLS SNI will be set to `fake.domain.com`.

After running, configure your application (e.g., web browser, FTP client) to use the SOCKS5 proxy at the specified local host and port (e.g., `127.0.0.1:1080`).

**Running Tests:**

Unit tests are located in the `ha_tunnel_plus_python/tests` directory. To run them, navigate to the project's root directory (the one containing the `ha_tunnel_plus_python` folder) and execute:

```bash
python -m unittest discover ha_tunnel_plus_python
```
or
```bash
python -m unittest ha_tunnel_plus_python.tests.test_ssh_tunnel
```

**Current Limitations & Future Scope:**

*   **SOCKS5 Features:** Only supports the `CONNECT` command for TCP. `BIND` and `UDP ASSOCIATE` are not implemented. Authentication for the SOCKS proxy itself (client to SOCKS proxy) is not implemented (defaults to "NO AUTHENTICATION REQUIRED").
*   **SNI Customization:** Implemented for outgoing TLS connections via the SOCKS proxy. Requires `scapy`. Currently supports a global SNI override. Does not add an SNI extension if one is not already present in the original ClientHello.
*   **Other Protocols (UDP, ICMP, IGMP):** The current SOCKS-based approach primarily targets TCP. Tunneling UDP effectively over SSH is complex, and ICMP/IGMP would likely require a TUN/TAP based architecture, which is a significant departure.
*   **Error Handling:** While improved, it can be made more robust, especially for diverse network conditions, SOCKS client behaviors, and Scapy parsing edge cases.
*   **GUI:** No graphical user interface is provided.
*   **Configuration Files:** Does not currently support loading configurations from a file.
*   **Packaging:** Not set up as an installable Python package.

This project serves as a foundational exploration of creating an SSH tunnel with SOCKS proxy capabilities in Python.
