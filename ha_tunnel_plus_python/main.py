from ssh_tunnel import SSHTunnel
import argparse
import getpass
import sys # For sys.exit()
import logging # Added
import time # Already present, but good to note for this section
import threading # Already present

# --- Logger Setup ---
logger = logging.getLogger("ha_tunnel_plus_python")
# Initial basic configuration. Can be refined.
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(name)s - %(module)s:%(lineno)d - %(message)s')


def main():
    """
    Main function to parse arguments, establish SSH tunnel, and start SOCKS proxy.
    Handles command-line arguments for SSH server details, authentication,
    and SOCKS proxy configuration. Manages the lifecycle of the SSH connection
    and the SOCKS proxy server thread.
    """
    parser = argparse.ArgumentParser(description="HA Tunnel Plus Python - SOCKS Proxy over SSH.")
    parser.add_argument("--server", required=True, help="SSH server hostname or IP address.")
    parser.add_argument("--port", type=int, default=22, help="SSH server port (default: 22).")
    parser.add_argument("--user", required=True, help="SSH username.")
    parser.add_argument("--password", help="SSH password. If not provided and key is not used, will prompt.")
    parser.add_argument("--key", help="Path to SSH private key file for key-based authentication.")

    parser.add_argument("--socks-host", default="127.0.0.1", help="Local host for SOCKS proxy (default: 127.0.0.1).")
    parser.add_argument("--socks-port", type=int, default=1080, help="Local port for SOCKS proxy (default: 1080).")

    parser.add_argument("--spoof-sni", help="Hostname to use as the SNI value for all TLS connections (if SNI modification is possible).")

    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging (currently basic).")

    args = parser.parse_args()

    if args.spoof_sni and not SCAPY_AVAILABLE:
        logger.warning("Scapy is not available, --spoof-sni functionality will be disabled.")
        # No need to nullify args.spoof_sni here, SSHTunnel init will handle it.

    # Handle verbosity
    if args.verbose:
        logger.setLevel(logging.DEBUG)
        logger.debug("Verbose mode enabled by CLI argument.")
    else:
        logger.setLevel(logging.INFO)

    logger.info("HA Tunnel Plus Python - SOCKS Proxy over SSH - Starting")

    ssh_password = args.password
    if not args.key and not ssh_password: # If no key and no password arg, prompt
        try:
            ssh_password = getpass.getpass(f"Enter SSH password for {args.user}@{args.server}: ")
        except KeyboardInterrupt:
            logger.info("Password entry cancelled by user. Exiting.")
            sys.exit(0)
        except EOFError: # Happens if stdin is not a tty (e.g. piped input)
            logger.error("Password entry aborted (EOF). Cannot prompt for password without a TTY. Provide --password or --key.")
            sys.exit(1)


    # --- Initialize and Connect ---
    # Pass the logger instance and custom_sni to the tunnel
    tunnel_params = {
        "ssh_server": args.server,
        "ssh_port": args.port,
        "ssh_username": args.user,
        "logger": logger,
        "custom_sni": args.spoof_sni # Pass the custom SNI value
    }
    if args.key:
        logger.info(f"Attempting SSH connection to {args.user}@{args.server}:{args.port} using key {args.key}...")
        tunnel_params["ssh_key_filepath"] = args.key
    elif ssh_password:
        logger.info(f"Attempting SSH connection to {args.user}@{args.server}:{args.port} using password...")
        tunnel_params["ssh_password"] = ssh_password
    else:
        logger.info(f"Attempting SSH connection to {args.user}@{args.server}:{args.port} (e.g., using SSH Agent or no auth)...")
        # No specific auth param needed if relying on agent or no auth

    tunnel = SSHTunnel(**tunnel_params)

    if not tunnel.connect():
        # Specific error messages are now logged within tunnel.connect()
        logger.critical("Failed to establish SSH connection. Please check logs for details. Exiting.")
        return

    logger.info(f"Successfully connected to SSH server: {args.server} as {args.user}.")

    # --- Basic Test: Execute a command ---
    logger.debug("Testing command execution (will run before SOCKS proxy starts)...")
    stdin, stdout, stderr = tunnel.execute_command("echo 'Hello from SSH server before SOCKS!'")

    if stdout:
        output = stdout.read().decode().strip()
        if output: logger.debug(f"Test command output from server: {output}")

    error_output = stderr.read().decode().strip()
    if error_output:
        logger.warning(f"Test command error from server: {error_output}")

    # --- Start SOCKS Proxy ---
    logger.info("Starting SOCKS5 proxy...")
    # We need to run the SOCKS proxy in a separate thread
    # so the main thread doesn't block and can handle shutdown.
    # Ensure SSHTunnel has self.running defined before starting thread.
    # It's typically set in start_socks_proxy, but good practice to ensure.
    tunnel.running = False # Will be set to True in start_socks_proxy by the thread

    socks_thread = threading.Thread(
        target=tunnel.start_socks_proxy,
        args=(args.socks_host, args.socks_port)
    )
    socks_thread.daemon = True
    socks_thread.start()

    # Give the SOCKS server a moment to try to start.
    # Successful startup is usually indicated by tunnel.running being True.
    time.sleep(0.5)

    if not tunnel.running: # Check if SOCKS proxy actually started (binds and listens)
        logger.critical(f"SOCKS proxy failed to start on {args.socks_host}:{args.socks_port}. Check other logs. Exiting.")
        if tunnel.client and tunnel.client.get_transport() and tunnel.client.get_transport().is_active():
            tunnel.disconnect()
        sys.exit(1) # Exit if SOCKS proxy couldn't start

    logger.info(f"SOCKS5 proxy should be running on {args.socks_host}:{args.socks_port}")
    logger.info("Configure your browser or application to use this SOCKS proxy.")
    logger.info(f"SOCKS Host: {args.socks_host}, Port: {args.socks_port} (SOCKS5)")
    logger.info("Press Ctrl+C to stop the tunnel and proxy.")

    try:
        while True:
            if not tunnel.running: # If SOCKS proxy stopped for some reason
                 logger.info("SOCKS proxy is no longer running. Shutting down main thread.")
                 break
            if not socks_thread.is_alive(): # If thread died
                logger.error("SOCKS proxy thread seems to have died unexpectedly. Shutting down.")
                tunnel.running = False # Ensure it's marked as not running
                break
            if not tunnel.is_ssh_connected(): # Check if SSH connection is still alive
                logger.error("SSH connection lost. Shutting down SOCKS proxy and application.")
                tunnel.running = False # Signal SOCKS proxy to stop
                break
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Ctrl+C received. Shutting down...")
    except Exception as e:
        logger.exception(f"Unexpected error in main loop: {e}. Shutting down.") # Log stack trace
    finally:
        logger.info("Initiating shutdown sequence...")
        if hasattr(tunnel, 'running') and tunnel.running: # Check if it was ever set to True
            logger.info("Stopping SOCKS proxy...")
            tunnel.stop_socks_proxy() # This sets tunnel.running to False
            if socks_thread.is_alive():
                logger.debug("Waiting for SOCKS proxy thread to join...")
                socks_thread.join(timeout=5)
                if socks_thread.is_alive():
                    logger.warning("SOCKS proxy thread did not stop in time.")

        if tunnel.is_ssh_connected():
            logger.info("Disconnecting SSH tunnel...")
            tunnel.disconnect()
        logger.info("Application finished.")

# Need to add these imports at the top of main.py
import time
import threading

if __name__ == "__main__":
    # Before running, ensure you have the paramiko library installed:
    # pip install paramiko
    # And replace placeholder SSH credentials in this script.

    # Note: You will need a running SSH server that you have access to.
    # If SSH_SERVER_IP is "your_ssh_server_ip_or_hostname", this script will fail
    # until you provide valid server details.

    # Check for default credentials (modified to be more specific)
    default_ip = "your_ssh_server_ip_or_hostname"
    default_user = "your_ssh_username"
    default_pass = "your_ssh_password" # Assuming None is not the default you'd use for actual password
    default_key = "/path/to/your/id_rsa" # Assuming None is not the default you'd use for actual key path

    using_default_creds = False
    if SSH_SERVER_IP == default_ip or SSH_USERNAME == default_user:
        using_default_creds = True
    if SSH_PASSWORD is not None and SSH_PASSWORD == default_pass: # Check if SSH_PASSWORD is not None before comparing
        using_default_creds = True
    if SSH_KEY_FILEPATH is not None and SSH_KEY_FILEPATH == default_key: # Check if SSH_KEY_FILEPATH is not None
        using_default_creds = True

    if using_default_creds:
        print("*"*60)
        print("WARNING: Default SSH credentials are still in use.")
        print("Please update SSH_SERVER_IP, SSH_USERNAME, and either SSH_PASSWORD or SSH_KEY_FILEPATH in main.py")
        print("with your actual SSH server details before running.")
        print("*"*50)
    else:
        main()
