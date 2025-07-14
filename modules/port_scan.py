import socket
import threading
import queue
import sys
import ipaddress # For validating IP addresses if domain resolves to multiple IPs

# Queue to hold ports to be scanned
port_queue = queue.Queue()
# List to store open ports found
open_ports = []
# Lock for thread-safe access to open_ports list
open_ports_lock = threading.Lock()

def check_port(target_host, port, timeout=1):
    """
    Attempts to establish a TCP connection to a specific port on the target host.
    Returns True if the port is open, False otherwise.
    """
    try:
        # Create a socket object for IPv4 TCP connection
        # AF_INET for IPv4, SOCK_STREAM for TCP
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Set a timeout for the connection attempt
        sock.settimeout(timeout)
        # Attempt to connect to the target host and port
        result = sock.connect_ex((target_host, port)) # connect_ex returns an error indicator

        if result == 0: # 0 means success (connection established)
            return True
        else:
            return False
    except socket.error as e:
        # Catch socket-related errors (e.g., host unreachable, network down)
        # print(f"Socket error checking {target_host}:{port}: {e}", file=sys.stderr)
        return False
    except Exception as e:
        # Catch any other unexpected errors
        # print(f"An unexpected error occurred checking {target_host}:{port}: {e}", file=sys.stderr)
        return False
    finally:
        # Ensure the socket is closed even if an error occurs
        if 'sock' in locals() and sock:
            sock.close()

def worker(target_host):
    """
    Worker thread function that continuously gets ports from the queue
    and checks them until the queue is empty.
    """
    while True:
        try:
            # Get a port from the queue. block=False would raise queue.Empty if empty.
            # We want to block until a port is available or the queue is explicitly joined.
            port = port_queue.get()
            
            if check_port(target_host, port):
                with open_ports_lock: # Acquire lock before modifying shared list
                    open_ports.append(port)
            
            # Mark the task as done, regardless of success or failure
            port_queue.task_done()
        except queue.Empty:
            # This should ideally not happen if using join() correctly, but good for safety
            break
        except Exception as e:
            # Log any unexpected errors in the worker thread
            print(f"Error in worker thread for {target_host}: {e}", file=sys.stderr)
            port_queue.task_done() # Still mark task as done to prevent deadlock

def scan_ports(target_domain, port_range, num_threads=50, scan_timeout=1):
    """
    Orchestrates the multi-threaded port scan.

    Args:
        target_domain (str): The domain name or IP address to scan.
        port_range (tuple): A tuple (start_port, end_port) representing the range to scan.
        num_threads (int): The number of concurrent threads to use for scanning.
        scan_timeout (int): Timeout in seconds for each individual port connection attempt.

    Returns:
        list: A sorted list of open ports found.
    """
    global open_ports # Declare intent to modify the global list
    open_ports = [] # Reset open_ports for a new scan

    print(f"[*] Resolving IP address for {target_domain}...")
    target_ip = None
    try:
        # Resolve the domain name to an IP address
        # gethostbyname is simpler but only returns one IPv4.
        # getaddrinfo is more robust for multiple IPs/IPv6, but for simple connect, one IP is fine.
        # For simplicity, we'll stick to gethostbyname and assume IPv4 for socket.AF_INET.
        # If gethostbyname fails, it raises socket.gaierror.
        target_ip = socket.gethostbyname(target_domain)
        print(f"[*] {target_domain} resolved to {target_ip}")
    except socket.gaierror as e:
        print(f"[!] Could not resolve host '{target_domain}': {e}", file=sys.stderr)
        return []
    except Exception as e:
        print(f"[!] An unexpected error occurred during host resolution for {target_domain}: {e}", file=sys.stderr)
        return []

    if not target_ip:
        return []

    start_port, end_port = port_range
    print(f"[*] Starting port scan on {target_ip} for ports {start_port}-{end_port} with {num_threads} threads...")

    # Populate the queue with ports to scan
    for port in range(start_port, end_port + 1):
        port_queue.put(port)

    # Create and start worker threads
    threads = []
    for _ in range(num_threads):
        thread = threading.Thread(target=worker, args=(target_ip,), daemon=True) # daemon=True allows main to exit even if threads are stuck
        thread.start()
        threads.append(thread)

    # Wait for all tasks in the queue to be processed
    port_queue.join()

    # All tasks are done, so all ports have been checked.
    # The threads are daemon threads, so they will exit when the main program exits.

    print(f"[*] Port scan complete for {target_ip}.")
    return sorted(open_ports)

if __name__ == "__main__":
    # This block is for testing the module independently
    print("--- Testing scan_ports module ---")
    # Test a common domain like scanme.nmap.org (designed for scanning)
    # Be respectful and do not scan random public IPs/domains without permission.
    test_target = "scanme.nmap.org"
    test_port_range = (20, 100) # Scan a small range for quick testing

    print(f"Attempting to scan {test_target} on ports {test_port_range[0]}-{test_port_range[1]}...")
    found_open_ports = scan_ports(test_target, test_port_range, num_threads=50, scan_timeout=0.5)

    if found_open_ports:
        print(f"\nFound {len(found_open_ports)} open ports on {test_target}:")
        for port in found_open_ports:
            print(f"  - {port}/tcp")
    else:
        print(f"\nNo open ports found on {test_target} in the range {test_port_range[0]}-{test_port_range[1]} or an error occurred.")
    print("--- Test Complete ---")
