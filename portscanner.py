import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

def scan_port(ip, port):
    """Scan a single port and return the result as a dictionary."""
    result_dict = {}
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex((ip, port))
            if result == 0:
                service = socket.getservbyport(port, 'tcp') if port <= 1024 else 'Unknown service'
                result_dict[port] = f"Port {port}: OPEN (Service: {service})"
            elif result == 10061:
                result_dict[port] = f"Port {port}: CLOSED"
            else:
                result_dict[port] = f"Port {port}: FILTERED"
    except Exception as e:
        result_dict[port] = f"Error scanning port {port}: {e}"
    return result_dict

def main():
    ip = input("Enter IP address to scan: ")
    start_port = int(input("Enter start port: "))
    end_port = int(input("Enter end port: "))
    
    results = {}
    start_time = time.time()

    # Use ThreadPoolExecutor to manage threading
    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = [executor.submit(scan_port, ip, port) for port in range(start_port, end_port + 1)]
        for future in as_completed(futures):
            results.update(future.result())

    end_time = time.time()
    scan_duration = end_time - start_time

    # Print scan report
    print(f"Scan Report for {ip}")
    print(f"Scan Start Time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(start_time))}")
    print(f"Scan End Time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(end_time))}")
    print(f"Scan Duration: {scan_duration:.2f} seconds\n")

    for port in sorted(results.keys()):
        print(results[port])

if __name__ == "__main__":
    main()
