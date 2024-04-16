import socket
import threading
import time


def scan_port(ip, port, results):
    """Scan a single port."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex((ip, port))
            if result == 0:
                service = socket.getservbyport(port, 'tcp') if port <= 1024 else 'Unknown service'
                results[port] = f"Port {port}: OPEN (Service: {service}"
            elif result == 10061:
                results[port] = f"Port {port}: CLOSED"
            else:
                results[port] = f"Port {port}: FILTERED"
    except Exception as e:
        results[port] = f"Error scanning port {port}: {e}"

def main():
    ip = input("Enter IP address to scan: ")
    start_port = int(input("Enter start port: "))
    end_port = int(input("Enter end port: "))

    threads = []
    results = {}
    start_time = time.time()

    for port in range(start_port, end_port + 1):
        thread = threading.Thread(target=scan_port, args=(ip, port, results))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    end_time = time.time()
    scan_duration = end_time - start_time

    print(f"Scan Report for {ip}")
    print(f"Scan Start Time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(start_time))}")
    print(f"Scan End Time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(end_time))}")
    print(f"Scan Duration: {scan_duration:.2f} seconds\n")

    for port in sorted(results.keys()):
        print(results[port])
    print(results)

if __name__ == "__main__":
    main()
