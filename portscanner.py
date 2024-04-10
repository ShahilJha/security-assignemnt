import socket
import threading

def scan_port(ip, port, results):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex((ip, port))
            if result == 0:
                try:
                    service = socket.getservbyport(port)
                except:
                    service = 'Unknown service'
                results[port] = f"Port {port}: OPEN (Service: {service})"
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

    for port in range(start_port, end_port + 1):
        thread = threading.Thread(target=scan_port, args=(ip, port, results))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    for port in sorted(results.keys()):
        print(results[port])

if __name__ == "__main__":
    main()
