import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

class PortScanner:
    def __init__(self, ip, start_port, end_port, max_threads=100):
        self.ip = ip
        self.start_port = start_port
        self.end_port = end_port
        self.max_threads = max_threads
        self.results = {}
        self.scan_metadata = {
            "ip": ip,
            "start_port": start_port,
            "end_port": end_port,
            "start_time": "",
            "end_time": "",
            "scan_duration": "",
        }

    def scan_port(self, port):
        """Scan a single port and return the result as a dictionary."""
        result_dict = {}
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((self.ip, port))
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

    def perform_scan(self):
        """Perform the port scan using ThreadPoolExecutor for managing threads."""
        start_time = time.time()
        self.scan_metadata['start_time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(start_time))
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = [executor.submit(self.scan_port, port) for port in range(self.start_port, self.end_port + 1)]
            for future in as_completed(futures):
                self.results.update(future.result())

        end_time = time.time()
        self.scan_metadata['end_time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(end_time))
        self.scan_metadata['scan_duration'] = f"{end_time - start_time:.2f} seconds"
        return self.results

    def print_results(self):
        """Print the results of the scan."""
        print(f"Scan Report for {self.ip}")
        print(f"Scan Start Time: {self.scan_metadata['start_time']}")
        print(f"Scan End Time: {self.scan_metadata['end_time']}")
        print(f"Scan Duration: {self.scan_metadata['scan_duration']}\n")

        for port in sorted(k for k in self.results.keys() if isinstance(k, int)):
            print(self.results[port])

    def get_scan_data(self):
        """Return scan data as a structured dictionary."""
        return {
            "ip": self.scan_metadata["ip"],
            "start_port": self.scan_metadata["start_port"],
            "end_port": self.scan_metadata["end_port"],
            "start_time": self.scan_metadata["start_time"],
            "end_time": self.scan_metadata["end_time"],
            "scan_duration": self.scan_metadata["scan_duration"],
        }

# Example of how to use the PortScanner class
if __name__ == "__main__":
    ip = "127.0.0.1"
    start_port = 0
    end_port = 1025
    scanner = PortScanner(ip, start_port, end_port)
    scanner.perform_scan()
    scanner.print_results()
    data = scanner.get_scan_data()
    print(data)  # Printing the structured scan data
