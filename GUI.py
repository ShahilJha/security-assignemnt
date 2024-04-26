# textual run --dev GUI.py
from textual import on
import json
import errno
import os
from textual.app import App
from textual.containers import ScrollableContainer
from textual.reactive import reactive
from textual.widgets import (
    Footer,
    Header,
    Static,
    Button,
    Label,
    Input,
    DataTable,
    Pretty,
)
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Semaphore
from textual.validation import Function, Number
import time
import re
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors



class Utils:

    def convert_to_csv(self, rows):
        """
        Converts a list of tuples into a single CSV string.
        """
        # Convert each tuple to a string with elements separated by '+'
        converted_rows = ["+".join(str(item) for item in row) for row in rows]

        # Join all the stringified tuples into a CSV format
        csv_result = ",".join(converted_rows)

        return csv_result

    def revert_from_csv(self, csv_string):
        """
        Reverts a CSV formatted string (with internal '+' symbol concatenation for tuple data) back to the original list of tuples format.
        """
        # Split the CSV string by commas to separate the individual tuple strings
        tuple_strings = csv_string.split(",")

        # Split each tuple string by '+' and convert them appropriately
        original_rows = [
            tuple(
                int(item) if item.isdigit() else item
                for item in tuple_string.split("+")
            )
            for tuple_string in tuple_strings
        ]

        return original_rows

    # Function to convert dictionary to a JSON string
    def serialize_data(self, rows):
        # Using json.dumps() to convert dict to a JSON string
        return json.dumps(rows)

    # Function to convert JSON string back to ldictionary
    def deserialize_data(self, json_string):
        # Using json.loads() to convert JSON string back to Python object
        return json.loads(json_string)

    def update_and_serialize_data(self, json_string, key, update_value):
        """
        Deserializes the JSON data, updates it using the provided key and value,
        then serializes it back to a JSON string.
        """
        # Deserialize the JSON string to a Python dictionary
        data = self.deserialize_data(json_string)

        # Check if the key exists in the dictionary
        if key not in data:
            raise KeyError(f"Key '{key}' not found in the data.")

        # Update the value associated with the key
        data[key] = update_value

        # Serialize the updated dictionary back to a JSON string
        updated_json_string = self.serialize_data(data)
        return updated_json_string

    def get_value(self, json_string, key):
        """
        Deserializes the JSON data and returns the value corresponding to the provided key.
        """
        data = self.deserialize_data(json_string)

        if key not in data:
            raise KeyError(f"Key '{key}' not found in the data.")

        return data[key]

    def dict_to_list_of_tuples(self, input_dict):
        """
        Convert a dictionary with tuple values into a list of tuples sorted by dictionary keys.
        """
        # Sorting the dictionary by keys and creating a list of tuples from the values
        sorted_tuples = sorted(input_dict.items())
        return [value for _, value in sorted_tuples]

    def is_valid_ip(self, ip_address):
        """
        Validate an IP address using regular expression.
        """
        # Regular expression for matching an IPv4 address
        ip_pattern = r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
        if re.match(ip_pattern, ip_address):
            return True
        else:
            return False
        
    def check_input_validity(self, ip_address, start_port, end_port):
        errors = []
        # 1. Check if any input is empty
        if not ip_address:
            errors.append("IP address is empty.")
        if start_port is None:
            errors.append("Starting port is not provided.")
        if end_port is None:
            errors.append("Ending port is not provided.")

        # 2. Validate the IP address
        if ip_address and not self.is_valid_ip(ip_address):
            errors.append(f"The IP address '{ip_address}' is not valid.")

        # 3. Check if the ports are integers and within valid range
        try:
            start_port = int(start_port)
            if not (0 <= start_port <= 65534):
                errors.append("Starting port must be between 0 and 65534.")
        except (ValueError, TypeError):
            errors.append("Starting port must be an integer.")

        try:
            end_port = int(end_port)
            if not (1 <= end_port <= 65535):
                errors.append("Ending port must be between 1 and 65535.")
        except (ValueError, TypeError):
            errors.append("Ending port must be an integer.")

        return errors

    def generate_pdf_report(self, scanner):
        """
        Generates a PDF report for the results of a PortScanner instance.
        """
        # Determine the Downloads folder path based on the operating system
        home = os.path.expanduser("~")
        download_path = os.path.join(home, "Downloads")
        os.makedirs(download_path, exist_ok=True)  # Ensure the directory exists
        filename = os.path.join(download_path, f"Port_Scan_Report_{scanner.ip}.pdf")

        document = SimpleDocTemplate(filename, pagesize=letter)
        elements = []
        styles = getSampleStyleSheet()

        # Adding the scan metadata
        metadata_title = Paragraph("Scan Metadata", styles['Heading1'])
        elements.append(metadata_title)
        metadata_info = [
            f"IP: {scanner.scan_metadata['ip']}",
            f"Start Port: {scanner.scan_metadata['start_port']}",
            f"End Port: {scanner.scan_metadata['end_port']}",
            f"Start Time: {scanner.scan_metadata['start_time']}",
            f"End Time: {scanner.scan_metadata['end_time']}",
            f"Duration: {scanner.scan_metadata['scan_duration']}",
            f"Open Ports: {scanner.scan_metadata['open_port_num']}",
            f"Closed Ports: {scanner.scan_metadata['close_port_num']}",
            f"Filtered Ports: {scanner.scan_metadata['filtered_port_num']}",
        ]
        for item in metadata_info:
            elements.append(Paragraph(item, styles['BodyText']))
            elements.append(Spacer(1, 12))

        # Helper function to create tables for each status
        def create_status_table(status):
            data = [[f"Port Number", "Status", "Service"]]
            filtered_results = [(port, res[1], res[2]) for port, res in scanner.results.items() if res[1] == status]
            data.extend(filtered_results)
            if filtered_results:  # Only create table if there are results for this status
                table = Table(data)
                table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ]))
                elements.append(Paragraph(f"{status} Ports", styles['Heading2']))
                elements.append(table)
                elements.append(Spacer(1, 20))

        # Adding tables for each port status
        create_status_table("OPEN")
        create_status_table("CLOSED")
        create_status_table("FILTERED")

        document.build(elements)
        # return filename
        return f"PDF report generated and saved to: {filename}"

class PortScanner:
    def __init__(self, ip, start_port, end_port, max_threads=100):
        self.ip = ip
        self.start_port = start_port
        self.end_port = end_port
        self.max_threads = max_threads
        self.semaphore = Semaphore(max_threads)
        self.results = {}
        self.open_port = 0
        self.closed_port = 0
        self.filtered_port = 0
        self.scan_metadata = {
            "ip": ip,
            "start_port": start_port,
            "end_port": end_port,
            "start_time": "",
            "end_time": "",
            "scan_duration": "",
            "open_port_num": "",
            "close_port_num": "",
            "filtered_port_num": "",
        }

    def scan_port(self, port):
        """Scan a single port and return the result as a dictionary."""
        self.semaphore.acquire()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2)
                result = s.connect_ex((self.ip, port))
                if result == 0:
                    service = socket.getservbyport(port, "tcp") if socket.getservbyport(port, "tcp") else "-"
                    status = "OPEN"
                    self.open_port += 1
                elif result in [errno.ECONNREFUSED, 10061]:
                    service = "-"
                    status = "CLOSED"
                    self.closed_port += 1
                elif result in [errno.ETIMEDOUT, errno.EHOSTUNREACH]:
                    service = "-"
                    status = "FILTERED"
                    self.filtered_port += 1
                else:
                    service = "-"
                    status = "FILTERED"
                    self.filtered_port += 1

                self.results[port] = (port, status, service)
        except Exception as e:
            self.results[port] = (port, "ERROR", str(e))
        finally:
            self.semaphore.release()

    def perform_scan(self):
        """Perform the port scan using ThreadPoolExecutor for managing threads."""
        start_time = time.time()
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = [executor.submit(self.scan_port, port) for port in range(self.start_port, self.end_port + 1)]
            for future in as_completed(futures):
                future.result()
        end_time = time.time()

        # Adding timing info to results dictionary
        self.scan_metadata["start_time"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(start_time))
        self.scan_metadata["end_time"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(end_time))
        self.scan_metadata["scan_duration"] = f"{end_time - start_time:.2f} seconds"
        self.scan_metadata["open_port_num"] = f"{self.open_port} ports"
        self.scan_metadata["close_port_num"] = f"{self.closed_port} ports"
        self.scan_metadata["filtered_port_num"] = f"{self.filtered_port} ports"

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
            "open_port_num": self.scan_metadata["open_port_num"],
            "close_port_num": self.scan_metadata["close_port_num"],
            "filtered_port_num": self.scan_metadata["filtered_port_num"],
        }

class MainFrame(Static):
    """the main framework for the application"""

    report_data = None
    util = Utils()
    data = {
        "ip": "",
        "start_port": 0,
        "end_port": 0,
        "start_time": "",
        "end_time": "",
        "scan_duration": "",
    }
    converted_data = reactive(util.serialize_data(data))

    @on(Input.Changed, "#ip_input,#start_port_input,#end_port_input")
    def update_data(self):
        ip_data = self.query_one("#ip_input")
        self.converted_data = self.util.update_and_serialize_data(
            self.converted_data, "ip", ip_data.value
        )
        # self.update(ip_data.value)

        start_port_data = self.query_one("#start_port_input")
        self.converted_data = self.util.update_and_serialize_data(
            self.converted_data, "start_port", start_port_data.value
        )

        end_port_data = self.query_one("#end_port_input")
        self.converted_data = self.util.update_and_serialize_data(
            self.converted_data, "end_port", end_port_data.value
        )

    @on(Input.Changed, "#ip_input,#start_port_input,#end_port_input")
    def show_invalid_reasons(self, event: Input.Changed):
        # Updating the UI to show the reasons why validation failed
        if not event.validation_result.is_valid:
            self.query_one(Pretty).update(event.validation_result.failure_descriptions)
        else:
            self.query_one(Pretty).update([])
        
    # refer a method for onPressed button
    # format: @on(Button.Pressed, "#id")
    @on(Button.Pressed, "#start_btn")
    def pressed_start(self):
        # self.add_class("scan_started")
        # self.query_one("#download_btn").remove_class("can_download") 
               
        
        summary_ui = self.query_one("ScannedSummarySection")
        ip = self.util.get_value(self.converted_data, "ip")
        start_port = self.util.get_value(self.converted_data, "start_port")
        end_port = self.util.get_value(self.converted_data, "end_port")
        
        error_list = self.util.check_input_validity(ip_address=ip,start_port=start_port, end_port=end_port)
        
        if len(error_list) != 0:
             self.query_one(Pretty).update(error_list)
        else:
            self.query_one(Pretty).update(['All Input Valid'])
            # start the port scanning
            portScanner = PortScanner(
                ip=ip, start_port=int(start_port), end_port=int(end_port)
            )
            result_data = portScanner.perform_scan()
            result_summary = portScanner.get_scan_data()
            self.report_data = portScanner

            
            # display scan results or error if any
            summary_ui.summary_data = f"Scan Report for IP Adress: {result_summary['ip']} \nStarting port: {result_summary['start_port']} \nEnding Port: {result_summary['end_port']} \nScan Start Time: {result_summary['start_time']} \nScan End Time: {result_summary['end_time']} \nScan Duration: {result_summary['scan_duration']} \nOpen Ports: {result_summary['open_port_num']} \nClose Ports: {result_summary['close_port_num']} \nFiltered Ports: {result_summary['filtered_port_num']}"

            table_ui = self.query_one("#table_data")
            table_ui.table_data = self.util.convert_to_csv(
                self.util.dict_to_list_of_tuples(result_data)
            )
            
            # table_ui.table_data = self.util.convert_to_csv([("1","shahil","jha")])

            # self.remove_class("scan_started")
            
    
    @on(Button.Pressed, "#download_btn")
    def pressed_download(self):
        if self.report_data == None:
            self.query_one(Pretty).update(["No scans performed yet"])
        else:
            return_str = Utils().generate_pdf_report(self.report_data)
            self.query_one(Pretty).update([return_str])
        

    def compose(self):
        with ScrollableContainer():
            yield DataInputSection()
            yield Pretty(f'[Input Validitiy Messages]')
            yield ScannedSummarySection(id="summary")
            yield Button("Download Report", variant="primary", id="download_btn", classes="cannot_download")
            yield ScannedPortDataSection(id="table_data")


class DataInputSection(Static):
    """WIdget to input Data"""

    util = Utils()

    def compose(self):
        yield Label("IP Address:")
        yield Input(
            id="ip_input",
            placeholder="127.0.0.1",
            validators=[
                Function(self.util.is_valid_ip, "IP address is invalid."),
            ],
        )
        yield Label("Start Port:")
        yield Input(
            id="start_port_input",
            placeholder="0",
            type="integer",
            max_length=5,
            validators=[
                Number(minimum=0, maximum=65534),
            ],
        )
        yield Label("End Port:")
        yield Input(
            id="end_port_input",
            placeholder="65535",
            type="integer",
            max_length=5,
            validators=[
                Number(minimum=1, maximum=65535),
            ],
        )
        yield Button("Start Scan", variant="success", id="start_btn", classes="started")


class ScannedSummarySection(Static):
    """WIdget to show the port summary data"""

    summary_data = reactive("")

    def watch_summary_data(self):
        """method to watch the change in data"""
        data = self.summary_data
        self.update(data)


COLUMN = ("Port Number", "Status", "Service Running")


class ScannedPortDataSection(Static):
    """WIdget to show the port data"""

    util = Utils()

    table_data = reactive("")

    def watch_table_data(self):
        data = self.table_data
        self.update(data)
        table = self.query_one(DataTable)
        table.clear()
        table.add_rows(self.util.revert_from_csv(data))

    def compose(self):
        yield DataTable()

    def on_mount(self):
        table = self.query_one(DataTable)
        table.add_columns(*COLUMN)
        # table.add_rows(self.util.revert_from_csv(self.table_data))


class PortScannerApp(App):
    # list of all the key bindings for the applicaiton
    # in the format of => (key, action_name, description)
    # key: the key you'll be using
    # action_name: reference the function name to be called.
    #   The method should always have a "action_" prefix to work,
    #   but the reference should not have the prefix when referencing
    # description: just the description of the binding
    BINDINGS = [
        ("d", "toggle_dark_mode", "Toggle Dark Mode"),
        ("q", "exit_app", "Exit App"),
    ]

    # to reference the path for the CSS stylesheet
    CSS_PATH = "style.css"

    def compose(self):
        """
        an expected funciton by Textual.
        What widgets is this app composed of?
        """
        yield Header()
        yield Footer()
        # yield MainFrame()

        with ScrollableContainer(id="mainframe"):
            yield MainFrame()

    def action_toggle_dark_mode(self):
        self.dark = not self.dark

    def action_exit_app(self):
        self.app.exit()


if __name__ == "__main__":
    PortScannerApp().run()