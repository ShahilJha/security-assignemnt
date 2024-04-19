# textual run --dev GUI.py
from textual import on
import json
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
    LoadingIndicator,
)
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

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
        original_rows = [tuple(int(item) if item.isdigit() else item for item in tuple_string.split("+")) for tuple_string in tuple_strings]
        
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
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = [executor.submit(self.scan_port, port) for port in range(self.start_port, self.end_port + 1)]
            for future in as_completed(futures):
                self.results.update(future.result())
        end_time = time.time()

        # Adding timing info to results dictionary
        self.scan_metadata['start_time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(start_time))
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


class MainFrame(Static):
    """the main framework for the application"""
    util = Utils()
    data = {
        "ip" : "",
        "start_port" : 0,
        "end_port" : 0,
        "start_time" : "",
        "end_time" : "",
        "scan_duration" : "",
    }
    converted_data = reactive(util.serialize_data(data))
    
    @on(Input.Changed,"#ip_input,#start_port_input,#end_port_input")
    def update_ip_data(self):
        ip_data = self.query_one("#ip_input")
        self.converted_data = self.util.update_and_serialize_data(self.converted_data, "ip", ip_data.value)
        # self.update(ip_data.value)
        
        start_port_data = self.query_one("#start_port_input")
        self.converted_data = self.util.update_and_serialize_data(self.converted_data, "start_port", start_port_data.value)
        
        end_port_data = self.query_one("#end_port_input")
        self.converted_data = self.util.update_and_serialize_data(self.converted_data, "end_port", end_port_data.value)
        
    
    # refer a method for onPressed button
    # format: @on(Button.Pressed, "#id")
    @on(Button.Pressed, "#start_btn")
    def pressed_start(self):
        self.add_class("scan_started")
        summary_ui = self.query_one("ScannedSummarySection")
        ip = self.util.get_value(self.converted_data, "ip")
        start_port = self.util.get_value(self.converted_data, "start_port")
        end_port = self.util.get_value(self.converted_data, "end_port")
        # start_time = self.util.get_value(self.converted_data, "start_time")
        # end_time = self.util.get_value(self.converted_data, "end_time")
        # scan_duration = self.util.get_value(self.converted_data, "scan_duration")
        
        #start the port scanning
        portScanner = PortScanner(ip=ip, start_port=int(start_port), end_port=int(end_port))
        result_data = portScanner.perform_scan()
        result_summary = portScanner.get_scan_data()
        table_ui = self.query_one("ScannedPortDataSection")
        # table_ui.table_data = 
        
        #display scan results or error if any
        summary_ui.summary_data = f"Scan Report for IP Adress: {result_summary['ip']} \nStarting port: {result_summary['start_port']} \nEnding Port: {result_summary['end_port']} \nScan Start Time: {result_summary['start_time']} \nScan End Time: {result_summary['end_time']} \nScan Duration: {result_summary['scan_duration']}"
        # summary_ui.summary_data = str(type(start_port))
        self.remove_class("scan_started")
        
        

    def compose(self):
        with ScrollableContainer():
            yield DataInputSection()
            yield ScannedSummarySection(id="summary")
            yield ScannedPortDataSection()


class DataInputSection(Static):
    """WIdget to input Data"""

    def compose(self):
        yield Label("IP Address:")
        yield Input(id="ip_input", placeholder="127.0.0.1")
        yield Label("Start Port:")
        yield Input(
            id="start_port_input", placeholder="0", type="integer", max_length=65534
        )
        yield Label("End Port:")
        yield Input(
            id="end_port_input", placeholder="65535", type="integer", max_length=65535
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
# ROWS = [
#     (4, "Joseph Schooling", "Singapore"),
#     (2, "Michael Phelps", "United States"),
#     (5, "Chad le Clos", "South Africa"),
#     (6, "László Cseh", "Hungary"),
#     (3, "Li Zhuhao", "China"),
#     (8, "Mehdy Metella", "France"),
#     (7, "Tom Shields", "United States"),
#     (1, "Aleksandr Sadovnikov", "Russia"),
#     (10, "Darren Burns", "Scotland"),
# ]



class ScannedPortDataSection(Static):
    """WIdget to show the port data"""
    util = Utils()
    
    table_data = reactive(util.convert_to_csv([("", "", "")]))

    def watch_table_data(self):
        data = self.table_data
        self.update(data)
        
    def compose(self):
        yield DataTable()

    def on_mount(self):
        table = self.query_one(DataTable)
        table.add_columns(*COLUMN)
        table.add_rows(self.util.revert_from_csv(self.table_data))
        # table.add_rows(ROWS)


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
