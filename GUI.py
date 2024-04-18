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


class MainFrame(Static):
    """the main framework for the application"""
    temp = reactive("asdfa")
    
    @on(Input.Changed,"#ip_input")
    def update_ip_data(self):
        data = self.query_one("#ip_input")
        self.temp = data.value
        self.update(data.value)

    # refer a method for onPressed button
    # format: @on(Button.Pressed, "#id")
    @on(Button.Pressed, "#start_btn")
    def pressed_start(self):
        # self.add_class("scan_started")
        # self.remove_class("scan_started")
        
        
       
        
        summary_ui = self.query_one("ScannedSummarySection")
        summary_ui.summary_data = f"{self.temp} \nScan Report for IP Adress: \nStarting port \nEnding Port: \nScan Start Time: \nScan End Time: \nScan Duration:"

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
ROWS = [
    (4, "Joseph Schooling", "Singapore"),
    (2, "Michael Phelps", "United States"),
    (5, "Chad le Clos", "South Africa"),
    (6, "László Cseh", "Hungary"),
    (3, "Li Zhuhao", "China"),
    (8, "Mehdy Metella", "France"),
    (7, "Tom Shields", "United States"),
    (1, "Aleksandr Sadovnikov", "Russia"),
    (10, "Darren Burns", "Scotland"),
]



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
