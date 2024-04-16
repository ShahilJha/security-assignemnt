# textual run --dev GUI.py
from textual import on
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


class MainFrame(Static):
    """the main framework for the application"""

    # refer a method for onPressed button
    # format: @on(Button.Pressed, "#id")
    @on(Button.Pressed, "#start_btn")
    def pressed_start(self):
        # self.app.exit()
        self.add_class("scan_started")
        # self.remove_class("scan_started")
        summary_ui = self.query_one("ScannedSummarySection")
        summary_ui.summary_data = f"Scan Report for IP Adress: \nStarting port \nEnding Port: \nScan Start Time: \nScan End Time: \nScan Duration:"

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


ROWS = [
    ("lane", "swimmer", "country", "time"),
    (4, "Joseph Schooling", "Singapore", 50.39),
    (2, "Michael Phelps", "United States", 51.14),
    (5, "Chad le Clos", "South Africa", 51.14),
    (6, "László Cseh", "Hungary", 51.14),
    (3, "Li Zhuhao", "China", 51.26),
    (8, "Mehdy Metella", "France", 51.58),
    (7, "Tom Shields", "United States", 51.73),
    (1, "Aleksandr Sadovnikov", "Russia", 51.84),
    (10, "Darren Burns", "Scotland", 51.84),
]


class ScannedPortDataSection(Static):
    """WIdget to show the port data"""

    def compose(self):
        yield DataTable()

    def on_mount(self):
        table = self.query_one(DataTable)
        table.add_columns(*ROWS[0])
        table.add_rows(ROWS[1:])


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
