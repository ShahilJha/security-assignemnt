from textual.app import App
from textual.widgets import Footer, Header

class PortScannerApp(App):
    # list of all the key bindings for the applicaiton
    # in the format of => (key, action_name, description)
    # key: the key you'll be using
    # action_name: reference the function name to be called. 
    #   The method should always have a "action_" prefix to work, 
    #   but the reference should not have the prefix when referencing
    # description: just the description of the binding
    BINDINGS = [
        ("d", "toggle_dark_mode","Toggle dark mode"),
    ]
    def compose(self):
        """
            an expected funciton by Textual.
            What widgets is this app composed of?
        """
        yield Header()
        yield Footer()
    
    def action_toggle_dark_mode(self):
        self.dark = not self.dark



if __name__ == "__main__":
    PortScannerApp().run()