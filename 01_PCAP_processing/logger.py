from datetime import datetime
import requests

class LogColors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def make_debug_log(message: str = ""):
    message_string = f"{LogColors.OKCYAN}{LogColors.BOLD}DEBUG: ({datetime.now()}){LogColors.ENDC} {message}"
    print(message_string)
    return f"DEBUG: {message}"

def make_info_log(message: str = ""):
    message_string = f"{LogColors.OKGREEN}{LogColors.BOLD}INFO: ({datetime.now()}){LogColors.ENDC} {message}"
    print(message_string)
    return f"INFO: {message}"

def make_error_log(message: str = ""):
    if type(message) == bytes:
        message = message.decode("utf-8")
    message_string = f"{LogColors.FAIL}{LogColors.BOLD}ERROR: ({datetime.now()}){LogColors.ENDC} {message}"
    print(message_string)
    return f"ERROR: {message}"

def processing_update(log: str):
    try:
        requests.post("REDACTED", data=log)
    except:
        print("ERROR: No connection to external host!")