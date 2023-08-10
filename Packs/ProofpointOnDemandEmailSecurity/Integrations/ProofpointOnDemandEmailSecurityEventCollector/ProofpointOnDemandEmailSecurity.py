from CommonServerPython import *  # noqa: F401
from websockets.sync.client import connect
import json
VENDOR = "proofpoint"
PRODUCT = "on_demand_email_security"


def long_running_execution_command():
    # start websocket connection
    events_to_fetch = 50
    events = []
    with connect("ws://echo.websocket.org") as connection:
        event: dict = json.loads(connection.recv())
        event["_time"] = event.get("ts")
        events.append(event)
        if len(events) == events_to_fetch:
            send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)


def main():
    command = demisto.command()
    demisto.params()
    demisto.args()
    if command == "long-running-execution":
        long_running_execution_command()
