from CommonServerPython import *  # noqa: F401
from websockets.sync.client import connect
from websockets.sync.connection import Connection

VENDOR = "proofpoint"
PRODUCT = "on_demand_email_security"

EVENTS_TO_FETCH = 10


def fetch_events(connection: Connection) -> list[dict]:
    events: list[dict] = []
    while len(events) < EVENTS_TO_FETCH:
        try:
            event = json.loads(connection.recv(timeout=60))
            date = dateparser.parse(event.get("ts"))
            if not date:
                raise DemistoException(f"Failed to parse date: {event.get('ts')}")
            event["_time"] = date.isoformat()
            demisto.info(f"Received event: {event}")
            events.append(event)
            demisto.info(f"len of message_events: {len(events)}")
        except TimeoutError:
            demisto.info("Timeout reached when receiving events")
            break
    return events


def long_running_execution_command(cluster_id: str, api_key: str):
    # start websocket connection
    now = datetime.now().isoformat()
    demisto.info("Starting websocket connection")
    extra_headers = {"Authorization": f"Bearer {api_key}"}
    with connect(
        f"wss://logstream.proofpoint.com/v1/stream?cid={cluster_id}&type=message&sinceTime={now}",
        additional_headers=extra_headers,
    ) as message_connection, connect(
        f"wss://logstream.proofpoint.com/v1/stream?cid={cluster_id}&type=maillog&sinceTime={now}",
        additional_headers=extra_headers,
    ) as maillog_connection:
        demisto.info("Connected to websocket")
        while True:
            message_events = fetch_events(message_connection)
            maillog_events = fetch_events(maillog_connection)
            demisto.info("Adding events to XSIAM")
            # Send the events to the XSIAM
            send_events_to_xsiam(message_events, vendor=VENDOR, product=PRODUCT)
            send_events_to_xsiam(maillog_events, vendor=VENDOR, product=PRODUCT)


def main():
    command = demisto.command()
    params = demisto.params()
    cluster_id = params.get("cluster_id", "")
    api_key = params.get("api_key", {}).get("password", "")
    if command == "long-running-execution":
        long_running_execution_command(cluster_id, api_key)


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
