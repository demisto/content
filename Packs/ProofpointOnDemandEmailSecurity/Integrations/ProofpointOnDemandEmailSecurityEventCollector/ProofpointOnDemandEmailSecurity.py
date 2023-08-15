import asyncio
from CommonServerPython import *  # noqa: F401
from websockets.client import connect 

VENDOR = "proofpoint"
PRODUCT = "on_demand_email_security"

async def long_running_execution_command(cluster_id: str, api_key: str):
    last_sent_time = datetime.min

    # start websocket connection
    events_to_fetch = 50
    message_events = []
    maillog_events = []
    demisto.info("Starting websocket connection")
    extra_headers = {"Authorization": f"Bearer {api_key}"}
    async with connect(f"wss://logstream.proofpoint.com/v1/stream?cid={cluster_id}&type=message", extra_headers=extra_headers) as message_connection, connect(f"wss://logstream.proofpoint.com/v1/stream?cid={cluster_id}&type=maillog", extra_headers=extra_headers) as maillog_connection:
        demisto.info("Connected to websocket")
        while True:        
        
        while len(message_events) < events_to_fetch or (datetime.now() - last_sent_time).total_seconds() > 360:
            event = json.loads(message_connection.recv())
            event["_time"] = event.get("ts")
            demisto.info(f"Received event: {event}")
            message_events.append(event)
        message_connection.close()

    # Connect to the maillog WebSocket stream
    with connect(f"wss://logstream.proofpoint.com/v1/stream?cid={cluster_id}&type=maillog", additional_headers={"Authorization": f"Bearer {api_key}"}) as maillog_connection:
        while len(maillog_events) < events_to_fetch or (datetime.now() - last_sent_time).total_seconds() > 360:
            event = json.loads(maillog_connection.recv())
            event["_time"] = event.get("ts")
            demisto.info(f"Received event: {event}")
            maillog_events.append(event)
        maillog_connection.close()
    demisto.info("Adding events to XSIAM")
    current_time = datetime.now()
    # Send the events to the XSIAM
    send_events_to_xsiam(message_events, vendor=VENDOR, product=PRODUCT)
    send_events_to_xsiam(maillog_events, vendor=VENDOR, product=PRODUCT)
    last_sent_time = current_time
        
async def main():
    command = demisto.command()
    params = demisto.params()
    cluster_id = params.get("cluster_id", "")
    api_key = params.get("api_key", {}).get("password", "")
    if command == "long-running-execution":
        await long_running_execution_command(cluster_id, api_key)

if __name__ in ('__main__', '__builtin__', 'builtins'):
    asyncio.run(main())