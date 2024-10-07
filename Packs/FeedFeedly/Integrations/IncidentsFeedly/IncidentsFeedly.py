import random

from CommonServerPython import *  # noqa: F401


def fetch_incidents() -> list[dict]:
    event_id = random.randint(1, 1000000)
    events = [
        {
            "name": f"event_test_{event_id}",
            "create_time": datetime.now().isoformat(),
            "event_id": event_id,
        },
    ]

    incidents = []
    for event in events:
        incident = {
            "name": event["name"],
            "occured": event["create_time"],
            "dbotMirrorId": str(event["event_id"]),
            "rawJSON": json.dumps(event),
        }
        incidents.append(incident)
    return incidents


def main() -> None:
    command = demisto.command()
    if command == "fetch-incidents":
        demisto.incidents(fetch_incidents())
