import sys
import demistomock as demisto
from urllib3 import disable_warnings
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

disable_warnings()

""" CONSTANTS """

VENDOR = "xsiam"
PRODUCT = "test"
DATE_FORMAT_EVENT = "%Y-%m-%dT%H:%M:%SZ"
ALL_FIELDS = {
    "action",
    "mailID",
    "sender",
    "genTime",
    "logType",
    "subject",
    "tlsInfo",
    "senderIP",
    "direction",
    "eventType",
    "messageID",
    "recipient",
    "domainName",
    "headerFrom",
    "policyName",
    "eventSubtype",
    "policyAction",
    "deliveredTo",
    "attachments",
    "recipients",
    "headerTo",
    "details",
    "timestamp",
    "size",
    "deliveryTime",
    "reason",
    "embeddedUrls",
}


def generate_event():
    return " ".join(ALL_FIELDS)


def generate_events(limit: int):
    new_event = generate_event()
    return [new_event for _ in range(limit)]


def fetch_events_command(limit: str):
    events = generate_events(int(limit))


def test_module():
    return "ok"


def main() -> None:  # pragma: no cover
    params = demisto.params()
    args = demisto.args()

    should_push_events = argToBoolean(args.get("should_push_events", False))

    command = demisto.command()
    try:

        if command == "test-module":
            return_results(test_module())

        elif command == "fetch-events":
            should_push_events = True
            should_update_last_run = True
            last_run = demisto.getLastRun()
            events, last_run = fetch_events_command(limit=params["limit"])

        else:
            raise NotImplementedError(f"Command {command} is not implemented.")

        if should_push_events:
            send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)
            demisto.debug(f"{len(events)} events were pushed to XSIAM")

            if should_update_last_run:
                demisto.setLastRun(last_run)
                demisto.debug(f"set {last_run=}")

    except Exception as e:
        return_error(
            f"Failed to execute {command} command. Error in TrendMicro EmailSecurity Event Collector Integration [{e}]."
        )


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
