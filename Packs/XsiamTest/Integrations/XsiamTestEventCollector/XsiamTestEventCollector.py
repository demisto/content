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


def generate_event() -> str:
    return " ".join(ALL_FIELDS)


def generate_events(max_fetch: int) -> list[str]:
    new_event = generate_event()
    return [new_event for _ in range(max_fetch)]


def fetch_events_command(max_fetch: str) -> tuple[list[str], dict]:
    return generate_events(int(max_fetch)), {}


def test_module():
    return "ok"


def main() -> None:  # pragma: no cover
    params = demisto.params()
    args = demisto.args()

    max_fetch = params.get("max_fetch", "5000")
    should_push_events = argToBoolean(args.get("should_push_events", False))

    command = demisto.command()
    try:

        if command == "test-module":
            return_results(test_module())

        elif command == "fetch-events":
            should_push_events = True
            should_update_last_run = True
            last_run = demisto.getLastRun()
            events, last_run = fetch_events_command(max_fetch=max_fetch)

        else:
            raise NotImplementedError(f"Command {command} is not implemented.")

        if should_push_events:
            size_of_events = sys.getsizeof(events)
            demisto.debug(f"{size_of_events=}")
            send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT, chunk_size=XSIAM_EVENT_CHUNK_SIZE_LIMIT / 2)
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
    # print(sys.getsizeof(generate_events(1050000)) / (1024 * 1024))
