import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
""" DUMMY TEST event collector - generates fake events, makes no network calls. """

VENDOR = "dummy"
PRODUCT = "devsupport"
DEFAULT_LIMIT = 2


def generate_events(limit: int) -> list[dict]:
    now = datetime.utcnow()
    return [
        {
            "id": i + 1,
            "message": f"Dummy dev-support test event {i + 1}",
            "_time": (now - timedelta(seconds=i)).strftime(DATE_FORMAT),
        }
        for i in range(limit)
    ]


def main() -> None:  # pragma: no cover
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    demisto.debug(f"Command being called is {command}")
    try:
        if command == "test-module":
            return_results("ok")
        elif command == "dummy-dev-support-get-events":
            events = generate_events(arg_to_number(args.get("limit")) or DEFAULT_LIMIT)
            if argToBoolean(args.get("should_push_events", False)):
                send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
            return_results(CommandResults(readable_output=tableToMarkdown("Dummy Events", events), raw_response=events))
        elif command == "fetch-events":
            events = generate_events(arg_to_number(params.get("max_fetch")) or DEFAULT_LIMIT)
            send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
            demisto.setLastRun({"last_fetch": datetime.utcnow().strftime(DATE_FORMAT)})
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{e!s}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()

