import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import re


def get_sender_from_text(text):
    sender = re.search(r".*From\w*:.*\b([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\b", text, re.I)
    if sender:
        return sender.group(1)
    return ""


def format_data(data):
    data = data if isinstance(data, list) else [data]
    return [{k: formatCell(row[k]) for k in row} for row in data]


""" MAIN FUNCTION """


def main():
    try:
        email = demisto.getArg("email")
        if not email:
            get_sender_from_text(demisto.incidents()[0]["details"])

        if email:
            resp = demisto.executeCommand("pipl-search", {"email": email})

            if isError(resp[0]):
                demisto.results(resp)
            else:
                data = demisto.get(resp[0], "Contents")
                if data:
                    demisto.results(
                        {"ContentsFormat": formats["table"], "Type": entryTypes["note"], "Contents": format_data(data)}
                    )
                else:
                    demisto.results("No results.")
        else:
            demisto.results("Could not find the sender data")
    except Exception as ex:
        return_error(f"Failed to gets the sender data. Error: {ex}", error=ex)


""" ENTRY POINT """
if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
