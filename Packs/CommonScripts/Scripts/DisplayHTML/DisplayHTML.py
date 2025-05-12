import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    html = demisto.args().get("html")
    note = demisto.args().get("markAsNote")
    header = demisto.args().get("header")

    note = bool(note and note.lower() == "true")
    if header:
        html = f"<h1>{header}</h1></br>{html}"

    demisto.results({"ContentsFormat": formats["html"], "Type": entryTypes["note"], "Contents": html, "Note": note})


if __name__ == "__builtin__" or __name__ == "builtins":
    main()
