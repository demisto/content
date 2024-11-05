import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

GREEN_HTML_STYLE = "color:#00CD33;text-align:center;font-size:800%;>"
XSOARV8_HTML_STYLE = "color:#FFBE98;text-align:center;font-size:150%;>"


def main():
    if is_demisto_version_ge("8.0.0"):
        msg = "Not Available for XSOAR v8"
        html = f"<h3 style={XSOARV8_HTML_STYLE}{str(msg)}</h3>"
        demisto.results({"ContentsFormat": formats["html"], "Type": entryTypes["note"], "Contents": html})
        sys.exit()
    else:
        incident = demisto.incidents()
        query = incident[0].get("CustomFields", {}).get("healthchecknumberofinvestigationsinputoutputbiggerthan1mb", 0)

        html = f"<h1 style={GREEN_HTML_STYLE}{str(query)}</h1>"

        demisto.results({"ContentsFormat": formats["html"], "Type": entryTypes["note"], "Contents": html})


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
