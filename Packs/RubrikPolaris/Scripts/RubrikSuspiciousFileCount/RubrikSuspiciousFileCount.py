import demistomock as demisto  # noqa: F401
from CommonServerPython import *

""" CONSTANTS """

ORANGE_HTML_STYLE = "color:#FF9000;font-size:275%;>"
GREEN_HTML_STYLE = "color:#00CD33;font-size:275%;>"
RED_HTML_STYLE = "color:#FF1744;font-size:275%;>"
DIV_HTML_STYLE = "display:block;text-align:center;"

""" MAIN FUNCTION """


def main():
    """
    Main function
    """
    suspicious_file_count = demisto.incident().get("CustomFields", {}).get("rubriksuspiciousfilecount")

    if suspicious_file_count is None:
        html = f"<div style={DIV_HTML_STYLE}><h1 style={ORANGE_HTML_STYLE}No Results Found</h1></div>"
    elif suspicious_file_count == 0:
        html = f"<div style={DIV_HTML_STYLE}><h1 style={GREEN_HTML_STYLE}{suspicious_file_count}</h1></div>"
    else:
        html = f"<div style={DIV_HTML_STYLE}><h1 style={RED_HTML_STYLE}{suspicious_file_count}</h1></div>"

    demisto.results({"ContentsFormat": formats["html"], "Type": entryTypes["note"], "Contents": html})


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
