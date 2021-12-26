import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

ORANGE_HTML_STYLE = "'color:#EF9700;font-size:48px;padding: 60px; text-align:center;padding-left: 70px'>"
GREEN_HTML_STYLE = "'color:#1DB846;font-size:48px;padding: 60px; text-align:center;padding-left: 70px'>"
GREY_HTML_STYLE = "'color:#404142;font-size:48px;padding: 60px; text-align:center;padding-left: 70px'>"


def main():
    incident = demisto.incidents()
    query = incident[0].get('CustomFields', {}).get('eradicationtaskcount', 0)

    if not query:
        html = f"<div style={GREY_HTML_STYLE}{0}</div>"
    elif int(query) == 0:
        html = f"<div style={ORANGE_HTML_STYLE}{str(query)}</div>"
    else:
        html = f"<div style={GREEN_HTML_STYLE}{str(query)}</div>"

    demisto.results({
        'ContentsFormat': formats['html'],
        'Type': entryTypes['note'],
        'Contents': html
    })


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
