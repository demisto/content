import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


GREEN_HTML_STYLE = "'color:#1DB846;font-size:38px;padding: 60px; text-align:center;padding-left: 70px'>"
YELLOW_HTML_STYLE = "'color:#e3dc0e;font-size:48px;padding: 60px; text-align:center;padding-left: 70px'>"
ORANGE_HTML_STYLE = "'color:#EF9700;font-size:48px;padding: 60px; text-align:center;padding-left: 70px'>"
RED_HTML_STYLE = "'color:#b81d1d;font-size:48px;padding: 60px; text-align:center;padding-left: 70px'>"


def main():
    query = demisto.context().get('OverallScore')

    if not query:
        html = f"<div style={GREEN_HTML_STYLE}0/100<br>No suspicious strings found</div>"
    elif int(query) == 0:
        html = f"<div style={GREEN_HTML_STYLE}{int(query)}/100<br>No suspicious strings found</div>"
    elif int(query) > 0 and int(query) < 30:
        html = f"<div style={YELLOW_HTML_STYLE}{int(query)}/100</div>"
    elif int(query) > 29 and int(query) < 70:
        html = f"<div style={ORANGE_HTML_STYLE}{int(query)}/100</div>"
    elif int(query) > 69 and int(query) < 100:
        html = f"<div style={RED_HTML_STYLE}{int(query)}/100</div>"
    else:
        query = "100"
        html = f"<div style={RED_HTML_STYLE}{int(query)}/100</div>"

    return_results({
        'ContentsFormat': formats['html'],
        'Type': entryTypes['note'],
        'Contents': html
    })


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
