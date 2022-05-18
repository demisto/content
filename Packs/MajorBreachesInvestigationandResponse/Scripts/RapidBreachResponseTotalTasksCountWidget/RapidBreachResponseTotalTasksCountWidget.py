import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

GREY_HTML_STYLE = "'color:#404142;font-size:48px;padding: 60px; text-align:center;padding-left: 70px'>"


def main():
    incident = demisto.incidents()
    query = incident[0].get('CustomFields', {}).get('totaltaskcount', 0)

    if not query:
        html = f"<div style={GREY_HTML_STYLE}0</div>"
    else:
        html = f"<div style={GREY_HTML_STYLE}{str(query)}</div>"

    demisto.results({
        'ContentsFormat': formats['html'],
        'Type': entryTypes['note'],
        'Contents': html
    })


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
