import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

ORANGE_HTML_STYLE = "color:#FF9000;text-align:center;font-size:800%;>"
GREEN_HTML_STYLE = "color:#00CD33;text-align:center;font-size:800%;>"


def main():
    incident = demisto.incidents()
    query = incident[0].get('CustomFields', {}).get('totalinstances', 0)

    if not query:
        html = f"<h1 style={GREEN_HTML_STYLE}0</h1>"

    else:
        html = f"<h1 style={ORANGE_HTML_STYLE}{str(query)}</h1>"

    demisto.results({
        'ContentsFormat': formats['html'],
        'Type': entryTypes['note'],
        'Contents': html
    })


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
