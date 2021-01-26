import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

RED_HTML_STYLE = "color:#FF1744;text-align:center;font-size:800%;>"
GREEN_HTML_STYLE = "color:#00CD33;text-align:center;font-size:800%;>"


def main():
    incident = demisto.incidents()
    query = incident[0].get('CustomFields', {}).get('numberofentriesiderrors', 0)

    if not query:
        html = f"<h1 style={GREEN_HTML_STYLE}0</h1>"

    else:
        html = f"<h1 style={RED_HTML_STYLE}{str(query)}</h1>"

    return_results({
        'ContentsFormat': EntryFormat.HTML,
        'Type': EntryType.NOTE,
        'Contents': html
    })


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
