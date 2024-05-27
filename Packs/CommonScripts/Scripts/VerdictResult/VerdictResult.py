import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

RED_HTML_STYLE = "color:#FF1744;text-align:center;font-size:300%;padding-top:1em>"
GREEN_HTML_STYLE = "color:#00CD33;text-align:center;font-size:300%;padding-top:1em>"
ORANGE_HTML_STYLE = "color:#FF9000;text-align:center;font-size:300%;padding-top:1em>"
GREY_HTML_STYLE = "color:#808080;text-align:center;font-size:300%;padding-top:1em>"


def main():
    investigationverdict = demisto.incidents()[0].get('CustomFields').get('verdict')

    if investigationverdict == 'Malicious':
        html = f"<h1 style={RED_HTML_STYLE}Malicious</h1>"

    elif investigationverdict == 'Suspicious':
        html = f"<h1 style={ORANGE_HTML_STYLE}Suspicious</h1>"

    elif investigationverdict == 'Non-Malicious':
        html = f"<h1 style={GREEN_HTML_STYLE}Non-Malicious</h1>"

    else:
        html = f"<h1 style={GREY_HTML_STYLE}Not Determined</h1>"

    demisto.results({
        'ContentsFormat': formats['html'],
        'Type': entryTypes['note'],
        'Contents': html
    })


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
