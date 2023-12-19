import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
RED_HTML_STYLE = "color:#FF1744;text-align:center;font-size:300%;>"
GREEN_HTML_STYLE = "color:#00CD33;text-align:center;font-size:300%;>"
GREY_HTML_STYLE = "color:#808080;text-align:center;font-size:300%;>"


def main():
    investigationverdict = demisto.context().get('Verdict')

    if investigationverdict == 'Malicious':
        html = f"<h1 style={RED_HTML_STYLE}Malicious</h1>"

    elif investigationverdict == 'Benign':
        html = f"<h1 style={GREEN_HTML_STYLE}Benign</h1>"

    else:
        html = f"<h1 style={GREY_HTML_STYLE}Not Determined</h1>"

    demisto.results({
        'ContentsFormat': formats['html'],
        'Type': entryTypes['note'],
        'Contents': html
    })


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
