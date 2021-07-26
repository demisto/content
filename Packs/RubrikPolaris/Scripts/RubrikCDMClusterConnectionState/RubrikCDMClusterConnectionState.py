import demistomock as demisto  # noqa: F401
from CommonServerPython import *


def main() -> None:

    ORANGE_HTML_STYLE = "color:#FF9000;font-size:250%;>"
    GREEN_HTML_STYLE = "color:#00CD33;font-size:250%;>"
    RED_HTML_STYLE = "color:#FF1744;font-size:250%;"
    DIV_HTML_STYLE = "display:block;text-align:center;"

    try:
        cdm_connection_state = demisto.executeCommand("Print", {"value": "${Rubrik.CDM.Cluster.ConnectionState}"})
        cdm_connection_state = cdm_connection_state[0]["Contents"]

        if cdm_connection_state == "Connected":
            html = f"<div style={DIV_HTML_STYLE}><h1 style={GREEN_HTML_STYLE}{str(cdm_connection_state)}</h1></div>"
        else:
            html = f"<div style={DIV_HTML_STYLE}><h1 style={RED_HTML_STYLE}{str(cdm_connection_state)}</h1></div>"

    except KeyError:
        html = f"<div style={DIV_HTML_STYLE}><h1 style={ORANGE_HTML_STYLE}No State Found</h1></div>"

    demisto.results({
        'ContentsFormat': formats['html'],
        'Type': entryTypes['note'],
        'Contents': html
    })


# python2 uses __builtin__ python3 uses builtins
if __name__ == '__builtin__' or __name__ == 'builtins':
    main()
