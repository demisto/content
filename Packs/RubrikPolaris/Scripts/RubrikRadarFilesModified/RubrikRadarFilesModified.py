import demistomock as demisto  # noqa: F401
from CommonServerPython import *


def main() -> None:

    ORANGE_HTML_STYLE = "color:#FF9000;font-size:275%;>"
    GREEN_HTML_STYLE = "color:#00CD33;font-size:275%;>"
    RED_HTML_STYLE = "color:#FF1744;font-size:275%;>"
    DIV_HTML_STYLE = "display:block;text-align:center;"

    try:
        radar_files_modified = demisto.executeCommand("Print", {"value": "${incident.labels.radar_files_modified}"})
        radar_files_modified = radar_files_modified[0]["Contents"]

        if not radar_files_modified:
            html = f"<div style={DIV_HTML_STYLE}><h1 style={GREEN_HTML_STYLE}{str(radar_files_modified)}</h1></div>"
        else:
            html = f"<div style={DIV_HTML_STYLE}><h1 style={RED_HTML_STYLE}{str(radar_files_modified)}</h1></div>"

    except KeyError:
        html = f"<div style={DIV_HTML_STYLE}><h1 style={ORANGE_HTML_STYLE}No Results Found</h1></div>"

    demisto.results({
        'ContentsFormat': formats['html'],
        'Type': entryTypes['note'],
        'Contents': html
    })


# python2 uses __builtin__ python3 uses builtins
if __name__ == '__builtin__' or __name__ == 'builtins':
    main()
