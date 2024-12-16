import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main() -> None:
    """
    This function is the main entry point of the program. It retrieves the number of files with hits
    from the demisto context and generates an HTML string based on the number of files. If there are no files
    with hits, the HTML string will display a green message. If there are files with hits, the HTML
    string will display a red message. If the context does not contain the necessary information, the HTML
    string will display an orange message. The HTML string is then returned as a result.

    Raises:
        KeyError: If the necessary information is not found in the demisto context.
    """

    ORANGE_HTML_STYLE = "color:#FF9000;font-size:250%;>"
    GREEN_HTML_STYLE = "color:#00CD33;font-size:275%;>"
    RED_HTML_STYLE = "color:#FF1744;font-size:275%;>"
    DIV_HTML_STYLE = "display:block;text-align:center;"

    try:
        radar_open_access_files = demisto.context()["Rubrik"]["Sonar"]["filesWithHits"]

        if not radar_open_access_files:
            html = f"<div style={DIV_HTML_STYLE}><h1 style={GREEN_HTML_STYLE}{str(radar_open_access_files)}</h1></div>"
        else:
            html = f"<div style={DIV_HTML_STYLE}><h1 style={RED_HTML_STYLE}{str(radar_open_access_files)}</h1></div>"

    except KeyError:
        html = f"<div style={DIV_HTML_STYLE}><h1 style={ORANGE_HTML_STYLE}No Results Found</h1></div>"

    return_results({
        'ContentsFormat': formats['html'],
        'Type': entryTypes['note'],
        'Contents': html
    })


# python2 uses __builtin__ python3 uses builtins
if __name__ == '__builtin__' or __name__ == 'builtins':
    main()
