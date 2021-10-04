import demistomock as demisto
from CommonServerPython import *
import traceback


def get_html_representation(dbotscore) -> str:
    html = "<div style='color:grey; text-align:center;'><h1>0<br/>Unknown</h1></div>"
    if dbotscore == 1:
        html = "<div style='color:green; text-align:center;'><h1>1<br/>Good</h1></div>"
    elif dbotscore == 2:
        html = "<div style='color:orange; text-align:center;'><h1>2<br/>Suspicious</h1></div>"
    elif dbotscore == 3:
        html = "<div style='color:red; text-align:center;'><h1>3<br/>Bad</h1></div>"
    return html


def main() -> None:
    try:
        dbotscore = demisto.incidents()[0].get('CustomFields').get('chronicledbotscore', 0)
        html = get_html_representation(dbotscore)

        demisto.results({
            "Type": 1,
            "ContentsFormat": formats["html"],
            "Contents": html
        })

    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Could not load widget:\n{e}')


# python2 uses __builtin__ python3 uses builtins
if __name__ == '__builtin__' or __name__ == 'builtins':
    main()
