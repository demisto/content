
from CommonServerPython import *
import json


def get_color(cvss):
    colors = {
        'Green1': '#50C878',
        'Green2': '#6CB65B',
        'Green3': '#89C35B',
        'Green4': '#A3C157',
        'Amber1': '#FFB347',
        'Amber2': '#FFA07A',
        'Amber3': '#FF7F50',
        'Red1': '#FF6347',
        'Red2': '#FF4500',
        'Red3': '#FF4040'
    }

    if not 0 < cvss <= 10:
        color = "#000000"
        cvss = ""
    elif cvss <= 4:
        color = colors[f"Green{int(cvss)}"]
    elif cvss <= 7:
        color = colors[f"Amber{int(cvss) - 4}"]
    else:
        color = colors[f"Red{int(cvss) - 7}"]

    return color


def main():
    indicator = demisto.callingContext['args']['indicator']

    try:
        cvss = indicator.get('CustomFields').get('cvss', '')
        cvss = json.loads(cvss)
        cvss = float(cvss['Score'])

    except (ValueError, AttributeError, KeyError):
        cvss = 0

    color = get_color(cvss)
    return_results(CommandResults(readable_output=f"# <-:->{{{{color:{color}}}}}(**{cvss}**)"))


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
    
