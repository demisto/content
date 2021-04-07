import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    try:
        incident = demisto.incident()
        magnitude = incident.get('CustomFields', {}).get('magnitudeoffense', 0)  # define which incident field to use

        if 8 <= magnitude <= 10:
            magnitude = str(magnitude)
            html = "<h1 style='color:#D13C3C;text-align:center;'>" + magnitude + "</h1>"

        elif 4 <= magnitude <= 7:
            magnitude = str(magnitude)
            html = "<h1 style='color:#D17D00;text-align:center;'>" + magnitude + "</h1>"

        else:
            magnitude = str(magnitude)
            html = "<h1 style='color:#1DB846;text-align:center;'>" + magnitude + "</h1>"

        return {
            'ContentsFormat': formats['html'],
            'Type': entryTypes['note'],
            'Contents': html
        }

    except Exception as exp:
        return_error('could not parse QRadar assets', error=exp)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    return_results(main())
