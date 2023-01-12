import demistomock as demisto
from CommonServerPython import *


def main():
    try:
        incident = demisto.incidents()
        query = incident[0].get('CustomFields', {}).get('breachconfirmation', "Pending Confirmation")
        color = 'green'
        header = 'Pending Confirmation'

        if query == "Confirm":
            color = 'red'
            header = 'Confirmed'

        elif query == "Not Confirm":
            color = 'blue'
            header = "Not Confirmed"

        html = f"<div style='color:{color};'><h2>{header}</h2></div>"
        demisto.results({
            'ContentsFormat': formats['html'],
            'Type': entryTypes['note'],
            'Contents': html
        })

    except Exception as ex:
        return_error(f'Failed to execute calculate entropy script. Error: {str(ex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
