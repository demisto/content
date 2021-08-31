import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import traceback


''' MAIN FUNCTION '''


def main():
    try:
        # Map the incident_markdown parsed before to radarkitems field.
        demisto.executeCommand("setIncident", {"radarkitems": demisto.args().get('itemDetails')['items_markdown']})
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute CreateIndicators. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
