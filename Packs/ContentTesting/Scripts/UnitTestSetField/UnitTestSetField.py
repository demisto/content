import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    try:
        key = demisto.args()['field']
        value = demisto.args()['value']
        # Set incident field
        demisto.executeCommand("setIncident", {key: value})
    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f"UnitTestSetField: Exception failed to execute. Error: {str(ex)}")


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
