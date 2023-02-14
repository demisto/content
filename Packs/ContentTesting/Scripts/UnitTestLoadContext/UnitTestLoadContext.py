import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    try:
        incid = demisto.args()['id']
        context = demisto.executeCommand("getContext", {"id": incid})[0]["Contents"]["context"]
        # Set each context value
        for key in context.keys():
            demisto.executeCommand("Set", {"key": key, "value": context[key]})
    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f"UnitTestLoadContext: Exception failed to execute. Error: {str(ex)}")


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
