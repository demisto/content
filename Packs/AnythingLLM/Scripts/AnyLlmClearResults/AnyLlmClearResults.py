import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    try:
        execute_command("setIncident", {'customFields': {'anythingllmsearchresults': ""}})
    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f'AnyLlmClearResults: error is - {ex}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
