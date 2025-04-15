import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    try:
        inci = demisto.incident()['CustomFields']
        search_results = inci.get("anythingllmsearchresults", "")
        if search_results != "":
            execute_command("setIncident", {'customFields': {'anythingllmnewcontext': search_results}})
    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f'AnyLlmAddResultsConvo: error is - {ex}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
