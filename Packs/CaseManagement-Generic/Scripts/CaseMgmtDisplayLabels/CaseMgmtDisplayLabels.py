import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    try:
        labels = demisto.incident().get('labels', [])
        if labels:
            readable = tableToMarkdown("Alert Information", labels)
        else:
            readable = "No labels found on Incident"

        return_results(CommandResults(readable_output=readable, ignore_auto_extract=True))
    except Exception as ex:
        return_results(f'Failed to execute BaseScript. Error: {str(ex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
