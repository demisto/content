import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


''' MAIN FUNCTION '''


def main():
    try:
        branches = ['']

        res = demisto.executeCommand('GetIncidentsByQuery', {'incidentTypes': "Pull Request Creation"})
        if isError(res):
            return_error(f'Error occurred while trying to get incidents by query: {get_error(res)}')

        incidents_from_query = json.loads(res[0]['Contents'])
        for incident in incidents_from_query:
            branch = incident.get('CustomFields', {}).get('branch')
            if branch:
                branches.append(branch)

        output = {"hidden": False, "options": sorted(branches)}
        return_results(output)

    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute script. Error: {str(traceback.format_exc())}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
