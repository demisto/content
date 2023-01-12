import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


''' MAIN FUNCTION '''


def main():
    try:
        branches = ['']

        res = execute_command('GetIncidentsByQuery', {'incidentTypes': "Pull Request Creation"})

        incidents_from_query = json.loads(res)
        for incident in incidents_from_query:
            branch = incident.get('CustomFields', {}).get('cicdbranch')
            if branch:
                branches.append(branch)

        output = {"hidden": False, "options": sorted(branches)}
        return_results(output)

    except Exception as ex:
        demisto.error(str(ex))  # print the traceback
        return_error(f'Failed to execute script. Error: {ex}', error=ex)


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
