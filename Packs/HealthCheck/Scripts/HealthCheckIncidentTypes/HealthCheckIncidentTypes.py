import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def filter_non_locked(res):
    nonLockedTypes = list(filter(lambda x: x['locked'] is False or x['detached'] is True, res))
    return nonLockedTypes


def main():
    incident = demisto.incidents()[0]
    account_name = incident.get('account')
    account_name = f"acc_{account_name}" if account_name != "" else ""

    res = execute_command(
        "demisto-api-get",
        {
            "uri": f"{account_name}/incidenttype"
        })['response']

    nonLockedTypes = filter_non_locked(res)

    table = []
    for incident_type in nonLockedTypes:
        newEntry = {}
        extract_settings = incident_type['extractSettings']
        if extract_settings['mode'] == 'All':
            newEntry['incidenttype'] = incident_type['prevName']
            newEntry['detection'] = "Indicators extraction defined on all fields"
            table.append(newEntry)
        elif extract_settings['mode'] == 'Specific' and extract_settings['fieldCliNameToExtractSettings']:
            newEntry['incidenttype'] = incident_type['prevName']
            newEntry['detection'] = "No indicators extraction defined on all fields"
            table.append(newEntry)
        else:
            continue
    execute_command("setIncident", {"healthcheckautoextractionbasedincidenttype": table})


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
