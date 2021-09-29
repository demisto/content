import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from typing import Dict


def get_notable_data_from_incident(incident_id: str) -> Dict[str, str]:
    """
    Args:
        incident_id(str): The identifier of the incident in XSOAR system.

    Returns:
        a dict of the notable data required to run the edit event comand.
    """
    try:
        incidents_data = demisto.executeCommand("getIncidents", {'id': incident_id})[0]['Contents']['data'][0]
        arguments = {"eventIDs": incidents_data['dbotMirrorId']}
        instance = incidents_data.get('sourceInstance')
        if instance:
            arguments["using"] = instance

        return arguments
    except (KeyError, IndexError):
        raise DemistoException('cuold not determine the notable id and mirror instance.') from None


def get_command_args(args: Dict[str, str]) -> Dict[str, str]:
    notable_id = args.get('notable_id')
    incident_id = args.get('incident_id')
    if notable_id:
        return {"eventIDs": notable_id}
    elif incident_id:
        return get_notable_data_from_incident(incident_id)
    else:
        raise DemistoException('you need to specify either notable_id or incident_id (not both).')


def main():
    args = demisto.args()
    command_args = {
        'comment': args['comment'],
        **get_command_args(args)
    }

    if 'incident_id' in args:
        demisto.executeCommand("executeCommandAt", {"command": "splunk-notable-event-edit",
                               "incidents": args['incident_id'], "arguments": command_args})
    else:
        demisto.executeCommand("splunk-notable-event-edit", command_args)

    demisto.results('ok')


if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    main()
