from typing import Tuple

from CommonServerPython import *

''' STANDALONE FUNCTION '''

INCIDENT_ID = demisto.incident().get('id')

XDR_ACTIONS = {
    'isolate': 'xdr-isolate-endpoint',
    'unisolate': 'xdr-unisolate-endpoint'
}

MSDE_ACTIONS: Dict[str, Tuple[str, Dict[str, str]]] = {
    'isolate': ('microsoft-atp-isolate-machine', {'isolation_type': 'Full'}),
    'unisolate': ('microsoft-atp-unisolate-machine', {})
}

CROWDSTRIKE_ACTIONS = {
    'isolate': 'cs-falcon-contain-host',
    'unisolate': 'cs-falcon-lift-host-containment'
}

CROWDSTRIKE_HASH_ACTIONS = {
    'allow': {'action': 'allow',
              'description': f'Whitelisted based on XSOAR inc {INCIDENT_ID}',
              'severity': 'low'},
    'block': {'action': 'prevent',
              'description': f'Blacklisted based on XSOAR inc {INCIDENT_ID}',
              'severity': 'high'}
}


def create_commands(device_ids: List[str], action: str) -> List[CommandRunner.Command]:
    """
    Create a list of `Command` of the isolate/unisolate command to `Cortex XDR`, `CrowdstrikeFalcon`,
     `Microsoft Defender Advanced Threat Protection`

    :param device_ids: The device id's to run
    :param action: The action to have (one of {'isolate', 'unisolate'})
    :return: A list of `Command`
    """
    msde_command, msde_args = MSDE_ACTIONS[action]
    msde_args.update({'machine_id': ','.join(device_ids),
                      'comment': f'XSOAR - related incident {INCIDENT_ID}'})
    return [CommandRunner.Command(commands=XDR_ACTIONS.get(action),
                                  args_lst=[{'endpoint_id': device_id} for device_id in device_ids]),
            CommandRunner.Command(commands=msde_command,
                                  args_lst=msde_args),
            CommandRunner.Command(commands=CROWDSTRIKE_ACTIONS.get(action),
                                  args_lst={'ids': ','.join(device_ids)})]


def run_isolation_action(device_ids: List[str], action: str) -> list:
    """
    Given arguments to the command, returns a list of results to return

    :param device_ids: List of device ids
    :param action: The action to perform (isolate or unisolate)

    :return: list of results to return
    :rtype: ``list``
    """

    commands = create_commands(device_ids, action)
    return CommandRunner.run_commands_with_summary(commands)


''' MAIN FUNCTION '''


def main():  # pragma: no cover
    args = demisto.args()
    device_ids = argToList(args.get('device_ids'))
    if not device_ids:
        raise ValueError('hash not specified')
    action = args.get('action')
    if not action or action not in {'isolate', 'unisolate'}:
        raise ValueError('Action not specified or not in allowed actions')

    try:
        return_results(run_isolation_action(device_ids, action))
    except Exception as ex:
        return_error(f'Failed to execute IsolationAssetWrapper. Error: {str(ex)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
