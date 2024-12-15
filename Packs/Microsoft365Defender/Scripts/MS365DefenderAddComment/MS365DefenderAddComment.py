import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def add_comment(args: Dict[str, Any]) -> CommandResults:
    """
    Add comment to incident in Microsoft 365 Defender using the Microsoft 365 Defender integration incident update command.
    Args:
        args(Dict[str, Any]): Demisto arguments.
            id: The incident id.
            comment: The comment to add.
            instance_name: The instance name.
    Returns:
        CommandResults: The command results.
    """
    incident_id = args.get('id', 'none')
    comment = args.get('comment')
    using = args.get('instance_name')

    command_args = {}

    if incident_id == 'none':
        incident_id = demisto.incident()['CustomFields'].get('microsoft365defenderid')

    command_args['id'] = incident_id
    command_args['comment'] = comment
    command_args['using'] = using

    demisto.debug(f'Calling microsoft-365-defender-incident-update , {command_args=}')
    command_res = demisto.executeCommand("microsoft-365-defender-incident-update", command_args)
    demisto.debug(f'After calling microsoft-365-defender-incident-update, {command_res=}')
    return command_res


def main():
    try:
        res = add_comment(demisto.args())
        return_results(res)

    except Exception as e:
        return_error(f'Failed to execute MS365DefenderAddComment. Error: {str(e)}')


if __name__ in ["__builtin__", "builtins", '__main__']:
    main()
