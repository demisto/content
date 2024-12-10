import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def add_comment(args: Dict[str, Any]) -> CommandResults:
    incident_id = args.get('id', 'none')
    comment = args.get('comment')
    using = args.get('instance_name')

    command_args = {}

    if incident_id == 'none':
        incident_id = demisto.incident()['CustomFields'].get('microsoft365defenderid')

    command_args['id'] = incident_id
    command_args['comment'] = comment
    command_args['using'] = using

    try:
        demisto.debug(f'Calling microsoft-365-defender-incident-update , {command_args=}')
        command_res = demisto.executeCommand("microsoft-365-defender-incident-update", command_args)
        demisto.debug(f'After calling microsoft-365-defender-incident-update, {command_res=}')
        return command_res

    except Exception as ex1:
        demisto.info(f"Failed to add comment to incident. {type(ex1)}: {ex1}, Trace:\n{traceback.format_exc()}")
        return_error(str(ex1))


def main():
    try:
        res = add_comment(demisto.args())
        return_results(res)

    except Exception as ex2:
        return_error(f'Failed to execute MS365DefenderAddComment. Error: {str(ex2)}')


if __name__ in ["__builtin__", "builtins", '__main__']:
    main()
