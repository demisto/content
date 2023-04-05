import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def create_output(error_msg):
    return {
        "Type": entryTypes["error"],
        "ContentsFormat": formats["text"],
        "Contents": error_msg,
        "HumanReadable": error_msg,
        "ReadableContentsFormat": formats["text"],
    }


def execute_xsoar_command(args: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Execute the command !jira-list-transitions with respect to the arguments `args`, which will hold the issue id
    and which brand to use, Jira V3, or V2.

    Args:
        args (Dict[str, Any]): The arguments of the command.
    Returns:
        List[Dict[str, Any]]: The results of the executed command.
    """
    demisto.info(f'got the following args {args}')
    res = demisto.executeCommand(
        "jira-list-transitions", args
    )
    if res and isinstance(res, list):
        return res
    else:
        raise DemistoException((f'Error occurred while running script-JiraListStatus, expected a list as response but got:'
                               f' {type(res)}. The response is: {res}'))


def get_transitions_from_jirav3_brand(command_execution_response: List[Dict[str, Any]]) -> List[str]:
    """Gets the list of transitions from the CommandResults object returned by the command !jira-list-transitions when
    using the brand Jira V3.

    Args:
        command_execution_response (List[Dict[str, Any]]): The response of the command !jira-list-transitions.

    Returns:
        List[str]: The list of transitions.
    """
    return command_execution_response[0].get('EntryContext', {}).get('Ticket(val.Id && val.Id == obj.Id)', {}).\
        get('Transitions', {}).get('transitions', [])


def extract_statuses_from_transition_response(command_execution_response: List[Dict[str, Any]]) -> List[str] | Any:
    if not command_execution_response:
        raise DemistoException('Got an empty list after executing the command !jira-list-transitions')
    transition_raw_response = command_execution_response[0].get('Contents', {})
    return [transition.get('to', {}).get('name', '') for transition in transition_raw_response.get('transitions', {})]


def get_status_names_by_source_brand(incident_id: Dict[str, Any], source_brand: str) -> Dict[str, Any]:
    """Gets the list of possible transitions of an incident of type Jira Incident, by calling the command
    !jira-list-transitions, while taking into consideration of we are using Jira V2 or V3, using the `using-brand` argument.

    Args:
        incident_id (Dict[str, Any]): The incident id, which is the Jira issue id.
        source_brand (str): The brand that will run the command, either Jira V3, or jira-v2.

    """
    statuses_names: List[str] = []
    res: List[Dict[str, Any]] = []
    args = {}
    demisto.debug(f'Got the following sourceBrand {source_brand}')
    if source_brand == 'Jira V3':
        args = {'issue_id': incident_id, 'using-brand': source_brand}
    elif source_brand == 'jira-v2':
        args = {"issueId": incident_id, 'using-brand': source_brand}
    else:
        raise DemistoException('No Jira instance was found, please configure the newest Jira Integration')
    res = execute_xsoar_command(args=args)
    statuses_names = extract_statuses_from_transition_response(command_execution_response=res)
    if isError(res):
        raise DemistoException(f'Error occurred while running jira-list-transitions. The response is: {res}')
    demisto.debug(f'Got the following transitions: {statuses_names}')
    return {"hidden": False, "options": sorted(statuses_names)}


def main():
    demisto.debug('ScriptJiraListStatus is being called')
    output = {}
    try:
        incident = demisto.incidents()[0]
        # incident_id = incident.get("dbotMirrorId")
        if incident_id := incident.get("dbotMirrorId"):
            output = get_status_names_by_source_brand(incident_id=incident_id, source_brand=incident.get('sourceBrand', ''))
        else:
            output = create_output(
                'Error occurred while running script-JiraListStatus because could not get "dbotMirrorId" from '
                'incident. '
            )
    except Exception as ex:
        output = create_output(
            "Error occurred while running script-JiraListStatus. got the next error:\n"
            + str(ex)
        )
    finally:
        demisto.results(output)


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
