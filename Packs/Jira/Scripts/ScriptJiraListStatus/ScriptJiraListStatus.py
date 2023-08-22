import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def execute_jira_list_transitions_command(args: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Execute the command !jira-list-transitions with respect to the arguments `args`, which will hold the issue id
    and which brand to use, Jira V3, or V2.

    Args:
        args (Dict[str, Any]): The arguments of the command.
    Returns:
        List[Dict[str, Any]]: The results of the executed command.
    """
    demisto.debug(f'Got the following args {args}')
    res = demisto.executeCommand(
        "jira-list-transitions", args
    )
    if res and isinstance(res, list):
        return res
    else:
        raise DemistoException(f'Error occurred while running JiraListStatus, expected a list as response but got:'
                               f' {type(res)}. The response is: {res}')


def extract_statuses_from_transition_response(command_execution_response: List[Dict[str, Any]]) -> List[str]:
    """Gets the list of statuses from the CommandResults object returned by the command !jira-list-transitions when
    using the brand Jira V3.

    Args:
        command_execution_response (List[Dict[str, Any]]): The response of the command !jira-list-transitions.

    Returns:
        List[str]: The list of statuses.
    """
    if not command_execution_response:
        raise DemistoException('Got an empty list object after executing the command !jira-list-transitions')
    transition_raw_response = command_execution_response[0].get('Contents', {})
    return [transition.get('to', {}).get('name', '') for transition in transition_raw_response.get('transitions', [])]


def get_status_names_by_source_brand(incident_id: Dict[str, Any], source_brand: str) -> Dict[str, Any]:
    """Gets the list of possible statuses of an incident of type Jira Incident, by calling the command
    !jira-list-transitions, while taking into consideration if we are using Jira V2 or V3, using the `using-brand` argument.

    Args:
        incident_id (Dict[str, Any]): The incident id, which is the Jira issue id.
        source_brand (str): The brand that will run the command, either Jira V3, or jira-v2.

    """
    statuses_names: List[str] = []
    res: List[Dict[str, Any]] = []
    args = {}
    demisto.debug(f'Got the following source brand {source_brand}')
    if source_brand == 'Jira V3':
        args = {'issue_id': incident_id, 'using-brand': source_brand}
    elif source_brand == 'jira-v2':
        args = {"issueId": incident_id, 'using-brand': source_brand}
    else:
        raise DemistoException('No Jira instance was found, please configure the newest Jira Integration')
    res = execute_jira_list_transitions_command(args=args)
    statuses_names = extract_statuses_from_transition_response(command_execution_response=res)
    if isError(res):
        raise DemistoException(f'Error occurred while running jira-list-transitions. The response is: {res}')
    demisto.debug(f'Got the following statuses: {statuses_names}')
    return {"hidden": False, "options": sorted(statuses_names)}


def main():
    demisto.debug('JiraListStatus is being called')
    try:
        incident = demisto.incidents()[0]
        if incident_id := incident.get("dbotMirrorId"):
            output = get_status_names_by_source_brand(incident_id=incident_id, source_brand=incident.get('sourceBrand', ''))
            return_results(output)
        else:
            raise DemistoException('Error occurred while running JiraListStatus because could not get "dbotMirrorId" from'
                                    ' incident.')
    except Exception as ex:
        return_error(f'Error occurred while running JiraListStatus. Got the error:\n{ex}')


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
