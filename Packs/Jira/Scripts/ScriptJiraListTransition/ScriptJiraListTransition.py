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
        raise DemistoException(f'Error occurred while running script-JiraListTransition. expected a list as response but got:'
                               f' {type(res)}. The response is: {res}')


def get_transitions_from_jirav3_brand(command_execution_response: List[Dict[str, Any]]) -> List[str]:
    """Gets the list of transitions from the CommandResults object returned by the command !jira-list-transitions when
    using the brand Jira V3.

    Args:
        command_execution_response (List[Dict[str, Any]]): The response of the command !jira-list-transitions.

    Returns:
        List[str]: The list of transitions.
    """
    if not command_execution_response:
        raise DemistoException('Got an empty list object after executing the command !jira-list-transitions')
    transition_raw_response = command_execution_response[0].get('Contents', {})
    return [transition.get('name', '') for transition in transition_raw_response.get('transitions', [])]


def get_transition_names_by_source_brand(incident_id: Dict[str, Any], source_brand: str) -> Dict[str, Any]:
    """Gets the list of possible transitions of an incident of type Jira Incident, by calling the command
    !jira-list-transitions, while taking into consideration of we are using Jira V2 or V3, using the `using-brand` argument.

    Args:
        incident_id (Dict[str, Any]): The incident id, which is the Jira issue id.
        source_brand (str): The brand that will run the command, either Jira V3, or jira-v2.

    """
    transitions_names: List[str] = []
    res: List[Dict[str, Any]] = []
    demisto.debug(f'Got the following source brand {source_brand}')
    if source_brand == 'Jira V3':
        res = execute_jira_list_transitions_command(args={'issue_id': incident_id, 'using-brand': source_brand})
        transitions_names = get_transitions_from_jirav3_brand(res)
    elif source_brand == 'jira-v2':
        res = execute_jira_list_transitions_command(args={"issueId": incident_id, 'using-brand': source_brand})
        if not res:
            raise DemistoException('Got an empty list object after executing the command !jira-list-transitions')
        transitions_names = res[0].get('Contents', [])
    else:
        raise DemistoException('No Jira instance was found, please configure the newest Jira Integration')
    if isError(res):
        raise DemistoException(f'Error occurred while running jira-list-transitions. The response is: {res}')
    demisto.debug(f'Got the following transitions: {transitions_names}')
    return {"hidden": False, "options": sorted(transitions_names)}


def main():
    demisto.debug('script-JiraListTransition is being called')
    try:
        incident = demisto.incidents()[0]
        if incident_id := incident.get("dbotMirrorId"):
            output = get_transition_names_by_source_brand(incident_id=incident_id, source_brand=incident.get('sourceBrand', ''))
            return_results(output)
        else:
            raise DemistoException('Error occurred while running script-JiraListTransition because could not get "dbotMirrorId"'
                                    ' from incident.')
    except Exception as ex:
        return_error(f'Error occurred while running script-JiraListTransition. Got the error:\n{ex}')


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
