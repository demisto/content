import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():  # pragma: no cover
    try:
        apply_transition()
    except Exception as exc:
        return_error(f'Failed to execute script-JiraChangeTransition. Error: {exc}')


def edit_jira_issue_with_transition(incident_id: str, transition: str) -> Any:
    # We added the argument issue_id to both commands, since in JiraV3, the command expects to receive
    # either issue_id, or issue_key, and not issueId, and in JiraV2, we use the argument issueId.
    demisto.executeCommand(
        "jira-edit-issue",
        {"issueId": incident_id, "transition": transition, "issue_id": incident_id},
    )
    res = demisto.executeCommand(
        "jira-get-issue", {"issueId": incident_id, "issue_id": incident_id}
    )
    if not res or not isinstance(res, list):
        raise DemistoException(
            f"Error occurred while running JiraChangeStatus. expected a list as response "
            f"but got: {type(res)}. The response is: {res} "
        )
    return res


def apply_transition():
    incident = demisto.incidents()[0]
    if not (incident_id := incident.get("dbotMirrorId")):
        raise DemistoException(
            'Failed to get a list of transactions because could not get "dbotMirrorId" from incident.'
        )

    if not (custom_fields := incident.get("CustomFields")):
        raise DemistoException(
            f'Failed to get "CustomFields" of incident with {incident_id} dbotMirrorId. The incident is:\n'
            f' {incident} '
        )
    if not (chosen_transition := custom_fields.get("jiratransitions")):
        raise DemistoException(
            f'Failed to get "jiratransitions" incident field from incident with {incident_id} dbotMirrorId.'
        )
    res = edit_jira_issue_with_transition(incident_id=incident_id, transition=chosen_transition)
    for entry in res:
        if entry.get("Type") == 1:
            if not (incident_content := entry.get("Contents")):
                raise DemistoException(
                    f'Error occurred while running script-JiraChangeTransition. Could not find:'
                    f'"Content" as key. The response is: {res} '
                )
            if isError(entry):
                raise DemistoException(
                    f"Error occurred while running jira-get-issue. The response is: {incident_content}"
                )
            elif incident_fields := incident_content.get("fields"):
                set_status_and_updated_time_of_incident(incident_fields=incident_fields)
                break
            else:
                raise DemistoException(
                    f'Error occurred while running script-JiraChangeTransition. Could not '
                    f'find:"fields" as key. The issue returned is: {incident_content} '
                )


def set_status_and_updated_time_of_incident(incident_fields: Dict[str, Any]):
    """Gets the fields of the new edited Jira issue, and updates the Jira Status, JiraV3 Status, and Last Update Time
    Incident Fields.
    """
    if not (jira_status := incident_fields.get("status", {}).get("name")):
        raise DemistoException(
            f"Error occurred while running script-JiraChangeTransition. Could "
            f"not find: the issue's status name. The issue returned is: "
            f"{incident_fields} "
        )

    # We set for both jirastatus, and jirav3status since this script works for both Jira V3 and Jira V2.
    demisto.executeCommand(
        "setIncident",
        {"jirastatus": jira_status},
    )
    demisto.executeCommand(
        "setIncident",
        {"jirav3status": jira_status},
    )
    demisto.executeCommand(
        "setIncident",
        {"jiratransitions": "Select"},
    )
    if updated_time := incident_fields.get('updated'):
        demisto.executeCommand(
            "setIncident",
            {"lastupdatetime": updated_time},
        )
    else:
        raise DemistoException(('Error occurred while running script-JiraChangeTransition'
                                ', could not find the issue\'s updated time. The issue'
                                f' returned is :{incident_fields}'))


if __name__ in ["__main__", "builtin", "builtins"]:  # pragma: no cover
    main()
