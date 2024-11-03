import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():  # pragma: no cover
    try:
        apply_status()
    except Exception as exc:
        return_error(f'Failed to execute JiraChangeStatus. Error: {exc}')


def edit_jira_issue_with_status(incident_id: str, status: str) -> Any:
    # We added the argument issue_id to both commands, since in JiraV3, the command expects to receive
    # either issue_id, or issue_key, and not issueId, and in JiraV2, we use the argument issueId.
    demisto.executeCommand(
        "jira-edit-issue",
        {"issueId": incident_id, "status": status, "issue_id": incident_id},
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


def apply_status():
    incident = demisto.incidents()[0]
    if not (incident_id := incident.get("dbotMirrorId")):
        raise DemistoException(
            'Failed to get a list of statuses because could not get "dbotMirrorId" from incident.'
        )

    if not (custom_fields := incident.get("CustomFields")):
        raise DemistoException(
            f'Failed to get "CustomFields" of incident with {incident_id} dbotMirrorId. The incident is:\n'
            f' {incident} '
        )
    if not (chosen_status := custom_fields.get("jirav3status")):
        raise DemistoException(
            f'Failed to get "jirav3status" incident field from incident with {incident_id} dbotMirrorId.'
        )
    res = edit_jira_issue_with_status(incident_id=incident_id, status=chosen_status)
    for entry in res:
        if entry.get("Type") == 1:
            if not (incident_content := entry.get("Contents")):
                raise DemistoException(
                    f'Error occurred while running JiraChangeStatus. Could not find:'
                    f'"Contents" as key. The response is: {res} '
                )
            elif isError(entry):
                raise DemistoException(
                    f"Error occurred while running jira-get-issue. The response is: {incident_content}"
                )
            elif incident_fields := incident_content.get("fields"):
                set_status_and_updated_time_of_incident(incident_fields=incident_fields)
                break
            else:
                raise DemistoException(
                    f'Error occurred while running JiraChangeStatus. Could not '
                    f'find:"fields" as key. The issue returned is: {incident_content} '
                )


def set_status_and_updated_time_of_incident(incident_fields: Dict[str, Any]):
    """Gets the fields of the new edited Jira issue, and updates the JiraV3 Status, and Last Update Time
    Incident Fields.
    """
    if not (jira_status := incident_fields.get("status", {}).get("name")):
        raise DemistoException(
            f"Error occurred while running JiraChangeStatus. Could "
            f"not find: the issue's status name. The issue returned is: "
            f"{incident_fields} "
        )

    demisto.executeCommand(
        "setIncident",
        {"jirav3status": jira_status},
    )
    if updated_time := incident_fields.get('updated'):
        demisto.executeCommand(
            "setIncident",
            {"lastupdatetime": updated_time},
        )
    else:
        raise DemistoException('Error occurred while running JiraChangeStatus'
                                ', could not find the issue\'s updated time. The issue'
                                f' returned is :{incident_fields}')


if __name__ in ["__main__", "builtin", "builtins"]:  # pragma: no cover
    main()
