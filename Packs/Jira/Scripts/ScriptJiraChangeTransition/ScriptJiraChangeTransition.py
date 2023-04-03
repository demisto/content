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


def main():
    output = {}
    try:
        apply_transition()
    except Exception as e:
        output = create_output(
            ('Error occurred while running script-JiraChangeTransition. got the next error:\n'
             f'{e}')
        )
    finally:
        if output:
            demisto.results(output)


def apply_transition():
    incident = demisto.incidents()[0]
    if not (incident_id := incident.get("dbotMirrorId")):
        raise DemistoException(
            'Failed to get a list of transaction because could not get "dbotMirrorId" from incident.'
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
    # We added the argument issue_id to both commands, since in JiraV3, the command expects to receive
    # either issue_id, or issue_key, and not issueId, and in JiraV2, we use the argument issueId.
    demisto.executeCommand(
        "jira-edit-issue",
        {"issueId": incident_id, "transition": chosen_transition, "issue_id": incident_id},
    )
    res = demisto.executeCommand(
        "jira-get-issue", {"issueId": incident_id, "issue_id": incident_id}
    )
    if not res or not isinstance(res, list):
        raise DemistoException(
            f"Error occurred while running script-JiraChangeTransition. expected a list as response "
            f"but got: {type(res)}. The response is: {res} "
        )
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
            elif incident_fields := incident_content.get(
                "fields"
            ):
                if not (
                    jira_status := incident_fields.get("status", {}).get(
                        "name"
                    )
                ):
                    raise DemistoException(
                        f"Error occurred while running script-JiraChangeTransition. Could "
                        f"not find: the issue's status name. The issue returned is: "
                        f"{incident_fields} "
                    )

                demisto.executeCommand(
                    "setIncident",
                    {"jirastatus": jira_status},
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
                break
            else:
                raise DemistoException(
                    f'Error occurred while running script-JiraChangeTransition. Could not '
                    f'find:"fields" as key. The issue returned is: {incident_content} '
                )


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
