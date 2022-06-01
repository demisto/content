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
        incident = demisto.incidents()[0]
        incident_id = incident.get("dbotMirrorId")
        if incident_id:
            custom_fields = incident.get("CustomFields")
            if custom_fields:
                chosen_transition = custom_fields.get("jiratransitions")
                if chosen_transition:
                    demisto.executeCommand(
                        "jira-edit-issue",
                        {"issueId": incident_id, "transition": chosen_transition},
                    )
                    res = demisto.executeCommand(
                        "jira-get-issue", {"issueId": incident_id}
                    )
                    if res and isinstance(res, list):
                        for entry in res:
                            if entry.get("Type") == 1:
                                incident_content = entry.get("Contents")
                                if incident_content:
                                    if not isError(entry):
                                        incident_fields = incident_content.get("fields")
                                        if incident_fields:
                                            jira_status = incident_fields.get(
                                                "status", {}
                                            ).get("name")
                                            if jira_status:
                                                demisto.executeCommand(
                                                    "setIncident",
                                                    {"jirastatus": jira_status},
                                                )
                                                demisto.executeCommand(
                                                    "setIncident",
                                                    {"jiratransitions": "Select"},
                                                )
                                                break
                                            else:
                                                output = create_output(
                                                    f"Error occurred while running script-JiraChangeTransition. Could "
                                                    f"not find: the issue's status name. The issue returned is: "
                                                    f"{incident_fields} "
                                                )
                                        else:
                                            output = create_output(
                                                f'Error occurred while running script-JiraChangeTransition. Could not '
                                                f'find:"fields" as key. The issue returned is: {incident_content} '
                                            )
                                    else:
                                        output = create_output(
                                            f"Error occurred while running jira-get-issue. The response is: {incident_content}"
                                        )
                                else:
                                    output = create_output(
                                        f'Error occurred while running script-JiraChangeTransition. Could not find:'
                                        f'"Content" as key. The response is: {res} '
                                    )
                    else:
                        output = create_output(
                            f"Error occurred while running script-JiraChangeTransition. expected a list as response "
                            f"but got: {type(res)}. The response is: {res} "
                        )
                else:
                    output = create_output(
                        'Failed to get "jiratransitions" incident field from incident with {incident_id} dbotMirrorId.'
                    )
            else:
                output = create_output(
                    f'Failed to get "CustomFields" of incident with {incident_id} dbotMirrorId. The incident is:\n'
                    f' {incident} '
                )
        else:
            output = create_output(
                'Failed to get a list of transaction because could not get "dbotMirrorId" from incident.'
            )

    except Exception as ex:
        output = create_output(
            "Error occurred while running script-JiraChangeTransition. got the next error:\n"
            + str(ex)
        )
    finally:
        if output:
            demisto.results(output)


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
