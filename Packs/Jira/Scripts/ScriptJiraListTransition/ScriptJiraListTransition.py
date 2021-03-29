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
        incident_id = demisto.incidents()[0].get("dbotMirrorId")
        if incident_id:
            res = demisto.executeCommand(
                "jira-list-transitions", {"issueId": incident.get("dbotMirrorId")}
            )
            if res and isinstance(res, list):
                transitions_names = res[0].get("Contents")
                if transitions_names:
                    if not isError(res):
                        output = {"hidden": False, "options": sorted(transitions_names)}
                    else:
                        output = create_output(
                            f"Error occurred while running jira-list-transitions. The response is: {transitions_names}"
                        )
                else:
                    output = create_output(
                        f'Error occurred while running script-JiraListTransition. Could not find:"Content" as key. '
                        f'The response is: {res} '
                    )
            else:
                output = create_output(
                    f"Error occurred while running script-JiraListTransition. expected a list as response but got:"
                    f" {type(res)}. The response is: {res}"
                )
        else:
            output = create_output(
                'Error occurred while running script-JiraListTransition because could not get "dbotMirrorId" from '
                'incident. '
            )
    except Exception as ex:
        output = create_output(
            "Error occurred while running script-JiraListTransition. got the next error:\n"
            + str(ex)
        )
    finally:
        demisto.results(output)


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
