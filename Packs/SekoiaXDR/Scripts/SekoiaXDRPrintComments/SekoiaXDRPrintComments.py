import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():

    incident = demisto.incident()
    alert_short_id = incident.get("CustomFields", {}).get("alertid")
    readable_output = (
        "### Comments:\n ### {{color:green}}(There is no comments in this alert.)"
    )

    try:
        comments = execute_command("sekoia-xdr-get-comments", {"id": alert_short_id})
    except Exception as e:
        return_error(f"Failed to get comments: {str(e)}")

    if len(comments) > 0:  # type: ignore
        readable_comment = []
        for comment in comments:  # type: ignore
            new_item = {
                "date": comment["date"],  # type: ignore
                "comment": comment["content"],  # type: ignore
                "user": comment["user"],  # type: ignore
            }
            readable_comment.append(new_item)

        headers = ["date", "comment", "user"]
        readable_output = tableToMarkdown(
            "Comments:", readable_comment, headers=headers
        )

    command_results = CommandResults(readable_output=readable_output)
    return_results(command_results)


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
