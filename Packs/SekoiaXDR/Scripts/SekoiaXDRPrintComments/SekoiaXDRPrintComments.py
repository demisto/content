import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def create_comment_object(comments):
    return [
        {
            "date": comment_item["date"],
            "comment": comment_item["content"],
            "user": comment_item["user"],
        }
        for comment_item in comments
    ]


def get_comments(alert_id: str):
    readable_output = ""
    try:
        comments = execute_command("sekoia-xdr-get-comments", {"id": alert_id})
    except Exception as e:
        return_error(f"Failed to get comments: {str(e)}")

    if len(comments) > 0:  # type: ignore
        readable_comments = create_comment_object(comments)
        headers = ["date", "comment", "user"]
        readable_output = tableToMarkdown(
            "Comments:", readable_comments, headers=headers
        )
    else:
        readable_output = (
            "### Comments:\n ### {{color:green}}(There is no comments in this alert.)"
        )

    return readable_output


def main():
    incident = demisto.incident()
    alert_short_id = incident.get("CustomFields", {}).get("alertid")

    readable_output = get_comments(alert_short_id)

    command_results = CommandResults(readable_output=readable_output)
    return_results(command_results)


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
