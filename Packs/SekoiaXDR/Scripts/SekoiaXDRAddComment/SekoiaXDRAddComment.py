import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def get_username():
    get_users = execute_command("getUsers", {"current": "true"})
    username = get_users[0]["name"]  # type: ignore
    return username


def post_comment(alert_short_id: str, comment: Optional[str], author: str):
    try:
        execute_command(
            "sekoia-xdr-post-comment-alert",
            {"id": alert_short_id, "comment": comment, "author": author},
        )
    except Exception as e:
        return_error(
            f"Failed to post comment for alert with id {alert_short_id} : {str(e)}"
        )


def main():
    alert_short_id = demisto.args()["short_id"]
    comment = demisto.args().get("comment")

    user = get_username()
    post_comment(alert_short_id, comment, user)
    readable_output = f"### Comment added by {user}:\n {comment}"

    command_results = CommandResults(readable_output=readable_output)
    return_results(command_results)


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
