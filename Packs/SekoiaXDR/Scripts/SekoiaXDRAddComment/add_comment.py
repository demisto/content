import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():

    alert_short_id = demisto.args().get("short_id")
    comment = demisto.args().get("comment")

    user = execute_command("getUsers", {"current": "true"})[0]["name"]
    execute_command(
        "sekoia-xdr-post-comment-alert",
        {"id": alert_short_id, "comment": comment, "author": user},
    )

    readable_output = f"### Comment added by {user}:\n {comment}"
    demisto.results(
        {
            "ContentsFormat": formats["markdown"],
            "Type": entryTypes["note"],
            "Contents": readable_output,
        }
    )


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
