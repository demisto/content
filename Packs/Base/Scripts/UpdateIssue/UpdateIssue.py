import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    args = demisto.args()
    issue_id = args.pop("id", None)
    systems = args.pop("systems", None)
    command_executed = False
    try:
        if systems:  # ensures that more than issue_id presents
            demisto.debug(f"Calling setIssue with {systems}")
            command_executed = True
            execute_command("setIssue", {"systems": systems, "id": issue_id})

        if len(args) > 0:
            demisto.debug(f"Calling core-update-issue with {args}")
            command_executed = True
            args["id"] = issue_id
            execute_command("core-update-issue", args)

        if command_executed:
            return_results("done")
        else:
            return_error("Please provide arguments to update the issue.")

    except Exception as e:
        return_error(f"Failed to execute script.\nError:\n{e!s}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
