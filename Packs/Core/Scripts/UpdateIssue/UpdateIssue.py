import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def map_to_command_args(args: dict) -> tuple[dict, dict]:
    set_issue_args = ["systems", "type", "custom_fields", "details"]
    update_issue_args = ["name", "assigned_user_mail", "severity", "occurred", "phase"]

    set_issue_args_dict = {}
    update_issue_args_dict = {}

    for arg, value in args.items():
        if arg in set_issue_args:
            if arg == "custom_fields":
                set_issue_args_dict["customFields"] = value
            else:
                set_issue_args_dict[arg] = value

        elif arg in update_issue_args:
            update_issue_args_dict[arg] = value

    return set_issue_args_dict, update_issue_args_dict


def main():
    args = demisto.args()
    issue_id = args.pop("id", None)
    set_issue_args_dict, update_issue_args_dict = map_to_command_args(args)
    command_executed = False
    try:
        if len(set_issue_args_dict) > 0:  # ensures that more than issue_id presents
            demisto.debug(f"Calling setIssue with {set_issue_args_dict}")
            command_executed = True
            set_issue_args_dict["id"] = issue_id
            execute_command("setIssue", set_issue_args_dict)

        if len(update_issue_args_dict) > 0:
            demisto.debug(f"Calling core-update-issue with {update_issue_args_dict}")
            command_executed = True
            update_issue_args_dict["id"] = issue_id
            execute_command("core-update-issue", update_issue_args_dict)

        if command_executed:
            return_results("done")
        else:
            return_error("Please provide arguments to update the issue.")

    except Exception as e:
        return_error(f"Failed to execute script.\nError:\n{e!s}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
