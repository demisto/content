import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def map_to_command_args(args) -> tuple[dict, dict]:
    set_issue_args = ["owner", "systems", "labels", "add_labels", "type", "replace_playbook", "custom_fields", "details"]
    update_issue_args = ["name", "assigned_user_mail", "severity", "occurred", "phase"]

    set_issue_args_dict = {}
    update_issue_args_dict = {}

    for arg, value in args.items():
        if arg in set_issue_args:
            if arg == "add_labels":
                set_issue_args_dict["addLabels"] = value
            elif arg == "replace_playbook":
                set_issue_args_dict["replacePlaybook"] = value
            elif arg == "custom_fields":
                set_issue_args_dict["customFields"] = value
            else:
                set_issue_args_dict[arg] = value

        elif arg in update_issue_args:
            update_issue_args_dict[arg] = value

        elif arg == "id":
            set_issue_args_dict[arg] = value
            update_issue_args_dict[arg] = value

    return set_issue_args_dict, update_issue_args_dict


def main():
    args = demisto.args()
    set_issue_args_dict, update_issue_args_dict = map_to_command_args(args)
    issue_id = args.get("id")
    len_set = len(set_issue_args_dict)
    len_update = len(update_issue_args_dict)
    if issue_id:
        len_set = len_set - 1
        len_update = len_update - 1

    flag = False
    try:
        if len_set > 0:  # ensures that more than issue_id presents
            demisto.debug(f"Calling setIssue with {set_issue_args_dict}")
            flag = True
            execute_command("setIssue", set_issue_args_dict)

        if len_update:
            demisto.debug(f"Calling core-update-issue with {update_issue_args_dict}")
            flag = True
            execute_command("core-update-issue", update_issue_args_dict)

        if flag:
            return_results("done")
        else:
            return_error("Please provide arguments to update the issue.")

    except Exception as e:
        return_error(f"Failed to execute script.\nError:\n{e!s}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
