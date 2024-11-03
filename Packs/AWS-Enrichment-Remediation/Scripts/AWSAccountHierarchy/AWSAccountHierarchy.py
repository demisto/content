import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from typing import Any
import traceback


""" STANDALONE FUNCTION """


def lookup(parent_obj: str, level: int, instance_to_use: str) -> tuple[str, dict]:
    """
    Lookup information on a organization unit (ou) or root object. Unless the current lookup
    is a root object, it returns parent object to lookup and results of current lookup.
    Args:
        parent_obj (str): root/ou object in number format.
        level (int): the current level that the object is (ascending).
        instance_to_use (str): what integration instance to use.

    Returns:
        str: parent object to look up next or "NONE" for error handling and "stop" if no parent.
        dict: dictionary of id, name and level of the lookup object.

    """
    temp: dict[str, str] = {}
    try:
        if "ou-" in parent_obj:
            ou_info = execute_command(
                "aws-org-organization-unit-get",
                {"organization_unit_id": parent_obj, "using": instance_to_use},
            )
            if not ou_info:
                return "NONE", temp
            temp["level"] = str(level)
            temp["id"] = ou_info.get("Id", "")
            temp["name"] = ou_info.get("Name", "")
            temp["arn"] = ou_info.get("Arn", "")
            ou_parent = execute_command(
                "aws-org-parent-list",
                {"child_id": parent_obj, "using": instance_to_use},
            )
            if not ou_parent:
                return "NONE", temp
            next_one = ou_parent[0].get("Id", "")
        elif "r-" in parent_obj:
            next_one = "stop"
            root_info = execute_command("aws-org-root-list", {"using": instance_to_use})
            if not root_info:
                return "NONE", temp
            root = root_info.get("AWS.Organizations.Root(val.Id && val.Id == obj.Id)")[
                0
            ]
            temp["level"] = str(level)
            temp["id"] = root.get("Id", "")
            temp["name"] = root.get("Name", "")
            temp["arn"] = root.get("Arn", "")
        else:
            raise ValueError("unexpected object type")
    except TypeError:
        return "NONE", temp
    else:
        return next_one, temp


""" COMMAND FUNCTION """


def aws_account_heirarchy(args: dict[str, Any]) -> CommandResults:
    """
    Determine AWS account hierarchy by looking up parent objects until the root level is reached.
    Args:
        args (dict): Command arguments from XSOAR.

    Returns:
        list[CommandResults]: outputs, readable outputs and raw response for XSOAR.

    """

    account_id = args.get("account_id")

    if not account_id:
        raise ValueError("account_id not specified")
    # Using `demisto.executeCommand` instead of `execute_command` because for
    # multiple integration instances we can expect one too error out.
    account_info = demisto.executeCommand(
        "aws-org-account-list", {"account_id": account_id}
    )
    account_returned = [
        account
        for account in account_info
        if (not isError(account) and account.get("Contents").get("Arn"))
    ]
    if not account_returned:
        return CommandResults(readable_output="could not find specified account info")
    else:
        match_account = account_returned[0].get("Contents")
        instance_to_use = account_returned[0]["Metadata"]["instance"]
    level = 1
    hierarchy = [
        {
            "level": "account",
            "id": match_account.get("Id", ""),
            "name": match_account.get("Name", ""),
            "arn": match_account.get("Arn", ""),
        }
    ]
    account_parent = demisto.executeCommand(
        "aws-org-parent-list", {"child_id": account_id, "using": instance_to_use}
    )
    if isError(account_parent):
        return CommandResults(readable_output="could not find specified account parent")
    next_one, to_append = lookup(
        account_parent[0].get("Contents", {})[0].get("Id", ""), level, instance_to_use
    )
    if next_one == "NONE":
        return CommandResults(readable_output="could not find specified ou/root info")
    hierarchy.append(to_append)
    try:
        while "stop" not in next_one:
            level += 1
            next_one, to_append = lookup(next_one, level, instance_to_use)
            if next_one == "NONE" or next_one is None:
                return CommandResults(
                    readable_output="could not find specified ou/root info"
                )
            hierarchy.append(to_append)
    except TypeError:
        return CommandResults(readable_output="could not find specified ou/root info")

    return CommandResults(
        outputs_prefix="AWSHierarchy",
        outputs_key_field="level",
        outputs=hierarchy,
    )


""" MAIN FUNCTION """


def main():
    try:
        return_results(aws_account_heirarchy(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Failed to execute AWSAccountHierarchy. Error: {str(ex)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
