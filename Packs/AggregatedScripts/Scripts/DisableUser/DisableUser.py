import demistomock as demisto
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]
from CommonServerUserPython import *  # noqa: E402 lgtm [py/polluting-import]

from typing import Literal, TypedDict
from collections.abc import Callable


class DisabledUserResult(TypedDict):
    """Represents the result of a user disable operation."""

    Disabled: bool
    Result: Literal["Success", "Failed"]
    Message: str


class UserData(TypedDict):
    """Represents the data of a user retrieved from get-user-data."""

    ID: str
    Username: str
    Email: str
    Status: str
    Brand: str
    Instance: str


def run_command(cmd: str, args: dict, label_hr: bool = True) -> tuple[list[dict], str]:
    """Executes a Demisto command and captures human-readable outputs.

    Args:
        cmd (str): The name of the command to execute.
        args (dict): The arguments for the command.
        label_hr (bool): Whether the human readables should be labeled with the command and args.

    Returns:
        list[dict]: A list of command results, filtered to include only
                    notes and errors.
    """
    results = cast(list[dict], demisto.executeCommand(cmd, args))
    results = [
        res
        for res in results
        if res.get("Type") in (EntryType.NOTE, EntryType.ERROR)  # filter out log files
    ]
    human_readable = "\n\n".join(
        (
            (
                f"#### {'Error' if is_error(res) else 'Result'} for "
                f"name={cmd} args={args} current instance={args.get('using', 'N/A')}\n{msg}"
            )
            if label_hr
            else msg
        )
        for res in results
        if isinstance((msg := (res.get("HumanReadable") or res.get("Contents"))), str)
    )
    return results, human_readable


def get_module_command_func(
    module: str,
) -> Callable[[UserData, str], tuple[list[DisabledUserResult], str]]:
    """Returns the corresponding disable function for a given module brand.

    Args:
        module (str): The brand name of the module (e.g., "Active Directory Query v2").

    Raises:
        DemistoException: If the module is not supported.

    Returns:
        Callable: The function to call for disabling a user in the specified module.
    """
    try:
        return {
            "Active Directory Query v2": run_active_directory_query_v2,
            "Microsoft Graph User": run_microsoft_graph_user,
            "Okta v2": run_okta_v2,
            "Okta IAM": run_iam_disable_user,
            "AWS-ILM": run_iam_disable_user,
            "GSuiteAdmin": run_gsuiteadmin,
        }[module]
    except KeyError:
        raise DemistoException(f"Unable to find module: {module!r}")


def run_active_directory_query_v2(user: UserData, using: str) -> tuple[list[DisabledUserResult], str]:
    """Disables a user in Active Directory using the 'ad-disable-account' command.

    Args:
        user (UserData): The user data dictionary.
        using (str): The name of the Active Directory integration instance.

    Returns:
        tuple[list[DisabledUserResult], str]: A list containing the result of the disable operation.
    """
    res_cmd, hr = run_command("ad-disable-account", {"username": user["Username"], "using": using})
    func_res = []
    for res in res_cmd:
        res_msg = res["Contents"]
        func_res.append(
            DisabledUserResult(Disabled=True, Result="Success", Message="User successfully disabled")
            if res_msg == f"User {user['Username']} was disabled"
            else DisabledUserResult(Disabled=False, Result="Failed", Message=res_msg)
        )
    return func_res, hr


def run_microsoft_graph_user(user: UserData, using: str) -> tuple[list[DisabledUserResult], str]:
    """Disables a user in Microsoft Graph using the 'msgraph-user-account-disable' command.

    Args:
        user (UserData): The user data dictionary.
        using (str): The name of the Microsoft Graph User integration instance.

    Returns:
        tuple[list[DisabledUserResult], str]: A list containing the result of the disable operation.
    """
    res_cmd, hr = run_command("msgraph-user-account-disable", {"user": user["Username"], "using": using})
    func_res = []
    for res in res_cmd:
        res_hr = res["HumanReadable"]
        func_res.append(
            DisabledUserResult(Disabled=True, Result="Success", Message="User successfully disabled")
            if res_hr == f'user: "{user["Username"]}" account has been disabled successfully.'
            else DisabledUserResult(Disabled=False, Result="Failed", Message=res["Content"])
        )
    return func_res, hr


def run_okta_v2(user: UserData, using: str) -> tuple[list[DisabledUserResult], str]:
    """Disables a user in Okta using the 'okta-suspend-user' command.

    Args:
        user (UserData): The user data dictionary.
        using (str): The name of the Okta v2 integration instance.

    Returns:
        tuple[list[DisabledUserResult], str]: A list containing the result of the disable operation.
    """
    res_cmd, hr = run_command("okta-suspend-user", {"username": user["Username"], "using": using})
    func_res = []
    for res in res_cmd:
        res_msg = res["Contents"]
        if res_msg == f"### {user['Username']} status is Suspended":
            dur = DisabledUserResult(Disabled=True, Result="Success", Message="User successfully disabled")
        elif "Cannot suspend a user that is not active" in res_msg:
            dur = DisabledUserResult(Disabled=True, Result="Failed", Message="User already disabled")
        else:
            dur = DisabledUserResult(Disabled=False, Result="Failed", Message=res_msg)
        func_res.append(dur)
    return func_res, hr


def run_iam_disable_user(user: UserData, using: str) -> tuple[list[DisabledUserResult], str]:
    """Disables a user using the 'iam-disable-user' command, which is common
    to several IAM integrations like Okta IAM and AWS-ILM.

    Args:
        user (UserData): The user data dictionary.
        using (str): The name of the IAM integration instance.

    Returns:
        tuple[list[DisabledUserResult], str]: A list containing the result of the disable operation.
    """
    res_cmd, hr = run_command(
        "iam-disable-user",
        {"user-profile": f'{{"id":"{user["ID"]}"}}', "using": using},
    )
    return [
        DisabledUserResult(
            Disabled=(not dict_safe_get(res, ("Contents", "active"))),
            Result=("Failed" if is_error(res) or not dict_safe_get(res, ("Contents", "success")) else "Success"),
            Message=str(dict_safe_get(res, ("Contents", "errorMessage")) or "User successfully disabled"),
        )
        for res in res_cmd
    ], hr


def run_gsuiteadmin(user: UserData, using: str) -> tuple[list[DisabledUserResult], str]:
    """Disables a user in G Suite Admin using the 'gsuite-user-update' command.

    Args:
        user (UserData): The user data dictionary.
        using (str): The name of the GSuiteAdmin integration instance.

    Returns:
        tuple[list[DisabledUserResult], str]: A list containing the result of the disable operation.
    """
    res_cmd, hr = run_command(
        "gsuite-user-update",
        {"user_key": user["Email"], "suspended": "true", "using": using},
    )
    func_res = []
    for res in res_cmd:
        if dict_safe_get(res, ("Contents", "suspended")):
            dur = DisabledUserResult(
                Disabled=True,
                Result="Success",
                Message="User successfully disabled",
            )
        else:
            dur = DisabledUserResult(
                Disabled=False,
                Result="Failed",
                Message=str(res.get("Contents") or "Unable to disable user"),
            )
        func_res.append(dur)
    return func_res, hr


def validate_input(args: dict):
    """Validates that at least one user identifier argument is provided.

    Args:
        args (dict): The arguments passed to the script.

    Raises:
        DemistoException: If no user identifier (user_id, user_name, or user_email) is found.
    """
    if not (args.get("user_id") or args.get("user_name") or args.get("user_email")):
        raise ValueError("At least one of the following arguments must be specified: user_id, user_name or user_email.")


def get_users(args: dict) -> tuple[list[UserData], str]:
    """Retrieves user data from available integrations using the 'get-user-data' command.

    Args:
        args (dict): The arguments passed to the script for user identification.

    Raises:
        DemistoException: If the 'get-user-data' command fails, no integrations are available,
                          or the response is unexpected.

    Returns:
        tuple[list[UserData], str]: A list of user data dictionaries.
    """
    res, hr = run_command("get-user-data", args | {"verbose": "true"}, label_hr=False)
    if errors := [r for r in res if r["Type"] == EntryType.ERROR]:
        if err := next((r for r in errors if not r["HumanReadable"]), None):
            raise DemistoException(f"Error when calling get-user-data:\n{err['Contents']}")
        return_results(errors)
    if any(  # if there are no available modules
        r["HumanReadable"] == "### User(s) data\n**No entries.**\n" for r in res
    ):
        raise DemistoException("No integrations available")
    res_user = next(  # get the output with the users
        (r for r in res if r["EntryContext"]), None
    )
    if not res_user:
        raise DemistoException(f"Unexpected response when calling get-user-data:\n{res}")
    return (
        [dict.fromkeys(UserData.__required_keys__, "") | res for res in res_user["Contents"]],  # pylint: disable=E1101
        hr,
    )


def disable_users(users: list[UserData]) -> tuple[list[dict], str]:
    """Disables a list of users by calling the appropriate integration command for each.

    Args:
        users (list[UserData]): A list of user data dictionaries to disable.

    Raises:
        DemistoException: If no users were found with a "found" status.

    Returns:
        tuple[list[dict], str]: A list of results from the disable operations, including user
                    profile information.
    """
    context = []
    human_readables = []
    for user in users:
        if user["Status"] == "found":
            command_func = get_module_command_func(user["Brand"])
            res_cmd, hr = command_func(user, user["Instance"])
            context += [
                {
                    "UserProfile": {
                        "Email": user["Email"],
                        "ID": user["ID"],
                        "Username": user["Username"],
                    },
                    "Brand": user["Brand"],
                    "Instance": user["Instance"],
                }
                | res
                for res in res_cmd
            ]
            human_readables.append(hr)
        else:
            demisto.debug(f"User: {user['Username']} not found for brand: {user['Brand']}")
    if not context:
        raise DemistoException("User(s) not found.")
    return context, "\n\n".join(human_readables)


def main():
    args = demisto.args()
    verbose_hr = ""

    try:
        validate_input(args)
        users, hr_get = get_users(args)
        outputs, hr_disable = disable_users(users)

        if argToBoolean(args.get("verbose", "false")):
            verbose_hr = "\n\n".join(("", hr_get, hr_disable))

        if any(res["Disabled"] for res in outputs):
            return_results(
                CommandResults(
                    outputs_prefix="DisableUser",
                    outputs_key_field=["UserProfile.Email", "UserProfile.ID", "UserProfile.Username", "Disabled", "Instance"],
                    outputs=outputs,
                    readable_output=tableToMarkdown(
                        "Disable User",
                        outputs,
                        headers=[
                            "Brand",
                            "Instance",
                            "UserProfile",
                            "Disabled",
                            "Result",
                            "Message",
                        ],
                    )
                    + verbose_hr,
                )
            )
        else:
            return_results(
                CommandResults(
                    entry_type=EntryType.ERROR,
                    content_format=EntryFormat.MARKDOWN,
                    readable_output=tableToMarkdown("Disable User: All integrations failed.", outputs) + verbose_hr,
                )
            )

    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute DisableUser. Error: {ex}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
