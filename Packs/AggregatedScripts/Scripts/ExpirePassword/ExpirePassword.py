import demistomock as demisto
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]
from CommonServerUserPython import *  # noqa: E402 lgtm [py/polluting-import]

from typing import Literal, TypedDict
from collections.abc import Callable


class ExpiredPasswordResult(TypedDict):
    """Represents the result of a user password expiration operation."""

    Result: Literal["Success", "Failed"]
    Message: str
    Instance: str


class UserData(TypedDict):
    """Represents the data of a user retrieved from get-user-data."""

    ID: str
    Username: str
    Email: str
    Status: str
    Brand: str
    Instance: str


# --- Constants ---
# Success message patterns for different integrations
AD_NEVER_EXPIRE_CLEARED = 'AD account {username} has cleared "password never expire" attribute. Value is set to False'
AD_PASSWORD_EXPIRED = "Expired password successfully"
MSGRAPH_PASSWORD_RESET = "User {username} will be required to change his password."
AWS_PASSWORD_CHANGED = "The user {username} Password was changed"
OKTA_PASSWORD_EXPIRED_MARKER = "PASSWORD_EXPIRED"


# --- Utility Functions ---
def get_instance_from_result(res: dict) -> str:
    """
    Extract instance name from command result.
    
    Args:
        res (dict): Command result dictionary.
    
    Returns:
        str: Instance name or empty string if not found.
    """
    return dict_safe_get(res, ["Metadata", "instance"]) or ""


def get_response_message(res: dict, default: str = "Command failed") -> str:
    """
    Extract message from command result, checking both HumanReadable and Contents.
    
    Args:
        res (dict): Command result dictionary.
        default (str): Default message if neither field is found.
    
    Returns:
        str: The extracted message.
    """
    return res.get("HumanReadable") or res.get("Contents") or default


def build_result(
    res: dict,
    success_condition: bool,
    success_msg: str,
    failure_msg: str | None = None
) -> ExpiredPasswordResult:
    """
    Build standardized ExpiredPasswordResult.
    
    Args:
        res (dict): Command result dictionary.
        success_condition (bool): Whether the operation succeeded.
        success_msg (str): Message to use on success.
        failure_msg (str | None): Message to use on failure. If None, extracts from res.
    
    Returns:
        ExpiredPasswordResult: Standardized result dictionary.
    """
    return ExpiredPasswordResult(
        Result="Success" if success_condition else "Failed",
        Message=success_msg if success_condition else (failure_msg or get_response_message(res)),
        Instance=get_instance_from_result(res)
    )


def run_command(cmd: str, args: dict, label_hr: bool = True) -> tuple[list[dict], str]:
    """
    Executes a Demisto command and captures human-readable outputs.

    Args:
        cmd (str): The name of the command to execute.
        args (dict): The arguments for the command.
        label_hr (bool): Whether the human readables should be labeled with the command and args.

    Returns:
        tuple[list[dict], str]: A list of command results (notes and errors) and the concatenated
                                human-readable output string.
    """
    results = cast(list[dict], demisto.executeCommand(cmd, args))
    results = [
        res
        for res in results
        if res.get("Type") in (EntryType.NOTE, EntryType.ERROR)
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


# --- Module-Specific Command Functions ---
def get_module_command_func(
        module: str,
) -> Callable[[UserData, str], tuple[list[ExpiredPasswordResult], str]]:
    """
    Returns the corresponding password expiration function for a given module brand.

    Args:
        module (str): The brand name of the module (e.g., "Active Directory Query v2").

    Raises:
        DemistoException: If the module is not supported.

    Returns:
        Callable: The function to call for expiring a user's password in the specified module.
    """
    try:
        return {
            "Active Directory Query v2": run_active_directory_query_v2,
            "Microsoft Graph User": run_microsoft_graph_user,
            "Okta v2": run_okta_v2,
            "GSuiteAdmin": run_gsuiteadmin,
            "AWS - IAM": run_aws_iam,
        }[module]
    except KeyError:
        raise DemistoException(f"Unable to find module: {module!r}")


def run_active_directory_query_v2(user: UserData, using: str) -> tuple[list[ExpiredPasswordResult], str]:
    """
    Expires a user's password in Active Directory by clearing the 'Password Never Expires' flag
    and then running the 'ad-expire-password' command.

    Args:
        user (UserData): The user data dictionary.
        using (str): The name of the Active Directory integration instance.

    Returns:
        tuple[list[ExpiredPasswordResult], str]: A list containing the result of the password expiration operation and the HR.
    """
    username = user["Username"]

    # 1. Clear the "Password Never Expires" attribute (userAccountControl 0x10000)
    # This must run before ad-expire-password to ensure the policy can be enforced.
    args_modify_never_expire_command = {"username": username, "using": using, "value": "false"}
    res_modify_never_expire, hr_modify_never_expire = run_command("ad-modify-password-never-expire", args_modify_never_expire_command)
    demisto.debug(f"DELETE-ExpirePassword: AD {res_modify_never_expire=} {hr_modify_never_expire=}")

    # Check if clearing the "never expire" flag failed first
    expected_msg = AD_NEVER_EXPIRE_CLEARED.format(username=username)
    if not any(res.get("Contents") == expected_msg for res in res_modify_never_expire):
        return [
            ExpiredPasswordResult(
                Result="Failed",
                Message=f"In Active Directory, clearing the never expire flag failed",
                Instance=""
            )
        ], hr_modify_never_expire

    # 2. Run the explicit password expiration command
    args_expire = {"username": username, "using": using}
    res_expire, hr_expire = run_command("ad-expire-password", args_expire)
    demisto.debug(f"DELETE-ExpirePassword: AD {res_expire=} {hr_expire=}")
    # Combine human-readable outputs
    hr = f"{hr_modify_never_expire}\n\n{hr_expire}"

    func_res = []
    for res in res_expire:
        res_msg = res.get("Contents", "AD password command failed")
        success = res_msg == AD_PASSWORD_EXPIRED
        func_res.append(
            build_result(
                res,
                success_condition=success,
                success_msg=f"Active Directory: {res_msg}",
                failure_msg=res_msg
            )
        )
    return func_res, hr


def run_microsoft_graph_user(user: UserData, using: str) -> tuple[list[ExpiredPasswordResult], str]:
    """
    Forces a user password reset in Microsoft Graph using the 'msgraph-user-force-reset-password' command.

    Args:
        user (UserData): The user data dictionary.
        using (str): The name of the Microsoft Graph User integration instance.

    Returns:
        tuple[list[ExpiredPasswordResult], str]: A list containing the result of the password expiration operation and the HR.
    """
    res_cmd, hr = run_command("msgraph-user-force-reset-password", {"user": user["Username"], "using": using})
    demisto.debug(f"DELETE-ExpirePassword: MSG User {res_cmd=} {hr=}")
    func_res = []
    for res in res_cmd:
        res_hr = get_response_message(res, "Microsoft Graph User expiration password command failed")
        expected_msg = MSGRAPH_PASSWORD_RESET.format(username=user['Username'])
        success = res_hr == expected_msg
        func_res.append(
            build_result(
                res,
                success_condition=success,
                success_msg="Password reset successfully enforced",
                failure_msg=res_hr
            )
        )
    return func_res, hr


def run_okta_v2(user: UserData, using: str) -> tuple[list[ExpiredPasswordResult], str]:
    """
    Forces a user password reset in Okta using the 'okta-expire-password' command.

    Args:
        user (UserData): The user data dictionary.
        using (str): The name of the Okta v2 integration instance.

    Returns:
        tuple[list[ExpiredPasswordResult], str]: A list containing the result of the password expiration operation and the HR.
    """
    res_cmd, hr = run_command("okta-expire-password", {"username": user["Username"], "using": using})
    demisto.debug(f"DELETE-ExpirePassword: Okta v2 {res_cmd=} {hr=}")
    func_res = []
    for res in res_cmd:
        res_msg = get_response_message(res)
        demisto.debug(f"DELETE-ExpirePassword: Okta v2 Check Content {res_msg=}")
        success = OKTA_PASSWORD_EXPIRED_MARKER in res_msg
        func_res.append(
            build_result(
                res,
                success_condition=success,
                success_msg="Password expired successfully",
                failure_msg=res_msg
            )
        )
    return func_res, hr


def run_gsuiteadmin(user: UserData, using: str) -> tuple[list[ExpiredPasswordResult], str]:
    """
    Updates the user to force a password change in GSuite Admin using the 'gsuite-user-reset-password' command.

    Args:
        user (UserData): The user data dictionary.
        using (str): The name of the GSuiteAdmin integration instance.

    Returns:
        tuple[list[ExpiredPasswordResult], str]: A list containing the result of the password expiration operation and the HR.
    """
    res_cmd, hr = run_command(
        "gsuite-user-reset-password",
        {"user_key": user["Email"], "using": using},
    )
    demisto.debug(f"DELETE-ExpirePassword: gsuite {res_cmd=} {hr=}")
    func_res = []
    for res in res_cmd:
        # make sure the field changePasswordAtNextLogin is true
        success = bool(dict_safe_get(res, ["Contents", "changePasswordAtNextLogin"]))
        func_res.append(
            build_result(
                res,
                success_condition=success,
                success_msg="Password reset successfully enforced",
                failure_msg=str(res.get("Contents") or "Unable to expire password")
            )
        )
    return func_res, hr


def run_aws_iam(user: UserData, using: str) -> tuple[list[ExpiredPasswordResult], str]:
    """
    Forces a user to change their password on the next sign-in in AWS IAM
    using the 'aws-iam-update-login-profile' command with explicit arguments.

    Args:
        user (UserData): The user data dictionary.
        using (str): The name of the AWS-IAM integration instance.

    Returns:
        tuple[list[ExpiredPasswordResult], str]: A list containing the result of the password expiration operation and the HR.
    """

    args = {
        "userName": user["Username"],
        "using": using,
        "passwordResetRequired": "True"
    }

    res_cmd, hr = run_command(
        "aws-iam-update-login-profile",
        args,
    )
    demisto.debug(f"DELETE-ExpirePassword: AWS-IAM {res_cmd=} {hr=}")
    func_res = []
    for res in res_cmd:
        res_msg = get_response_message(res)
        # The AWS-IAM integration returns "The user {user} password was changed" on success
        expected_msg = AWS_PASSWORD_CHANGED.format(username=user['Username'])
        success = res_msg == expected_msg
        func_res.append(
            build_result(
                res,
                success_condition=success,
                success_msg="IAM user login profile updated successfully, requiring password change on next sign-in.",
                failure_msg=f"AWS-IAM command did not confirm success. Response: {res_msg or 'No response message'}"
            )
        )
    return func_res, hr


# --- Core Logic Functions ---
def validate_input(args: dict):
    """
    Validates that at least one user identifier argument is provided.

    Args:
        args (dict): The arguments passed to the script.

    Raises:
        ValueError: If no user identifier (user_id, user_name, or user_email) is found.
    """
    if not (args.get("user_id") or args.get("user_name") or args.get("user_email")):
        raise ValueError("At least one of the following arguments must be specified: user_id, user_name or user_email.")


def get_users(args: dict) -> tuple[list[UserData], str]:
    """
    Retrieves user data from available integrations using the 'get-user-data' command,
    with error handling aligned with the Expire Password design flow.

    Args:
        args (dict): The arguments passed to the script for user identification.

    Raises:
        DemistoException: If the 'get-user-data' command fails, no integrations are available,
                          no users are found, or the response is unexpected.

    Returns:
        tuple[list[UserData], str]: A list of user data dictionaries and the human-readable output.
    """
    res, hr = run_command("get-user-data", args | {"verbose": "true"}, label_hr=False)

    demisto.debug(f"DELETE-ExpirePassword: get_users {res=} {hr=}")
    if error_results := [r for r in res if r["Type"] == EntryType.ERROR]:
        if err := next((r for r in error_results if not r["HumanReadable"]), None):
            demisto.debug(f"Error when calling get-user-data:\n{err['Contents']}")

    # Check for no available integrations
    if any(
            r["HumanReadable"] == "### User(s) data\n**No entries.**\n" for r in res
    ):
        raise DemistoException(
            f"No integrations were found for the brands {args.get('brands')}. Please verify the brand instances' setup."
        )

    user_result = next(  # get the output with the users
        (r for r in res if r["EntryContext"]), None
    )

    # Check for unexpected response
    if not user_result:
        raise DemistoException(f"Unexpected response when calling get-user-data:\n{res}")

    # Build user list with all required fields, defaulting missing ones to empty string
    users = [
        {key: user_data.get(key, "") for key in UserData.__required_keys__}
        for user_data in user_result["Contents"]
    ]

    # Check for no users found (Status is not 'found' for any user)
    if not any(user["Status"] == "found" for user in users):
        demisto.debug(f"ExpirePassword: Did not found valid users {users}.")
        raise DemistoException("ExpirePassword: User(s) not found.")

    return users, hr


def expire_passwords(users: list[UserData]) -> tuple[list[dict], str]:
    """
    Expires the passwords for a list of users by calling the appropriate integration command for each.

    Args:
        users (list[UserData]): A list of user data dictionaries to expire passwords for.

    Raises:
        DemistoException: If no users were found with a "found" status that could be acted upon.

    Returns:
        tuple[list[dict], str]: A list of results from the password expiration operations,
                                including user profile information and the aggregated HR.
    """
    context: list[dict] = []
    human_readables = []
    demisto.debug(f"DELETE-ExpirePassword: expire_passwords {users=}")
    for user in users:
        if user["Status"] == "found":
            command_func = get_module_command_func(user["Brand"])
            res_cmd, hr = command_func(user, user["Instance"])
            demisto.debug(f"DELETE-ExpirePassword: expire_passwords main {res_cmd=} {hr=}")
            # Build context entries by merging user profile with command results
            for res in res_cmd:
                result_entry = {
                    "UserProfile": {
                        "Email": user["Email"],
                        "ID": user["ID"],
                        "Username": user["Username"],
                    },
                    "Brand": user["Brand"],
                    **res  # Merge result fields (Result, Message, Instance)
                }
                context.append(result_entry)
            
            human_readables.append(hr)
        else:
            demisto.debug(f"ExpirePassword: {user['Status']}, for brand: {user['Brand']}")

    return context, "\n\n".join(human_readables)


def main():
    """
    Main function for the ExpirePassword script.
    """
    args = demisto.args()
    verbose_hr = ""
    demisto.debug(f"DELETE-ExpirePassword: {args=}")
    try:
        validate_input(args)
        users, hr_get = get_users(args)
        outputs, hr_expire = expire_passwords(users)
        demisto.debug(f"DELETE-ExpirePassword: Main {outputs=} {hr_expire=}")
        if argToBoolean(args.get("verbose", "false")):
            verbose_hr = "\n\n".join(("", hr_get, hr_expire))

        if any(res["Result"] == "Success" for res in outputs):
            return_results(
                CommandResults(
                    outputs_prefix="ExpirePassword",
                    outputs_key_field=["UserProfile.Email", "UserProfile.ID", "UserProfile.Username", "Instance", "Result"],
                    outputs=outputs,
                    readable_output=tableToMarkdown(
                        "Expire Password",
                        outputs,
                        headers=[
                            "Brand",
                            "Instance",
                            "UserProfile",
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
                    readable_output=tableToMarkdown("Expire Password: All integrations failed.", outputs)
                                    + "\n\n**All integrated actions failed.** Review the table above for specific error messages." + verbose_hr,
                )
            )

    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute ExpirePassword. Error: {ex}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
