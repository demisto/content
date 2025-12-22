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
# Success messages patterns for different integrations
SUCCESS_MESSAGES = {
    "ad_never_expire_cleared": 'AD account {username} has cleared "password never expire" attribute. Value is set to False',
    "ad_password_expired": "Expired password successfully",
    "msgraph_user": "User {username} will be required to change his password.",
    "aws_iam": "The user {username} will be required to change his password.",
}

OKTA_PASSWORD_EXPIRED_MARKER = "PASSWORD_EXPIRED"
OKTA_EXPECTED_FAILURE_PREFIX = "Failed to execute okta-expire-password command."
GENERIC_FAILURE_MESSAGE = "{user_brand} password expiration failed."


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


def build_result(res: dict, success_condition: bool, success_msg: str, failure_msg: str) -> ExpiredPasswordResult:
    """
    Build standardized ExpiredPasswordResult.

    Args:
        res (dict): Command result dictionary.
        success_condition (bool): Whether the operation succeeded.
        success_msg (str): Message to use on success.
        failure_msg (str): Message to use on failure.

    Returns:
        ExpiredPasswordResult: Standardized result dictionary.
    """
    return ExpiredPasswordResult(
        Result="Success" if success_condition else "Failed",
        Message=success_msg if success_condition else failure_msg,
        Instance=get_instance_from_result(res),
    )


def run_command(cmd: str, args: dict, label_hr: bool = True) -> tuple[list[dict], str]:
    """
    Executes a command and captures human-readable outputs.

    Args:
        cmd (str): The name of the command to execute.
        args (dict): The arguments for the command.
        label_hr (bool): Whether the human readables should be labeled with the command and args.

    Returns:
        tuple[list[dict], str]: A list of command results (notes and errors) and the concatenated
                                human-readable output string.
    """
    results = cast(list[dict], demisto.executeCommand(cmd, args))
    results = [res for res in results if res.get("Type") in (EntryType.NOTE, EntryType.ERROR)]
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


# --- Active Directory Helper Function ---
def check_ad_password_never_expires(username: str, using: str) -> tuple[bool | None, list[dict], str]:
    """
    Check if the 'Password Never Expires' flag is set for an Active Directory user.

    This function queries the Active Directory to retrieve the user's account control fields
    and extracts the DONT_EXPIRE_PASSWORD flag value.

    Args:
        username (str): The username (sAMAccountName) of the user to check.
        using (str): The name of the Active Directory integration instance to use.

    Returns:
        tuple[bool | None, list[dict], str]: A tuple containing:
            - bool | None: The value of the DONT_EXPIRE_PASSWORD flag (True, False).
            - list[dict]: The raw command results from ad-get-user.
            - str: The human-readable output from the ad-get-user command.
    """
    args_get_user = {"username": username, "using": using}
    res_get_user, hr_get_user = run_command("ad-get-user", args_get_user)

    dont_expire_flag = True
    for res in res_get_user:
        entry_context = res.get("EntryContext", {})

        # Get the ActiveDirectory.Users key (may have filter syntax like "ActiveDirectory.Users(obj.dn == val.dn)")
        output_key = None
        for key in entry_context:
            if key.startswith("ActiveDirectory.Users"):
                output_key = key
                break

        if output_key:
            outputs = entry_context.get(output_key, [])
            # If outputs is a list, get the first element
            if isinstance(outputs, list) and outputs:
                user_data = outputs[0]
            elif isinstance(outputs, dict):
                user_data = outputs
            else:
                continue

            # Extract userAccountControlFields
            fields = user_data.get("userAccountControlFields", {})
            dont_expire_flag = fields.get("DONT_EXPIRE_PASSWORD", None)
            break

    return dont_expire_flag, res_get_user, hr_get_user


def run_active_directory_query_v2(user: UserData, using: str) -> tuple[list[ExpiredPasswordResult], str]:
    """
    Expires a user's password in Active Directory by first checking if the 'Password Never Expires' flag
    is set, and only proceeding with password expiration if the flag is false.

    Args:
        user (UserData): The user data dictionary.
        using (str): The name of the Active Directory integration instance.

    Returns:
        tuple[list[ExpiredPasswordResult], str]: A list containing the result of the password expiration operation and the HR.
    """
    username = user["Username"]

    # 1. Check if the "Password Never Expires" flag is set
    dont_expire_flag, res_get_user, hr_get_user = check_ad_password_never_expires(username, using)

    # 2. If the flag is True, return failure with informative message
    if dont_expire_flag is True:
        return [
            ExpiredPasswordResult(
                Result="Failed",
                Message=(
                    f"Cannot expire password for user {username} due to user policy. "
                    f"The 'Password Never Expire' flag is set to true. "
                    f"To expire the password, please change this setting to false using the command "
                    f"'ad-modify-password-never-expire'."
                ),
                Instance=get_instance_from_result(res_get_user[0]) if res_get_user else "",
            )
        ], hr_get_user

    # 3. If the flag is None, return failure (unable to retrieve the flag)
    if dont_expire_flag is None:
        return [
            ExpiredPasswordResult(
                Result="Failed",
                Message="Failed to retrieve the 'Password Never Expire' flag - password expiration failed.",
                Instance=get_instance_from_result(res_get_user[0]) if res_get_user else "",
            )
        ], hr_get_user

    # 4. Run the password expiration command (flag is False)
    args_expire = {"username": username, "using": using}
    res_expire, hr_expire = run_command("ad-expire-password", args_expire)

    # Combine human-readable outputs from both commands
    hr = f"{hr_get_user}\n\n{hr_expire}"

    func_res = []
    for res in res_expire:
        res_msg = res.get("Contents")
        success = res_msg == SUCCESS_MESSAGES["ad_password_expired"]
        func_res.append(
            build_result(
                res,
                success_condition=success,
                success_msg=SUCCESS_MESSAGES["ad_password_expired"],
                failure_msg=res_msg or GENERIC_FAILURE_MESSAGE.format(user_brand=user["Brand"]),
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
    func_res = []
    for res in res_cmd:
        res_hr = get_response_message(res, GENERIC_FAILURE_MESSAGE.format(user_brand=user["Brand"]))
        expected_msg = SUCCESS_MESSAGES["msgraph_user"].format(username=user["Username"])
        success = res_hr == expected_msg
        func_res.append(build_result(res, success_condition=success, success_msg=expected_msg, failure_msg=res_hr))
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
    func_res = []
    for res in res_cmd:
        res_msg = get_response_message(res, GENERIC_FAILURE_MESSAGE.format(user_brand=user["Brand"]))
        success = OKTA_PASSWORD_EXPIRED_MARKER in res_msg
        # Verify that if the expire password command fail then the failure message is readable.
        failure_msg = (
            res_msg
            if not success and res_msg.startswith(OKTA_EXPECTED_FAILURE_PREFIX)
            else GENERIC_FAILURE_MESSAGE.format(user_brand=user["Brand"])
        )
        func_res.append(
            build_result(res, success_condition=success, success_msg="Password expired successfully.", failure_msg=failure_msg)
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
    func_res = []
    for res in res_cmd:
        # make sure the field changePasswordAtNextLogin is true
        success = bool(dict_safe_get(res, ["Contents", "changePasswordAtNextLogin"]))
        res_msg = get_response_message(res, GENERIC_FAILURE_MESSAGE.format(user_brand=user["Brand"]))
        func_res.append(
            build_result(res, success_condition=success, success_msg="Password reset successfully enforced", failure_msg=res_msg)
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

    args = {"userName": user["Username"], "using": using, "passwordResetRequired": "True"}
    res_cmd, hr = run_command(
        "aws-iam-update-login-profile",
        args,
    )
    func_res = []
    for res in res_cmd:
        res_msg = get_response_message(res, GENERIC_FAILURE_MESSAGE.format(user_brand=user["Brand"]))
        expected_msg = SUCCESS_MESSAGES["aws_iam"].format(username=user["Username"])
        success = res_msg == expected_msg
        func_res.append(build_result(res, success_condition=success, success_msg=expected_msg, failure_msg=res_msg))
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
    errors = [r for r in res if r["Type"] == EntryType.ERROR]
    if errors:
        err = next((r for r in errors if not r["HumanReadable"]), None)
        default_err_info = "Command execution failed."
        err_info_msg = err.get("Contents", default_err_info) if err else default_err_info
        demisto.debug(f"Error when calling get-user-data:\n{err_info_msg}")

    # Check for no available integrations
    if any((r.get("HumanReadable") or "") == "### User(s) data\n**No entries.**\n" for r in res):
        raise DemistoException(
            f"No integrations were found for the brands {args.get('brands')}. Please verify the brand instances setup."
        )

    user_result = next(  # get the output with the users
        (r for r in res if r["EntryContext"]), None
    )

    # Check for unexpected response
    if not user_result:
        raise DemistoException(f"Unexpected response when calling get-user-data:\n{res}")

    user_contents = user_result.get("Contents", [])

    if not isinstance(user_contents, list):
        raise DemistoException(f"Unexpected type for 'Contents' when calling get-user-data:\n{res}")

    # Build user list with all required fields, defaulting missing ones to empty string
    users: list[UserData] = [
        cast(
            UserData,
            {
                "ID": user_data.get("ID", ""),
                "Username": user_data.get("Username", ""),
                "Email": user_data.get("Email", ""),
                "Status": user_data.get("Status", ""),
                "Brand": user_data.get("Brand", ""),
                "Instance": user_data.get("Instance", ""),
            },
        )
        for user_data in user_contents
    ]
    # Remove duplicates by keeping unique users based on (Username, Email, ID, Brand, Instance)
    seen = set()
    deduplicated_users = []
    for user in users:
        # Create a unique key from user identifying fields
        user_key = (user["Username"], user["Email"], user["ID"], user["Brand"], user["Instance"])
        if user_key not in seen:
            seen.add(user_key)
            deduplicated_users.append(user)
    users = deduplicated_users
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
    for user in users:
        if user["Status"] == "found":
            command_func = get_module_command_func(user["Brand"])
            res_cmd, hr = command_func(user, user["Instance"])
            # Build context entries by merging user profile with command results
            for res in res_cmd:
                result_entry = {
                    "UserProfile": {
                        "Email": user["Email"],
                        "ID": user["ID"],
                        "Username": user["Username"],
                    },
                    "Brand": user["Brand"],
                    **res,  # Merge result fields (Result, Message, Instance)
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
    try:
        validate_input(args)
        users, hr_get = get_users(args)
        outputs, hr_expire = expire_passwords(users)
        if argToBoolean(args.get("verbose", "False")):
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
                    + "\n\n**All integrated actions failed.** Review the table above for specific error messages."
                    + verbose_hr,
                )
            )

    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute ExpirePassword. Error: {ex}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
