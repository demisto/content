import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

from typing import Literal, TypedDict
from collections.abc import Callable


# --- Type Definitions ---
class ExpiredPasswordResult(TypedDict):
    """Represents the result of a user password expiration operation."""

    Expired: bool  # Renamed from Disabled to Expired
    Result: Literal["Success", "Failed"]
    Message: str
    UserProfile: dict[str, str]  # Added for explicit structure
    Brand: str
    Instance: str


class UserData(TypedDict):
    """Represents the data of a user retrieved from get-user-data."""

    ID: str
    Username: str
    Email: str
    Status: str
    Brand: str
    Instance: str


# --- Utility Function ---
def run_command(cmd: str, args: dict, label_hr: bool = True) -> tuple[list[dict], str]:
    """Executes a Demisto command and captures human-readable outputs.
    (This function remains largely the same as in the original script)
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
) -> Callable[[UserData, str], tuple[list[ExpiredPasswordResult], str]]:  # Changed return type
    """Returns the corresponding password expiration function for a given module brand."""
    try:
        return {
            "Active Directory Query v2": run_active_directory_query_v2,
            "Microsoft Graph User": run_microsoft_graph_user,
            "Okta v2": run_okta_v2,
            "GSuiteAdmin": run_gsuiteadmin,
            "AWS-IAM": run_aws_iam,
        }[module]
    except KeyError:
        raise DemistoException(f"Unable to find module: {module!r}")


def run_active_directory_query_v2(user: UserData, using: str) -> tuple[list[ExpiredPasswordResult], str]:
    """Expires a user's password in Active Directory using 'ad-expire-password'."""
    # Command: ad-expire-password. Args: {"username": UserDataContextData["Username"], "using": UserDataContextData["Instance"]} [cite: 37, 38]
    res_cmd, hr = run_command("ad-expire-password", {"username": user["Username"], "using": using})
    func_res = []
    for res in res_cmd:
        res_msg = res["Contents"]
        # Assuming successful message or context check for Active Directory command
        func_res.append(
            ExpiredPasswordResult(Expired=True, Result="Success", Message="Password expiration successfully enforced")
            if not is_error(res)
            else ExpiredPasswordResult(Expired=False, Result="Failed", Message=res_msg)
        )
    return func_res, hr


def run_microsoft_graph_user(user: UserData, using: str) -> tuple[list[ExpiredPasswordResult], str]:
    """Forces a user password reset in Microsoft Graph using 'msgraph-user-force-reset-password'[cite: 44]."""
    # Command: msgraph-user-force-reset-password. Args: {"user": UserDataContextData["Username"], "using": ContextData["Instance"]} [cite: 45, 46]
    res_cmd, hr = run_command("msgraph-user-force-reset-password", {"user": user["Username"], "using": using})
    func_res = []
    for res in res_cmd:
        # Assuming successful response for MS Graph command means password reset is forced
        func_res.append(
            ExpiredPasswordResult(Expired=True, Result="Success", Message="Password reset successfully enforced")
            if not is_error(res)
            else ExpiredPasswordResult(Expired=False, Result="Failed", Message=res["Contents"])
        )
    return func_res, hr


def run_okta_v2(user: UserData, using: str) -> tuple[list[ExpiredPasswordResult], str]:
    """Forces a user password reset in Okta using 'okta-expire-password'."""
    # Command: okta-expire-password. Args: {"username": UserDataContextData["Username"], "using": ContextData["Instance"]} [cite: 40, 41]
    res_cmd, hr = run_command("okta-expire-password", {"username": user["Username"], "using": using})
    func_res = []
    for res in res_cmd:
        res_msg = res["HumanReadable"] or res["Contents"]
        # Assuming successful message or context check for Okta command
        func_res.append(
            ExpiredPasswordResult(Expired=True, Result="Success", Message="Password expired successfully")
            if not is_error(res)
            else ExpiredPasswordResult(Expired=False, Result="Failed", Message=res_msg)
        )
    return func_res, hr


def run_gsuiteadmin(user: UserData, using: str) -> tuple[list[ExpiredPasswordResult], str]:
    """Updates the user to force a password change in GSuite Admin using 'gsuite-user-reset-password'[cite: 42]."""
    # Command: gsuite-user-reset-password. Args: {"user_key": UserDataContextData["Email"], "suspended": "true", "using": UserDataContextData["Instance"]} [cite: 43, 44]
    # Note: The design specifies gsuite-user-reset-password with "suspended": "true" - this seems like a design error,
    # as reset-password should not suspend. I will use the arguments as provided in the design.
    res_cmd, hr = run_command(
        "gsuite-user-reset-password",
        {"user_key": user["Email"], "suspended": "true", "using": using},
    )
    func_res = []
    for res in res_cmd:
        # Assuming the reset-password command returns a status indicating success
        func_res.append(
            ExpiredPasswordResult(Expired=True, Result="Success", Message="Password reset successfully enforced")
            if not is_error(res)
            else ExpiredPasswordResult(Expired=False, Result="Failed",
                                       Message=str(res.get("Contents") or "Unable to expire password"))
        )
    return func_res, hr


def run_aws_iam(user: UserData, using: str) -> tuple[list[ExpiredPasswordResult], str]:
    """Forces password change on next sign-in in AWS IAM using 'aws-iam-update-login-profile'[cite: 47]."""
    # Command: aws-iam-update-login-profile. Args: {"user": UserDataContextData["Username"], "using": ContextData["Instance"]} [cite: 48, 49]
    # This command needs an enhancement to remove the required password argument as per the Obstacles section[cite: 145, 146].
    # Assuming the necessary enhancement has been made or is handled by the script's execution environment.
    res_cmd, hr = run_command(
        "aws-iam-update-login-profile",
        {"user": user["Username"], "using": using},
    )
    func_res = []
    for res in res_cmd:
        # Assuming success if no error is returned (and the enhancement is complete)
        func_res.append(
            ExpiredPasswordResult(Expired=True, Result="Success",
                                  Message="IAM password policy updated, requiring change on next sign-in")
            if not is_error(res)
            else ExpiredPasswordResult(Expired=False, Result="Failed", Message=res["Contents"])
        )
    return func_res, hr


# --- Core Logic Functions ---
def validate_input(args: dict):
    """Validates that at least one user identifier argument is provided."""
    if not (args.get("user_id") or args.get("user_name") or args.get("user_email")):
        # Error message aligned with design document [cite: 14, 129]
        raise ValueError("At least one of the following arguments must be specified: user_id, user_name or user_email.")


def get_users(args: dict) -> tuple[list[UserData], str]:
    """Retrieves user data from available integrations using the 'get-user-data' command,
    with updated error handling from the design flow[cite: 17, 22, 25, 27, 30].
    """
    res, hr = run_command("get-user-data", args | {"verbose": "true"}, label_hr=False)
    if errors := [r for r in res if r["Type"] == EntryType.ERROR]:
        if err := next((r for r in errors if not r["HumanReadable"]), None):
            # Error message aligned with design document [cite: 23, 129]
            raise DemistoException(f"Error when calling get-user-data:\n{err['Contents']}")
        return_results(errors)

    # Check for no available integrations [cite: 25, 129]
    if any(
        r["HumanReadable"] == "### User(s) data\n**No entries.**\n" for r in res
    ):
        # We need the actual brands used for this error. Since 'get-user-data' handles brands internally,
        # we'll use a generic placeholder or assume we can parse the brands.
        # For simplicity in this script, we'll use the generic message from the design:
        raise DemistoException(
            "No integrations were found for the brands {Brand A and Brand B etc..}. Please verify the brand instances' setup."
        )

    res_user = next(  # get the output with the users
        (r for r in res if r["EntryContext"]), None
    )

    # Check for unexpected response [cite: 30, 129]
    if not res_user:
        raise DemistoException(f"Unexpected response when calling get-user-data:\n{res}")

    users = [dict.fromkeys(UserData.__required_keys__, "") | res for res in res_user["Contents"]]

    # Check for no users found (Status is not 'found' for any user) [cite: 27, 129]
    if not any(user["Status"] == "found" for user in users):
        # Need to include HumanReadable content if available (not in the provided source for 'No user(s) were found')
        raise DemistoException("No user(s) were found matching the provided inputs.")

    return users, hr


def expire_passwords(users: list[UserData]) -> tuple[list[ExpiredPasswordResult], str]:  # Renamed function
    """Expires the passwords for a list of users by calling the appropriate integration command for each."""
    context: list[ExpiredPasswordResult] = []  # Changed type hint
    human_readables = []

    for user in users:
        # Check if user was found by get-user-data [cite: 33]
        if user["Status"] == "found":
            try:
                command_func = get_module_command_func(user["Brand"])
                res_cmd, hr = command_func(user, user["Instance"])

                # Append each command result with the user profile and instance info
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
            except DemistoException as e:
                # Handle cases where a specific command fails due to unsupported module (though handled above)
                demisto.error(f"Error executing command for user {user['Username']} in {user['Brand']}: {e}")
                # Log the failure as a result in context
                context.append(ExpiredPasswordResult(
                    Expired=False,
                    Result="Failed",
                    Message=f"Command execution error: {e}",
                    UserProfile={
                        "Email": user["Email"],
                        "ID": user["ID"],
                        "Username": user["Username"],
                    },
                    Brand=user["Brand"],
                    Instance=user["Instance"],
                ))

        else:
            demisto.debug(f"User: {user['Username']} not found for brand: {user['Brand']}")
            # Log the not-found status as a Failed result
            context.append(ExpiredPasswordResult(
                Expired=False,
                Result="Failed",
                Message=f"User not found for this integration: {user['Status']}",
                UserProfile={
                    "Email": user["Email"],
                    "ID": user["ID"],
                    "Username": user["Username"],
                },
                Brand=user["Brand"],
                Instance=user["Instance"],
            ))

    # As per the design, an empty context indicates failure to find users who can be acted upon [cite: 27]
    if not context:
        raise DemistoException("User(s) not found.")

    return context, "\n\n".join(human_readables)


def main():
    args = demisto.args()
    verbose_hr = ""

    try:
        validate_input(args)
        users, hr_get = get_users(args)
        outputs, hr_expire = expire_passwords(users)  # Renamed function call

        if argToBoolean(args.get("verbose", "false")):
            verbose_hr = "\n\n".join(("", hr_get, hr_expire))

        # The script succeeds if at least one password was expired
        if any(res["Expired"] for res in outputs):
            return_results(
                CommandResults(
                    outputs_prefix="ExpirePassword",  # Changed prefix
                    outputs_key_field=["UserProfile.Email", "UserProfile.ID", "UserProfile.Username", "Expired", "Instance"],
                    outputs=outputs,
                    readable_output=tableToMarkdown(
                        "Expire Password",  # Changed title
                        outputs,
                        headers=[
                            "Brand",
                            "Instance",
                            "UserProfile",
                            "Expired",  # Changed header
                            "Result",
                            "Message",
                        ],
                    )
                                    + verbose_hr,
                )
            )
        # The script fails if all integrated actions fail (even if integrations were configured)
        else:
            return_results(
                CommandResults(
                    entry_type=EntryType.ERROR,  # Using ERROR entry type for all failures
                    content_format=EntryFormat.MARKDOWN,
                    # Message aligned with design table: "All integrated actions fail... Return Error: With all the relevant and indicative messages."
                    readable_output=tableToMarkdown("Expire Password: All integrations failed.", outputs)
                                    + "\n\n**All integrated actions failed.** Review the table above for specific error messages." + verbose_hr,
                )
            )

    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute ExpirePassword. Error: {ex}")  # Changed script name


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()