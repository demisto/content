import demistomock as demisto
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]
from CommonServerUserPython import *  # noqa: E402 lgtm [py/polluting-import]

from typing import Callable, Literal, TypedDict

# TODO: add using/using-brand
# TODO: use "verbose" arg
# TODO: map user fields from get-user-data to disable-user input

class CmdFuncRes(TypedDict):
    Disabled: bool
    Result: Literal["Success", "Failed"]
    Message: str


def get_module_command_func(module: str) -> Optional[Callable[[str], CmdFuncRes]]:
    return {
        "Active Directory Query v2": run_active_directory_query_v2,
        "Microsoft Graph User": run_microsoft_graph_user,
        "Okta v2": run_okta_v2,
        "Okta IAM": run_okta_iam, # not in get-user-data
        "AWS-ILM": run_aws_ilm, # not in get-user-data
        "GSuiteAdmin": run_gsuiteadmin # not in get-user-data
    }.get(module)


def run_active_directory_query_v2(user: str) -> CmdFuncRes:

    res_cmd = demisto.executeCommand("ad-disable-account", {"username": user})
    res_msg = res_cmd[0]["Contents"]
    if res_msg == f"User {user} was disabled":  # AUD doesn't tell us if the user is already disabled
        return CmdFuncRes(
            Disabled=True,
            Result="Success",
            Message=res_msg
        )
    return CmdFuncRes(
        Disabled=False,
        Result="Failed",
        Message=res_msg
    )


def run_microsoft_graph_user(user: str) -> CmdFuncRes:
    res_cmd = demisto.executeCommand("msgraph-user-account-disable", {"user": user})
    res_hr = res_cmd[0]["HumanReadable"]
    if res_hr == f'user: "{user}" account has been disabled successfully.':
        return CmdFuncRes(
            Disabled=True,
            Result="Success",
            Message=res_hr
        )
    return CmdFuncRes(
        Disabled=False,
        Result="Failed",
        Message=res_cmd[0]["Content"]
    )


def run_okta_v2(user: str) -> CmdFuncRes:
    res_cmd = demisto.executeCommand("okta-suspend-user", {"username": user})
    res_hr = res_cmd[0]["HumanReadable"]
    if res_hr == f"### {user} status is Suspended":  # TODO: use context
        return CmdFuncRes(
            Disabled=True,
            Result="Success",
            Message=res_hr
        )


def run_okta_iam(user: str) -> CmdFuncRes:
    res_cmd = demisto.executeCommand("iam-disable-user", {"user-profile": user})
def run_aws_ilm(user: str) -> CmdFuncRes:
    res_cmd = demisto.executeCommand("iam-disable-user", {"user-profile": user})
def run_gsuiteadmin(user: str) -> CmdFuncRes:
    res_cmd = demisto.executeCommand("gsuite-user-update", {"user_key": user, "suspended": "true"})


def validate_input(args: dict):
    if not (
        args.get('user_id')
        or args.get('user_name')
        or args.get('user_email')
    ):
        raise DemistoException("At least one of the following arguments must be specified: user_id, user_name or user_email.")

def get_users(args: dict) -> list[dict]:
    res = demisto.executeCommand("get-user-data", args)
    if is_error(res):
        return_error(get_error(res))
    return cast(list[dict], res["Contents"])

def get_commands(brands: str | list[str], instances: str | list[str]) -> list[tuple[str, str]]: ...

def run_commands(TBD): ...

def main():
    try:
        args = demisto.args()
        validate_input(args)
        users = get_users(args)
        context = []
        for user in users:
            if user["Status"] == "found":
                command_func = get_module_command_func(user["Source"])
                if command_func is None:
                    continue
                res = command_func(user["Username"])
                context.append(
                    {
                        "UserProfile": user,
                        "Brand": user["Source"]
                    } | res
                )
        return_outputs(CommandResults(
            outputs_prefix="DisableUser",
            outputs_key_field="UserProfile.Email",
            outputs=context,
            readable_output=tableToMarkdown(
                "Disable User",
                context
            )
        ))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Failed to execute DisableUser. Error: {str(ex)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
