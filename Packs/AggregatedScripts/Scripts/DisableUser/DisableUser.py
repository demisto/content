import demistomock as demisto
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]
from CommonServerUserPython import *  # noqa: E402 lgtm [py/polluting-import]

from typing import Literal, TypedDict
from collections.abc import Callable

# TODO: add using/using-brand
# TODO: use "verbose" arg
# TODO: map user fields from get-user-data to disable-user input

HUMAN_READABLES = []


class CmdFuncRes(TypedDict):
    Disabled: bool
    Result: Literal["Success", "Failed"]
    Message: str


class User(TypedDict):
    ID: str
    Username: str
    Email: str
    Status: str
    Source: str


def execute_command(cmd: str, args: dict) -> list[dict]:
    results = cast(list[dict], demisto.executeCommand(cmd, args))
    HUMAN_READABLES.extend(hr for res in results if (hr := res.get("HumanReadable")))
    return [res for res in results if res.get("Type") in (1, 4)]  # filter out log files


9


def get_module_command_func(
    module: str,
) -> Optional[Callable[[User], list[CmdFuncRes]]]:
    return {
        "Active Directory Query v2": run_active_directory_query_v2,
        "Microsoft Graph User": run_microsoft_graph_user,
        "Okta v2": run_okta_v2,
        "Okta IAM": run_okta_iam,
        "AWS-ILM": run_aws_ilm,
        "GSuiteAdmin": run_gsuiteadmin,
    }.get(module)


def run_active_directory_query_v2(user: User) -> list[CmdFuncRes]:

    res_cmd = execute_command("ad-disable-account", {"username": user["Username"]})
    func_res = []
    for res in res_cmd:
        res_msg = res["Contents"]
        func_res.append(
            CmdFuncRes(Disabled=True, Result="Success", Message=res_msg)
            if res_msg == f"User {user['Username']} was disabled"
            else CmdFuncRes(Disabled=False, Result="Failed", Message=res_msg)
        )
    return func_res


def run_microsoft_graph_user(user: User) -> list[CmdFuncRes]:
    res_cmd = execute_command(
        "msgraph-user-account-disable", {"user": user["Username"]}
    )
    func_res = []
    for res in res_cmd:
        res_hr = res["HumanReadable"]
        func_res.append(
            CmdFuncRes(Disabled=True, Result="Success", Message=res_hr)
            if res_hr
            == f'user: "{user["Username"]}" account has been disabled successfully.'
            else CmdFuncRes(Disabled=False, Result="Failed", Message=res["Content"])
        )
    return func_res


def run_okta_v2(user: User) -> list[CmdFuncRes]:
    res_cmd = execute_command("okta-suspend-user", {"username": user["Username"]})
    func_res = []
    for res in res_cmd:
        res_msg = res["Contents"]
        if res_msg == f"### {user['Username']} status is Suspended":
            cfr = CmdFuncRes(Disabled=True, Result="Success", Message=res_msg)
        elif "Cannot suspend a user that is not active" in res_msg:
            cfr = CmdFuncRes(Disabled=True, Result="Failed", Message=res_msg)
        else:
            cfr = CmdFuncRes(Disabled=False, Result="Failed", Message=res_msg)
        func_res.append(cfr)
    return func_res


def run_okta_iam(user: User) -> list[CmdFuncRes]:
    res_cmd = execute_command(
        "iam-disable-user", {"user-profile": f"{{\"email\":\"{user['Email']}\"}}"}
    )
    return [
        CmdFuncRes(
            Disabled=bool(dict_safe_get(res, ("IAM", "Vendor", "active"))),
            Result=(
                "Failed"
                if is_error(res) or dict_safe_get(res, ("IAM", "Vendor", "success"))
                else "Success"
            ),
            Message=str(
                dict_safe_get(res, ("IAM", "Vendor", "errorMessage"))
                or res.get("HumanReadable")
            ),
        )
        for res in res_cmd
    ]


def run_aws_ilm(user: User) -> list[CmdFuncRes]:
    res_cmd = execute_command(
        "iam-disable-user", {"user-profile": f"{{\"email\":\"{user['Email']}\"}}"}
    )
    return [
        CmdFuncRes(
            Disabled=bool(dict_safe_get(res, ("IAM", "Vendor", "active"))),
            Result=(
                "Failed"
                if is_error(res) or dict_safe_get(res, ("IAM", "Vendor", "success"))
                else "Success"
            ),
            Message=str(
                dict_safe_get(res, ("IAM", "Vendor", "errorMessage"))
                or res.get("HumanReadable")
            ),
        )
        for res in res_cmd
    ]


def run_gsuiteadmin(user: User) -> list[CmdFuncRes]:
    res_cmd = execute_command(
        "gsuite-user-update", {"user_key": user["Email"], "suspended": "true"}
    )
    return [
        CmdFuncRes(
            Disabled=bool(dict_safe_get(res, ["Contents", "suspended"])),
            Result="Failed" if is_error(res) else "Success",
            Message=str(res.get("HumanReadable") or res.get("Contents")),
        )
        for res in res_cmd
    ]


def validate_input(args: dict):
    if not (args.get("user_id") or args.get("user_name") or args.get("user_email")):
        raise DemistoException(
            "At least one of the following arguments must be specified: user_id, user_name or user_email."
        )


def get_users(args: dict) -> list[User]:
    res = execute_command("get-user-data", args)
    if is_error(res):
        return_error(get_error(res))
    return cast(list[User], res["Contents"])


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
                res = command_func(user)
                context.append({"UserProfile": user, "Brand": user["Source"]} | res)
        return_results(
            CommandResults(
                outputs_prefix="DisableUser",
                outputs_key_field="UserProfile.Email",
                outputs=context,
                readable_output=tableToMarkdown("Disable User", context),
            )
        )
        if args.get("verbose"):
            return_results(HUMAN_READABLES)
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Failed to execute DisableUser. Error: {str(ex)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
