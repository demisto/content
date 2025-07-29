import demistomock as demisto
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]
from CommonServerUserPython import *  # noqa: E402 lgtm [py/polluting-import]

from typing import Literal, TypedDict
from collections.abc import Callable


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
    Brand: str
    Instance: str


def execute_command(cmd: str, args: dict) -> list[dict]:
    results = cast(list[dict], demisto.executeCommand(cmd, args))
    HUMAN_READABLES.extend(hr for res in results if (hr := res.get("HumanReadable")))
    return [res for res in results if res.get("Type") in (1, 4)]  # filter out log files


def get_module_command_func(
    module: str,
) -> Callable[[User, str], list[CmdFuncRes]]:
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


def run_active_directory_query_v2(user: User, using: str) -> list[CmdFuncRes]:
    res_cmd = execute_command("ad-disable-account", {"username": user["Username"], "using": using})
    func_res = []
    for res in res_cmd:
        res_msg = res["Contents"]
        func_res.append(
            CmdFuncRes(Disabled=True, Result="Success", Message=res_msg)
            if res_msg == f"User {user['Username']} was disabled"
            else CmdFuncRes(Disabled=False, Result="Failed", Message=res_msg)
        )
    return func_res


def run_microsoft_graph_user(user: User, using: str) -> list[CmdFuncRes]:
    res_cmd = execute_command("msgraph-user-account-disable", {"user": user["Username"], "using": using})
    func_res = []
    for res in res_cmd:
        res_hr = res["HumanReadable"]
        func_res.append(
            CmdFuncRes(Disabled=True, Result="Success", Message=res_hr)
            if res_hr == f'user: "{user["Username"]}" account has been disabled successfully.'
            else CmdFuncRes(Disabled=False, Result="Failed", Message=res["Content"])
        )
    return func_res


def run_okta_v2(user: User, using: str) -> list[CmdFuncRes]:
    res_cmd = execute_command("okta-suspend-user", {"username": user["Username"], "using": using})
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


def run_iam_disable_user(user: User, using: str) -> list[CmdFuncRes]:
    res_cmd = execute_command(
        "iam-disable-user",
        {"user-profile": f"{{\"email\":\"{user['Email']}\"}}", "using": using},
    )
    return [
        CmdFuncRes(
            Disabled=(not dict_safe_get(res, ("Contents", "active"))),
            Result=("Failed" if is_error(res) or not dict_safe_get(res, ("Contents", "success")) else "Success"),
            Message=str(dict_safe_get(res, ("Contents", "errorMessage")) or res.get("HumanReadable")),
        )
        for res in res_cmd
    ]


def run_gsuiteadmin(user: User, using: str) -> list[CmdFuncRes]:
    res_cmd = execute_command(
        "gsuite-user-update",
        {"user_key": user["Email"], "suspended": "true", "using": using},
    )
    return [
        CmdFuncRes(
            Disabled=bool(dict_safe_get(res, ("Contents", "suspended"))),
            Result="Failed" if is_error(res) else "Success",
            Message=str(res.get("HumanReadable") or res.get("Contents")),
        )
        for res in res_cmd
    ]


def validate_input(args: dict):
    if not (args.get("user_id") or args.get("user_name") or args.get("user_email")):
        raise DemistoException("At least one of the following arguments must be specified: user_id, user_name or user_email.")


def get_users(args: dict) -> list[User]:
    res = execute_command("get-user-data", args)
    if is_error(res):
        return_error(get_error(res))
    HUMAN_READABLES.append(res[0]["HumanReadable"])
    return cast(list[User], res[0]["Contents"])


def disable_users(users: list[User]) -> list[dict]:
    context = []
    for user in users:
        if user["Status"] == "found":
            command_func = get_module_command_func(user["Brand"])
            res_cmd = command_func(user, user["Instance"])
            context += [
                {
                    "UserProfile": {
                        "Email": user["Email"],
                        "ID": user["ID"],
                        "Username": user["Username"]
                    },
                    "Brand": user["Brand"],
                    "Instance": user["Instance"],
                }
                | res
                for res in res_cmd
            ]
    return context


def main():
    try:
        args = demisto.args()

        validate_input(args)
        users = get_users(args)
        outputs = disable_users(users)

        if args.get("verbose"):
            return_results(HUMAN_READABLES)

        if any(res["Disabled"] for res in outputs):
            return_results(
                CommandResults(
                    outputs_prefix="DisableUser",
                    outputs_key_field="UserProfile.Email",
                    outputs=outputs,
                    readable_output=tableToMarkdown("Disable User", outputs),
                )
            )
        else:
            return_results(
                CommandResults(
                    entry_type=EntryType.ERROR,
                    content_format=EntryFormat.MARKDOWN,
                    readable_output=tableToMarkdown("Disable User Failed", outputs),
                )
            )
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Failed to execute DisableUser. Error: {ex}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
