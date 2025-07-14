import demistomock as demisto
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]
from CommonServerUserPython import *  # noqa: E402 lgtm [py/polluting-import]

def get_module_command(module: str, user: str) -> tuple[str, dict]:
    return {
        "Active Directory Query v2": ("ad-disable-account", {"username": user}),
        "Microsoft Graph User": ("msgraph-user-account-disable", {"user": user}),
        "Okta v2": ("okta-suspend-user", {"username": user}),
        "Okta IAM": ("iam-disable-user", {"user-profile": user}),
        "AWS-ILM": ("iam-disable-user", {"user-profile": user}),
        "GSuiteAdmin": ("gsuite-user-update", {"user_key": user, "suspended": "true"})
    }[module]

def validate_input(args: dict): ...

def get_users(args: dict) -> list[str]: ...

def get_commands(brands: str | list[str], instances: str | list[str]) -> list[tuple[str, str]]: ...

def run_commands(TBD): ...

def main():
    try:
        return_outputs(demisto.args())
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Failed to execute DisableUser. Error: {str(ex)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
