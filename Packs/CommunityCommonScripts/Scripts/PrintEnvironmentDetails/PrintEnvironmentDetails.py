import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import os


def get_environment_details() -> CommandResults:
    """Retrieve and return the current UID, GID, and PWD."""
    uid = os.getuid()
    gid = os.getgid()
    pwd = os.getcwd()

    details = {
        "UID": uid,
        "GID": gid,
        "PWD": pwd,
    }

    readable_output = tableToMarkdown(
        "Environment Details",
        details,
        headers=["UID", "GID", "PWD"],
    )

    return CommandResults(
        outputs_prefix="EnvDetails",
        outputs_key_field="",
        readable_output=readable_output,
        outputs=details,
    )


def main():
    try:
        return_results(get_environment_details())
    except Exception as e:
        return_error(f"Failed to get environment details: {e}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
