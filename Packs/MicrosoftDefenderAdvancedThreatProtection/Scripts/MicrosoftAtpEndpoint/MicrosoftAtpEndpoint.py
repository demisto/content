import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

INTEGRATION_NAME = "Microsoft Defender Advanced Threat Protection"


def main():
    args = demisto.args()
    try:
        return_results(execute_polling_command("endpoint", args, using_brand=INTEGRATION_NAME))
    except Exception as e:
        return_error(f"Failed to execute script.\nError:\n{e!s}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
