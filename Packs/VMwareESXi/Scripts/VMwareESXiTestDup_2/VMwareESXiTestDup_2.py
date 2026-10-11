import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    try:
        return_results(CommandResults(readable_output="VMware ESXi Test Dup Script 2 - harness_v1"))
    except Exception as e:
        return_error(f"Failed to execute VMwareESXiTestDup. Error: {e}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
