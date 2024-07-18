import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    if is_demisto_version_ge("8.0.0"):
        return_results("Not Available for XSOAR v8")
        sys.exit()
    incident = demisto.incidents()[0]
    account_name = incident.get("account")
    account_name = f"acc_{account_name}/" if account_name != "" else ""

    res = execute_command("core-api-get", {"uri": f"{account_name}health/containers"})
    containers = res["response"]

    return CommandResults(
        readable_output=tableToMarkdown("Containers Status", [containers], headers=["all", "inactive", "running"]),
        outputs_prefix="containers",
        outputs=[containers],
        raw_response=containers,
    )


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    return_results(main())
