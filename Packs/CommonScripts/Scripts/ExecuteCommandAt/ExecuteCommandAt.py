import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main() -> None:
    args = demisto.args()
    incident_ids = str(args.get("incident_ids"))
    command = str(args.get("command"))
    arguments = args.get("arguments", {})

    return_results(execute_command("executeCommandAt", {"command": command, "incidents": incident_ids, "arguments": arguments}))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
