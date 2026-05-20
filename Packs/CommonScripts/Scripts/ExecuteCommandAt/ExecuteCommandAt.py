import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json


def execute_command_at(command: Any, incident_ids: list, arguments: dict | str) -> Any:
    # ensure that incident ids is a comma-separated list
    csv_incident_ids = ",".join(map(str, incident_ids))

    arguments_dict_error_msg = "Failed to execute ExecuteCommandAt. Argument 'arguments' must be in a dict format"

    if isinstance(arguments, list):
        raise DemistoException(arguments_dict_error_msg)

    if isinstance(arguments, str):
        try:
            arguments = json.loads(arguments)
        except Exception as ex:
            raise DemistoException(f"Failed to parse Argument 'arguments' {ex}")

        if not isinstance(arguments, dict):
            raise DemistoException(arguments_dict_error_msg)

    return execute_command("executeCommandAt", {"command": command, "incidents": csv_incident_ids, "arguments": arguments})


def main() -> None:
    try:
        args = demisto.args()
        incident_ids: list = argToList(args.get("incident_ids"))
        command = args.get("command")
        arguments = args.get("arguments", {})

        return_results(execute_command_at(command, incident_ids, arguments))

    except Exception as ex:
        return_error(f"Failed to execute ExecuteCommandAt. Error: {ex}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
