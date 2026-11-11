import demistomock as demisto
from CommonServerPython import *


def hello_pack_b_command() -> CommandResults:
    return CommandResults(
        readable_output="Hello Pack B",
        outputs_prefix="PackB",
        outputs={"Message": "Hello Pack B"},
    )


def main() -> None:
    command = demisto.command()
    try:
        if command == "test-module":
            return_results("ok")
        elif command == "packb-say-hello":
            return_results(hello_pack_b_command())
        else:
            raise NotImplementedError(f"Command {command!r} is not implemented.")
    except Exception as e:
        return_error(str(e))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
