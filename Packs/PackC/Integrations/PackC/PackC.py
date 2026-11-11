import demistomock as demisto
from CommonServerPython import *


def hello_pack_c_command() -> CommandResults:
    return CommandResults(
        readable_output="Hello Pack C",
        outputs_prefix="PackC",
        outputs={"Message": "Hello Pack C"},
    )


def main() -> None:
    command = demisto.command()
    try:
        if command == "test-module":
            return_results("ok")
        elif command == "packc-say-hello":
            return_results(hello_pack_c_command())
        else:
            raise NotImplementedError(f"Command {command!r} is not implemented.")
    except Exception as e:
        return_error(str(e))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
