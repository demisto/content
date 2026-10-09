import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from typing import Any


def group(data: list[Any], chunk: int, structure: str | None, delimiter: str | None) -> list[list[Any]] | list[str]:
    if structure == "List":
        return [data[i : i + chunk] for i in range(0, len(data), chunk)]
    else:
        if not delimiter:
            delimiter = ","
        return [delimiter.join(map(str, data[i : i + chunk])) for i in range(0, len(data), chunk)]


def main():
    try:
        args = demisto.args()
        data: list = argToList(args["input"])
        chunk: int = int(args["chunk"])
        structure: str | None = args.get("type")
        delimiter: str | None = args.get("delimiter")
        if chunk <= 0:
            return_error("chunk must be greater than 0.")
        outputs = group(data, chunk, structure, delimiter)
        return_results(
            CommandResults(
                outputs=outputs,
                outputs_prefix="Group",
                readable_output="Input is grouped.",
            )
        )
    except Exception as e:
        return_error("ERROR :" + str(e))


if __name__ in ("__main__", "builtins", "__builtin__"):
    main()
