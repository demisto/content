import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

"""Spec Test Script - Default

This script is a test fixture for validating that scripts WITHOUT
the 'spec' field continue to work normally with the default worker
memory allocation.

No 'spec' field is set in this script's YAML configuration,
meaning it will use the platform's default memory allocation (1 GB).
"""


def process_data(input_data: str, operation: str) -> dict:
    """Processes input data based on the specified operation.

    Args:
        input_data: The input data string to process.
        operation: The operation to perform (echo, reverse, count).

    Returns:
        dict: Processing result with status and data.
    """
    if operation == "echo":
        output = input_data
    elif operation == "reverse":
        output = input_data[::-1]
    elif operation == "count":
        output = f"characters={len(input_data)}, words={len(input_data.split())}"
    else:
        raise DemistoException(f"Unknown operation: {operation}")

    return {
        "Status": "completed",
        "Data": output,
    }


def main() -> None:
    """Main entry point for the script."""
    try:
        args = demisto.args()
        input_data = args.get("input_data", "")
        operation = args.get("operation", "echo")

        if not input_data:
            raise DemistoException("input_data is required")

        result = process_data(input_data, operation)

        return_results(
            CommandResults(
                outputs_prefix="SpecTestScriptDefault.Result",
                outputs=result,
                readable_output=tableToMarkdown(
                    name="Spec Test Script (Default) - Result",
                    t=result,
                    headers=["Status", "Data"],
                ),
            )
        )

    except Exception as e:
        demisto.error(f"Failed to execute SpecTestScriptDefault. Error: {str(e)}")
        return_error(f"Failed to execute script.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
