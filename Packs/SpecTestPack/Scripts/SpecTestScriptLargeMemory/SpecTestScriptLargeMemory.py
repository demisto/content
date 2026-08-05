import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

"""Spec Test Script - Large Memory

This script is a test fixture for validating the new 'spec' field
on Script content items. The 'spec' field determines the memory
allocation size for the dedicated worker running this script.

This script has spec: L (large) set in its YAML configuration,
indicating it requires extra memory (e.g., for heavy data processing).
"""


def process_data(input_data: str, operation: str) -> dict:
    """Processes input data based on the specified operation.

    Args:
        input_data: The input data string to process.
        operation: The operation to perform (transform, analyze, aggregate).

    Returns:
        dict: Processing result with status, output size, and data.
    """
    if operation == "transform":
        output = input_data.upper()
    elif operation == "analyze":
        output = f"Analysis of '{input_data}': length={len(input_data)}, words={len(input_data.split())}"
    elif operation == "aggregate":
        output = f"Aggregated: {input_data}"
    else:
        raise DemistoException(f"Unknown operation: {operation}")

    return {
        "Status": "completed",
        "OutputSize": len(output),
        "Data": output,
    }


def main() -> None:
    """Main entry point for the script."""
    try:
        args = demisto.args()
        input_data = args.get("input_data", "")
        operation = args.get("operation", "transform")

        if not input_data:
            raise DemistoException("input_data is required")

        result = process_data(input_data, operation)

        return_results(
            CommandResults(
                outputs_prefix="SpecTestScriptLargeMemory.Result",
                outputs=result,
                readable_output=tableToMarkdown(
                    name="Spec Test Script (Large Memory) - Result",
                    t=result,
                    headers=["Status", "OutputSize", "Data"],
                ),
            )
        )

    except Exception as e:
        demisto.error(f"Failed to execute SpecTestScriptLargeMemory. Error: {str(e)}")
        return_error(f"Failed to execute script.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
