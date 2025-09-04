import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def sanitize_input(value: Any, start: Optional[Any], end: Optional[Any]) -> tuple[list[int], Optional[int], Optional[int]]:
    """
    Sanitizes and validates the input values.
    """
    if value is None:
        return_error("Missing 'value' argument.")

    if isinstance(value, str):
        try:
            value = [int(item.strip().strip("\"'")) for item in value.strip("[]").split(",") if item.strip()]
        except ValueError:
            return_error("Input list contains non-integer values.")

    elif isinstance(value, list):
        try:
            value = [int(item) for item in value]
        except ValueError:
            return_error("Input list contains non-integer values.")
    else:
        return_error("Invalid input type for 'value'. Expected list or comma-separated string.")

    # Convert start and end to integers if provided
    try:
        start = int(start) if start else None
    except ValueError:
        return_error("Start value must be an integer.")

    try:
        end = int(end) if end else None
    except ValueError:
        return_error("End value must be an integer.")

    return value, start, end


def missing_elements(value: list[int], start: Optional[int], end: Optional[int]) -> CommandResults:
    """
    Returns missing elements in a range.
    """
    if not value:
        return_error("The input list is empty.")

    if start is None:
        start = min(value)
    if end is None:
        end = max(value)

    if start > end:
        return_error("Start value cannot be greater than End value.")
    if end < start:
        return_error("End value cannot be lesser than Start value.")

    expected_range = set(range(start, end + 1))
    input_set = set(value)
    missing: Optional[list[int]] = sorted(expected_range - input_set)

    if not missing:
        missing = None

    return CommandResults(
        outputs={"output": missing},
        outputs_prefix="MissingElements",
        readable_output=f"Missing elements: {missing}",
    )


def main():
    try:
        args = demisto.args()
        value = args.get("value")
        start = args.get("start")
        end = args.get("end")

        sanitized_value, sanitized_start, sanitized_end = sanitize_input(value, start, end)
        results = missing_elements(sanitized_value, sanitized_start, sanitized_end)
        return_results(results)

    except Exception as e:
        return_error(f"Failed to execute 'MissingElements'. Error: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
