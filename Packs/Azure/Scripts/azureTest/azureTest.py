import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

REQUIRED_ARGUMENTS = ("arg1", "arg2")
SUCCESS_MESSAGE = "ok"


def verify_arguments(args: dict[str, Any]) -> str:
    """
    Verifies that every required argument was provided with a non-empty value.

    Args:
        args (dict[str, Any]): The script arguments, expected to include arg1 and arg2.

    Returns:
        str: "ok" when all required arguments are non-empty.

    Raises:
        ValueError: If one or more required arguments are missing, empty, or whitespace only.
    """
    empty_arguments = [name for name in REQUIRED_ARGUMENTS if not str(args.get(name) or "").strip()]
    demisto.debug(f"running the Azure Test script with arguments: {empty_arguments}")
    if empty_arguments:
        raise ValueError(f"The following arguments must not be empty: {', '.join(empty_arguments)}.")
    return SUCCESS_MESSAGE


def main() -> None:  # pragma: no cover
    try:
        return_results(verify_arguments(demisto.args()))
    except Exception as e:
        return_error(f"Failed to execute azureTest. Error: {e}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
