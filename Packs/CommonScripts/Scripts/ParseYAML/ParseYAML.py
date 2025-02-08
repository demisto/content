import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

"""
Loads and parses a YAML string and outputs to context
"""

import traceback
from typing import Any

import yaml


def load_yaml(stream: str) -> dict:
    """Simple YAML Loader function

    Args:
        stream (str): YAML formatted string

    Returns:
        Dict: python simple data structure
    """
    return yaml.safe_load(stream)


def load_and_parse_yaml_command(args: dict[str, Any]) -> CommandResults:
    """XSOAR command function

    Args:
        args (Dict[str, Any]): XSOAR args

    Raises:
        ValueError: Returned if no string was passed

    Returns:
        CommandResults: XSOAR CommandResults object
    """
    stream = args.get("string", None)

    if not stream:
        raise ValueError("string not specified in command args")

    result = load_yaml(stream)

    return CommandResults(
        outputs_prefix="ParseYAML",
        outputs_key_field="",
        outputs=result,
    )


def main():
    try:
        return_results(load_and_parse_yaml_command(demisto.args()))
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute ParseYAML script. Error: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
