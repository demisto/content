import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

"""
Loads and parses a YAML string and outputs to context
"""

import traceback
from typing import Any, Dict

import yaml


def load_yaml(s: str) -> Dict:
    """Simple YAML Loader function

    Args:
        s (str): YAML formatted string

    Returns:
        Dict: python simple data structure
    """
    return yaml.safe_load(s)


def yamlload(args: Dict[str, Any]) -> CommandResults:
    """XSOAR command function

    Args:
        args (Dict[str, Any]): XSOAR args

    Raises:
        ValueError: Returned if no string was passed in

    Returns:
        CommandResults: XSOAR CommandResults object
    """
    s = args.get("string", None)

    if not s:
        raise ValueError("string not specified in command args")

    result = load_yaml(s)

    return CommandResults(
        outputs_prefix="ParseYAML",
        outputs_key_field="",
        outputs=result,
    )


def main():
    try:
        return_results(yamlload(demisto.args()))
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute ParseYAML script. Error: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
