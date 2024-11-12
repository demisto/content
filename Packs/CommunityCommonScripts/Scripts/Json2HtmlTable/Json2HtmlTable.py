import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
"""Converts a JSON object into a HTML table"""

from CommonServerUserPython import *
import json
from json2html import json2html
from typing import Any


''' STANDALONE FUNCTION '''


def get_json_from_string(value: Any) -> dict | str | None:
    """Returns the JSON content from a string if possible

    Args:
        value (Any): The input to be parsed

    Returns:
        dict | str: The parsed JSON content if possible
    """

    json_string: str | None = None

    if isinstance(value, str):
        json_string = value

    if isinstance(value, list) and len(value) == 1 and isinstance(value[0], str):
        json_string = value[0]

    try:
        return json.loads(json_string) if json_string else None
    except json.JSONDecodeError:
        return json_string


def json_to_html(value: str) -> str:
    """Converts the given JSON string into a HTML table

    Args:
        value (str): The JSON object string to convert

    Returns:
        str: The HTML table string
    """

    json_value: dict | str | None = get_json_from_string(value=value)

    return json2html.convert(json=json_value)


''' COMMAND FUNCTION '''


def json_to_html_command(args: dict[str, Any]) -> CommandResults:

    json_value = args.get('value', None)
    if not json_value:
        raise ValueError('JSON object was not specified!')

    result = json_to_html(value=json_value)

    return CommandResults(
        outputs_prefix='Json2HtmlTable',
        outputs_key_field='',
        outputs=result,
    )


''' MAIN FUNCTION '''


def main():
    try:
        return_results(json_to_html_command(demisto.args()))
    except Exception as ex:
        return_error(f'Failed to execute Json2HtmlTable. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
