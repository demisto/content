import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

"""Tests the script functions of the Json2HtmlTable script"""

import pytest
import Json2HtmlTable


@pytest.mark.parametrize("value,exptected", [
    (None, None),
    ('{"test": "value"}', {"test": "value"}),
    (['{"test": "value"}'], {"test": "value"})
])
def test_get_json_from_string(value, exptected):
    """Tests the get_json_from_string function"""

    result: dict | str | None = Json2HtmlTable.get_json_from_string(value=value)
    assert result == exptected


@pytest.mark.parametrize("value,expected", [
    ('{"test": "value"}', '<table border="1"><tr><th>test</th><td>value</td></tr></table>'),
    (['{"test": "value"}'], '<table border="1"><tr><th>test</th><td>value</td></tr></table>')
])
def test_json_to_html_command(value, expected):

    demisto_args: dict = {
        "value": value
    }
    result: CommandResults = Json2HtmlTable.json_to_html_command(
        args=demisto_args
    )
    assert result.outputs == expected
