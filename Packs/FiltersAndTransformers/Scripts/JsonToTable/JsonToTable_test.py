

import pytest
import demistomock as demisto
import JsonToTable

ONE_ROW_TABLE = '|header1|\n|---|\n| val1 |\n'
MULTI_LINE_TABLE = '|header1|\n|---|\n| val1 |\n| val2 |\n'


@pytest.mark.parametrize(argnames='value, expected_md', argvalues=[
    ({"header1": "val1"}, ONE_ROW_TABLE),
    ('{"header1": "val1"}', ONE_ROW_TABLE),
    ('{"header1": ["val1"]}', ONE_ROW_TABLE),
    ([{"header1": "val1"}, {"header1": "val2"}], MULTI_LINE_TABLE),
    ('[{"header1": "val1"}, {"header1": "val2"}]', MULTI_LINE_TABLE),
    (['[{"header1": "val1"}, {"header1": "val2"}]'], MULTI_LINE_TABLE),
    ('{"header1": ["val1", "val2"]}', MULTI_LINE_TABLE),
])
def test_json_to_table__sanity(mocker, value, expected_md):
    """
    Given - json or string value to be transformed to a MD table
    When - run the JsonToTable automation
    Then - Validate the Md are as expected
    """
    mocker.patch.object(demisto, 'args', return_value={'value': value})
    mocker.patch.object(JsonToTable, 'return_results')
    JsonToTable.main()

    JsonToTable.return_results.assert_called_with(expected_md)
