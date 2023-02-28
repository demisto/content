import pytest


def test_format_entity():
    """
    Given:
        - An entity
    When:
         - calling format_entity function
    Then:
        - Validate the entity is formatted correctly
    """
    entity = {'name': 'test', 'kind': 'test_kind', 'type': 'test_type', 'properties': {'testProp': 'test_value'}}
    expected = {'name': 'test', 'kind': 'test_kind', 'testProp': 'test_value'}

    from MicrosoftSentinelConvertEntitiesToTable import format_entity
    result = format_entity(entity)

    assert result == expected


CONTEXT_RESULTS_LIST_OF_DICTS = str([
    {'name': 'test', 'kind': 'test_kind', 'properties': {'testProp': 'test_value'}},
    {'name': 'test2', 'kind': 'test_kind2', 'properties': {'testProp': 'test_value2', 'testProp2': 'test_value3'}}
])
CONTEXT_RESULTS_ONE_DICT = str({'name': 'test', 'kind': 'test_kind', 'properties': {'testProp': 'test_value'}})

EXPECTED_TABLE_LIST_OF_DICTS = "|Name|Kind|Test Prop|Test Prop 2|\n" \
                               "|---|---|---|---|\n" \
                               "| test | test_kind | test_value |  |\n" \
                               "| test2 | test_kind2 | test_value2 | test_value3 |\n"
EXPECTED_TABLE_ONE_DICT = "|Name|Kind|Test Prop|\n" \
                          "|---|---|---|\n" \
                          "| test | test_kind | test_value |\n"


@pytest.mark.parametrize('context_results, expected', [
    (
        CONTEXT_RESULTS_LIST_OF_DICTS,
        EXPECTED_TABLE_LIST_OF_DICTS
    ),
    (
        CONTEXT_RESULTS_ONE_DICT,
        EXPECTED_TABLE_ONE_DICT
    )
])
def test_convert_to_table(context_results, expected):
    """
    Given:
        - A list of entities or a single entity in string format
    When:
        - calling convert_to_table function
    Then:
        - Validate the table is created correctly
    """
    from MicrosoftSentinelConvertEntitiesToTable import convert_to_table
    result = convert_to_table(context_results)

    assert result.readable_output == expected
