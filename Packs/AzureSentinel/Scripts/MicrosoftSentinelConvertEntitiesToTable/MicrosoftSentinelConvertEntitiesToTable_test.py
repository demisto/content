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


CONTEXT_RESULTS = str([
    {'name': 'test', 'kind': 'test_kind', 'properties': {'testProp': 'test_value'}},
    {'name': 'test2', 'kind': 'test_kind2', 'properties': {'testProp': 'test_value2', 'testProp2': 'test_value3'}}
])

EXPECTED_TABLE = "|Name|Kind|Test Prop|Test Prop 2|\n" \
                 "|---|---|---|---|\n" \
                 "| test | test_kind | test_value |  |\n" \
                 "| test2 | test_kind2 | test_value2 | test_value3 |\n"


def test_convert_to_table():
    """
    Given:
        - A list of entities in string format
    When:
        - calling convert_to_table function
    Then:
        - Validate the table is created correctly
    """
    from MicrosoftSentinelConvertEntitiesToTable import convert_to_table
    result = convert_to_table(CONTEXT_RESULTS)

    assert result.readable_output == EXPECTED_TABLE
