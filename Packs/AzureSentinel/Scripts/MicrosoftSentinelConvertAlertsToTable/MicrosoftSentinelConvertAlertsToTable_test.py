def test_format_alert():
    """
    Given:
        - An alert
    When:
         - calling format_alert function
    Then:
        - Validate the alert is formatted correctly
    """
    alert = {'name': 'test', 'kind': 'test_kind', 'type': 'test_type', 'properties': {'testProp': 'test_value'}}
    expected = {'name': 'test', 'kind': 'test_kind', 'testProp': 'test_value'}

    from MicrosoftSentinelConvertAlertsToTable import format_alert
    result = format_alert(alert)

    assert result == expected


CONTEXT_RESULTS = ('[{"name": "test", "kind": "test_kind", "properties": {"testProp": "test_value"}}, '
                   '{"name": "test2", "kind": "test_kind2", "properties": {"testProp": "test_value2", '
                   '"testProp2": "test_value3"}}]')

EXPECTED_TABLE = "|Name|Kind|Test Prop|Test Prop 2|\n" \
                 "|---|---|---|---|\n" \
                 "| test | test_kind | test_value |  |\n" \
                 "| test2 | test_kind2 | test_value2 | test_value3 |\n"


def test_convert_to_table():
    """
    Given:
        - A list of alerts in string format
    When:
        - calling convert_to_table function
    Then:
        - Validate the table is created correctly
    """
    from MicrosoftSentinelConvertAlertsToTable import convert_to_table
    result = convert_to_table(CONTEXT_RESULTS)

    assert result.readable_output == EXPECTED_TABLE
