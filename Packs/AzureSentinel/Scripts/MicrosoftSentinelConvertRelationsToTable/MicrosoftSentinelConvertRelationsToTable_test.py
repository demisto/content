def test_format_relation():
    """
    Given:
        - A relation
    When:
         - calling format_relation function
    Then:
        - Validate the relation is formatted correctly
    """
    relation = {'name': 'test', 'properties': {'relatedResourceKind': 'test_kind', 'relatedResourceType': 'test_type',
                                               'relatedResourceName': 'test_name', 'relatedResourceId': 'test_id'}}
    expected = {'name': 'test', 'relatedResourceKind': 'test_kind', 'relatedResourceType': 'test_type',
                'relatedResourceName': 'test_name', 'relatedResourceId': 'test_id'}

    from MicrosoftSentinelConvertRelationsToTable import format_relation
    result = format_relation(relation)

    assert result == expected


CONTEXT_RESULTS = ('[{"name": "test", "properties": {"relatedResourceKind": "test_kind", "relatedResourceType": "test_type", '
                   '"relatedResourceName": "test_name", "relatedResourceId": "test_id"}}, {"name": "test2", "properties": '
                   '{"relatedResourceKind": "test_kind2", "relatedResourceType": "test_type2", '
                   '"relatedResourceName": "test_name2", "relatedResourceId": "test_id2"}}]')

EXPECTED_TABLE = "|Name|Related Resource Kind|Related Resource Type|Related Resource Name|Related Resource Id|\n" \
                 "|---|---|---|---|---|\n" \
                 "| test | test_kind | test_type | test_name | test_id |\n" \
                 "| test2 | test_kind2 | test_type2 | test_name2 | test_id2 |\n"


def test_convert_to_table():
    """
    Given:
        - A list of relations in string format
    When:
        - calling convert_to_table function
    Then:
        - Validate the table is created correctly
    """
    from MicrosoftSentinelConvertRelationsToTable import convert_to_table
    result = convert_to_table(CONTEXT_RESULTS)

    assert result.readable_output == EXPECTED_TABLE
