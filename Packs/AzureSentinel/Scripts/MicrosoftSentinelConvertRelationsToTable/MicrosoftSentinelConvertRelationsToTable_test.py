import pytest


def test_format_relation():
    """
    Given:
        - An relation
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


CONTEXT_RESULTS_LIST_OF_DICTS = str([
    {'name': 'test', 'properties': {'relatedResourceKind': 'test_kind', 'relatedResourceType': 'test_type',
                                    'relatedResourceName': 'test_name', 'relatedResourceId': 'test_id'}},
    {'name': 'test2', 'properties': {'relatedResourceKind': 'test_kind2', 'relatedResourceType': 'test_type2',
                                     'relatedResourceName': 'test_name2', 'relatedResourceId': 'test_id2'}}
])
CONTEXT_RESULTS_ONE_DICT = str(
    {'name': 'test', 'properties': {'relatedResourceKind': 'test_kind', 'relatedResourceType': 'test_type',
                                    'relatedResourceName': 'test_name', 'relatedResourceId': 'test_id'}}
)

EXPECTED_TABLE_LIST_OF_DICTS = "|Name|Related Resource Kind|Related Resource Type|Related Resource Name|Related Resource Id|\n" \
                               "|---|---|---|---|---|\n" \
                               "| test | test_kind | test_type | test_name | test_id |\n" \
                               "| test2 | test_kind2 | test_type2 | test_name2 | test_id2 |\n"
EXPECTED_TABLE_ONE_DICT = "|Name|Related Resource Kind|Related Resource Type|Related Resource Name|Related Resource Id|\n" \
                          "|---|---|---|---|---|\n" \
                          "| test | test_kind | test_type | test_name | test_id |\n"


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
        - A list of relations or a single relation in string format
    When:
        - calling convert_to_table function
    Then:
        - Validate the table is created correctly
    """
    from MicrosoftSentinelConvertRelationsToTable import convert_to_table
    result = convert_to_table(context_results)

    assert result.readable_output == expected
