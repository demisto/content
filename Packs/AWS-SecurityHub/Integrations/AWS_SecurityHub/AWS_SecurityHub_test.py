import pytest

FILTER_FIELDS_TEST_CASES = [
    (
        'some non parseable input',
        {}
    ),
    (
        'name=name,value=value,comparison=comparison',
        {
            'name': [{
                'Value': 'value',
                'Comparison': 'COMPARISON'
            }]
        }
    ),
    (
        'name=name1,value=value1,comparison=comparison1;name=name2,value=value2,comparison=comparison2',
        {
            'name1': [{
                'Value': 'value1',
                'Comparison': 'COMPARISON1'
            }],
            'name2': [{
                'Value': 'value2',
                'Comparison': 'COMPARISON2'
            }]
        }
    )
]


@pytest.mark.parametrize('test_input, expected_output', FILTER_FIELDS_TEST_CASES)
def test_parse_filter_field(test_input, expected_output):
    """
    Given:
        - A string that represents filter fields with the structure 'name=...,value=...,comparison=...;name=...' etc.
    When:
     - Parsing it into a dict

    Then:
     - Ensure unparseable string returns an empty dict
     - Ensure one set of name,value,comparison is parsed correctly
     - Ensure two sets of name,value,comparison are parsed correctly
    """
    from AWS_SecurityHub import parse_filter_field
    assert parse_filter_field(test_input) == expected_output


TAG_FIELDS_TEST_CASES = [
    (
        'some non parseable input',
        []
    ),
    (
        'key=key,value=value',
        [{
            'Key': 'key',
            'Value': 'value'
        }]
    ),
    (
        'key=key1,value=value1;key=key2,value=value2',
        [
            {
                'Key': 'key1',
                'Value': 'value1'
            },
            {
                'Key': 'key2',
                'Value': 'value2'
            },
        ]
    )
]


@pytest.mark.parametrize('test_input, expected_output', TAG_FIELDS_TEST_CASES)
def test_parse_tag_field(test_input, expected_output):
    """
    Given:
        - A string that represents tag fields with the structure 'key=...,value=...;key=...,value...' etc.
    When:
     - Parsing it into a list of keys and values

    Then:
     - Ensure unparseable string returns an empty list
     - Ensure one pair of key, value is parsed correctly
     - Ensure two pairs of key, value are parsed correctly
    """
    from AWS_SecurityHub import parse_tag_field
    assert parse_tag_field(test_input) == expected_output


RESOURCE_IDS_TEST_CASES = [
    ('a,b,c', ['a', 'b', 'c']),
    ('a, b, c', ['a', 'b', 'c']),
    ('', [])
]


@pytest.mark.parametrize('test_input, expected_output', RESOURCE_IDS_TEST_CASES)
def test_parse_resource_ids(test_input, expected_output):
    """
    Given:
        - A string that represent a list of ids.
    When:
     - Parsing it into a list

    Then:
     - Ensure empty string returns an empty list
     - Ensure a string without spaces return a valid list separated by ','.
     - Ensure a string with spaces return a valid list separated by ','.
    """
    from AWS_SecurityHub import parse_resource_ids
    assert parse_resource_ids(test_input) == expected_output
