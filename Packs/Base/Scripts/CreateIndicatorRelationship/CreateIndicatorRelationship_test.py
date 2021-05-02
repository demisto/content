"""Base Script for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all funcion names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

"""

import demistomock as demisto


def test_validate_arguments(mocker):
    """
    """
    from CreateIndicatorRelationship import validate_arguments

    args = {
        'entity_a': '1.1.1.1',
        'entity_a_type': 'IP',
        'entity_b': '2.2.2.2',
        'entity_b_type': 'Domain',
        'entity_b_query': 'value:1.1.1.1',
        'description': 'Test',
        'last_seen': '',
        'source_reliability': '',
        'relationships': 'compromises',
        'reverse_relationships': '',
        'create_indicator': 'false'
    }
    mocker.patch.object(demisto, 'args', return_value=args)
    try:
        validate_arguments()
    except Exception as e:
        assert 'entity_b_query can not be used with entity_b and/or entity_b_type' in e.args[0]

    args = {
            'entity_a': '1.1.1.1',
            'entity_a_type': 'IP',
            'entity_b': '2.2.2.2,3.3.3.3',
            'entity_b_type': 'Domain',
            'entity_b_query': '',
            'description': 'Test',
            'last_seen': '',
            'source_reliability': '',
            'relationships': 'compromises',
            'reverse_relationships': '',
            'create_indicator': 'false'
        }
    mocker.patch.object(demisto, 'args', return_value=args)
    try:
        validate_arguments()
    except Exception as e:
        assert 'entity_b_type is a list, Please insert a single type to create the relationship' in e.args[0]

    args = {
        'entity_a': '1.1.1.1',
        'entity_a_type': 'IP',
        'entity_b': '2.2.2.2',
        'entity_b_type': '',
        'entity_b_query': '',
        'description': 'Test',
        'last_seen': '',
        'source_reliability': '',
        'relationships': 'compromises',
        'reverse_relationships': '',
        'create_indicator': 'false'
    }
    mocker.patch.object(demisto, 'args', return_value=args)
    try:
        validate_arguments()
    except Exception as e:
        assert "Missing entity_b_type in the create relationships" in e.args[0]

    args = {
        'entity_a': '1.1.1.1',
        'entity_a_type': 'IP',
        'entity_b': '',
        'entity_b_type': '',
        'entity_b_query': '',
        'description': 'Test',
        'last_seen': '',
        'source_reliability': '',
        'relationships': 'compromises',
        'reverse_relationships': '',
        'create_indicator': 'false'
    }
    mocker.patch.object(demisto, 'args', return_value=args)
    try:
        validate_arguments()
    except Exception as e:
        assert "Missing entity_b in the create relationships" in e.args[0]

    args = {
        'entity_a': '1.1.1.1,2.2.2.2',
        'entity_a_type': 'IP',
        'entity_b': '3.3.3.3',
        'entity_b_type': 'IP',
        'entity_b_query': '',
        'description': 'Test',
        'last_seen': '',
        'source_reliability': '',
        'relationships': 'compromises',
        'reverse_relationships': '',
        'create_indicator': 'false'
    }
    mocker.patch.object(demisto, 'args', return_value=args)
    try:
        validate_arguments()
    except Exception as e:
        assert "entity_a is a list, Please insert a single entity_a to create the relationship" in e.args[0]


def test_create_indicators(mocker):
    mocker.patch('CreateIndicatorRelationship.remove_existing_entity_b_indicators', return_value=[])
    pass


def test_remove_existing_entity_b_indicators_with_query(mocker):
    from CreateIndicatorRelationship import remove_existing_entity_b_indicators
    expected_entity_b_list = []
    args = {
        'entity_a': '1.1.1.1,2.2.2.2',
        'entity_a_type': 'IP',
        'entity_b_query': 'value:1.1.1.1',
        'description': 'Test',
        'last_seen': '',
        'source_reliability': '',
        'relationships': 'compromises',
        'reverse_relationships': '',
        'create_indicator': 'false'
    }
    entity_b_list = remove_existing_entity_b_indicators(args)
    assert expected_entity_b_list == entity_b_list
