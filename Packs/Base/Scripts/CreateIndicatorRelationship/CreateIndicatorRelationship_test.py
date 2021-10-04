import CommonServerPython


def test_validate_arguments(mocker):
    """
    Test that all the error occur in each scenario.
    Given:
    - a collection of arguments to the validate args function

    When:
    - each arg collection should result in a different error

    Then:
    - check that the corresponding error occurs
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
        'relationship': 'compromises',
        'reverse_relationship': '',
        'create_indicator': 'false'
    }
    try:
        validate_arguments(args)
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
        'relationship': 'compromises',
        'reverse_relationship': '',
        'create_indicator': 'false'
    }
    try:
        validate_arguments(args)
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
        'relationship': 'compromises',
        'reverse_relationship': '',
        'create_indicator': 'false'
    }
    try:
        validate_arguments(args)
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
        'relationship': 'compromises',
        'reverse_relationship': '',
        'create_indicator': 'false'
    }
    try:
        validate_arguments(args)
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
        'relationship': 'compromises',
        'reverse_relationship': '',
        'create_indicator': 'false'
    }
    try:
        validate_arguments(args)
    except Exception as e:
        assert "entity_a is a list, Please insert a single entity_a to create the relationship" in e.args[0]

    # Handle the Threat Intel Indicators in server versions:
    args = {
        'entity_a': '1',
        'entity_a_type': 'STIX Malware',
        'entity_b': '3.3.3.3',
        'entity_b_type': 'STIX Tool',
        'entity_b_query': '',
        'description': 'Test',
        'last_seen': '',
        'source_reliability': '',
        'relationship': 'compromises',
        'reverse_relationship': '',
        'create_indicator': 'false'
    }
    mocker.patch.object(CommonServerPython, 'is_demisto_version_ge', return_value=False)
    validate_arguments(args)
    assert args['entity_a_type'] == 'STIX Malware'
    assert args['entity_b_type'] == 'STIX Tool'

    mocker.patch.object(CommonServerPython, 'is_demisto_version_ge', return_value=True)
    validate_arguments(args)
    assert args['entity_a_type'] == 'Malware'
    assert args['entity_b_type'] == 'Tool'


def test_create_relation_command_using_query(mocker):
    """
    Test that the create relationships create the relationships objects
    Given:
    - arguments dict with the necessary args.

    When:
    - the given args using a entity_b_query include the necessary args to create 2 relationships.

    Then:
    - check the relationship object is as expected
    """
    from CreateIndicatorRelationship import create_relation_command_using_query
    expected_relationships = [
        {'name': 'compromises', 'reverseName': 'compromised-by', 'type': 'IndicatorToIndicator', 'entityA': '3.3.3.3',
         'entityAFamily': 'Indicator', 'entityAType': 'IP', 'entityB': '1.1.1.1', 'entityBFamily': 'Indicator',
         'entityBType': 'IP', 'reliability': '', 'brand': 'XSOAR'},
        {'name': 'compromises', 'reverseName': 'compromised-by', 'type': 'IndicatorToIndicator', 'entityA': '3.3.3.3',
         'entityAFamily': 'Indicator', 'entityAType': 'IP', 'entityB': '2.2.2.2', 'entityBFamily': 'Indicator',
         'entityBType': 'IP', 'reliability': '', 'brand': 'XSOAR'}]
    find_indicators_by_query = [{'entity_b': '1.1.1.1', 'entity_b_type': 'IP'},
                                {'entity_b': '2.2.2.2', 'entity_b_type': 'IP'}]
    args = {
        'entity_a': '3.3.3.3',
        'entity_a_type': 'IP',
        'entity_b_query': 'value:1.1.1.1 or value:2.2.2.2',
        'source_reliability': '',
        'relationship': 'compromises',
        'reverse_relationship': '',
        'create_indicator': 'false'
    }
    mocker.patch('CreateIndicatorRelationship.find_indicators_by_query', return_value=find_indicators_by_query)
    relationships = create_relation_command_using_query(args)
    relationships_entry = [relation.to_entry() for relation in relationships]
    for entry, expected_relationship in zip(relationships_entry, expected_relationships):
        entry.pop('fields')
        assert entry.items() <= expected_relationship.items()


def test_create_relation_command_using_args():
    """
    Test that the create relationships create the relationships objects
    Given:
    - arguments dict with the necessary args.

    When:
    - the given args using a entity_b and entity_b_type include the necessary args to create 2 relationships.

    Then:
    - check the relationship object is as expected
    """
    from CreateIndicatorRelationship import create_relationships_with_args
    expected_relationships = [
        {'name': 'compromises', 'reverseName': 'compromised-by', 'type': 'IndicatorToIndicator', 'entityA': '3.3.3.3',
         'entityAFamily': 'Indicator', 'entityAType': 'IP', 'entityB': '4.4.4.4', 'entityBFamily': 'Indicator',
         'entityBType': 'IP', 'reliability': '', 'brand': 'XSOAR'}]
    args = {
        'entity_a': '3.3.3.3',
        'entity_a_type': 'IP',
        'entity_b': '4.4.4.4',
        'entity_b_type': 'IP',
        'relationship': 'compromises',
        'reverse_relationship': '',
        'create_indicator': 'false'
    }
    relationships = create_relationships_with_args(args)
    relationships_entry = [relation.to_entry() for relation in relationships]
    for entry, expected_relationship in zip(relationships_entry, expected_relationships):
        entry.pop('fields')
        assert entry.items() <= expected_relationship.items()


def test_remove_existing_entity_b_indicators_with_query():
    """
    Test that the remove existing indicator.
    Given:
    - arguments dict with the necessary args.

    When:
    - Calling the remove_existing_entity_b_indicators with an entity_b_query.

    Then:
    - check that the expected list to create indicators in empty as the entity_b's come from the system.
    """
    from CreateIndicatorRelationship import remove_existing_entity_b_indicators
    expected_entity_b_list = []
    entity_b_list = remove_existing_entity_b_indicators(entity_b_list=[], entity_b_query='value:1.1.1.1')
    assert expected_entity_b_list == entity_b_list


def test_remove_existing_entity_b_indicators_with_args(mocker):
    """
    Test that the remove existing indicator.
    Given:
    - arguments dict with the necessary args.

    When:
    - Calling the remove_existing_entity_b_indicators

    Then:
    - check that the list of expected entity_b has only indicators that does not exist in the system.
    """
    from CreateIndicatorRelationship import remove_existing_entity_b_indicators
    expected_entity_b_list = ['3.3.3.3']
    find_indicators_by_query = [{'entity_b': '1.1.1.1', 'entity_b_type': 'IP'},
                                {'entity_b': '2.2.2.2', 'entity_b_type': 'IP'}]
    mocker.patch('CreateIndicatorRelationship.find_indicators_by_query', return_value=find_indicators_by_query)
    entity_b_list = remove_existing_entity_b_indicators(entity_b_list=['2.2.2.2', '3.3.3.3'])

    assert expected_entity_b_list == entity_b_list


def test_remove_existing_entity_b_indicators_reference_test(mocker):
    """
    Test that the entity b argument given to the remove_existing_entity_b_indicators function isnt changed after the
    function, check that if some entity b where removed from the create_indicators list, it does not effect the original
    entity_b list to create relationships.
    Given:
    - entity_b given list.

    When:
    - Calling the remove_existing_entity_b_indicators

    Then:
    - check that the list of given entity_b argument is equal to itself after the function run.
    """

    from CreateIndicatorRelationship import remove_existing_entity_b_indicators
    actual_entity_b_list = ['2.2.2.2', '3.3.3.3']
    expected_entity_b_list = actual_entity_b_list[:]
    find_indicators_by_query = [{'entity_b': '1.1.1.1', 'entity_b_type': 'IP'},
                                {'entity_b': '2.2.2.2', 'entity_b_type': 'IP'}]
    mocker.patch('CreateIndicatorRelationship.find_indicators_by_query', return_value=find_indicators_by_query)
    remove_existing_entity_b_indicators(entity_b_list=actual_entity_b_list)
    assert actual_entity_b_list == expected_entity_b_list
