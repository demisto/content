import json
import io
import demistomock as demisto


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_to_context_verbose_false():
    """
    Given:
    - the data section of the contents of the servers response to the SearchRelationships command.

    When:
    - running to_context function with verbose false.

    Then:
    - Ensure that the context is as expected.
    """
    from SearchIndicatorRelationships import to_context

    mock_response = util_load_json('test_data/searchRelationships-response.json')
    response = to_context(mock_response, False)
    expected = util_load_json('test_data/verbose_false_expected.json')
    assert expected == response


def test_to_context_verbose_true():
    """
    Given:
    - the data section of the contents of the servers response to the SearchRelationships command.

    When:
    - running to_context function with verbose true.

    Then:
    - Ensure that the context is as expected.
    """
    from SearchIndicatorRelationships import to_context

    mock_response = util_load_json('test_data/searchRelationships-response.json')
    response = to_context(mock_response, True)
    expected = util_load_json('test_data/verbose_true_expected.json')
    assert expected == response


def test_handle_stix_types(mocker):
    from SearchIndicatorRelationships import handle_stix_types

    mocker.patch.object(demisto, 'demistoVersion', return_value={'version': '6.1.0'})

    entity_types = 'STIX Malware,STIX Attack Pattern,STIX Threat Actor,STIX Tool'
    entity_types = handle_stix_types(entity_types)
    assert entity_types == 'STIX Malware,STIX Attack Pattern,STIX Threat Actor,STIX Tool'
