import json
import io
import demistomock as demisto
import pytest

from CommonServerPython import get_demisto_version
from SearchIndicatorRelationships import to_context, handle_stix_types, search_relationships


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
    mock_response = util_load_json('test_data/searchRelationships-response.json')
    response = to_context(mock_response, True)
    expected = util_load_json('test_data/verbose_true_expected.json')
    assert expected == response


def test_handle_stix_types(mocker):
    mocker.patch.object(demisto, 'demistoVersion', return_value={'version': '6.1.0'})

    entity_types = 'STIX Malware,STIX Attack Pattern,STIX Threat Actor,STIX Tool'
    entity_types = handle_stix_types(entity_types)
    assert entity_types == 'STIX Malware,STIX Attack Pattern,STIX Threat Actor,STIX Tool'


@pytest.mark.parametrize('demisto_version, expected_result', [
    ('6.5.0', ['mock_result_1']),
    ('6.6.0', ['mock_result_2']),
    ('7.0.0', ['mock_result_3'])
])
def test_search_relationship_command_args_by_demisto_version(mocker, demisto_version, expected_result):
    """
    Given:
        XSOAR versions:
        1. 6.5.0
        2. 6.6.0
        3. 7.0.0
    When:
        Calling search_relationships method.
    Then:
        Make sure that for each version, the correct implementation of searchRelationships server script is called:
        - For version 6.5.0:
          - The command is called using `executeCommand`.
          - The payload is sent in the expected `searchRelationships` format.
          - An XSOAR entry is returned.
        - For versions 6.6.0 and 7.0.0:
          - the command is called using `demisto.searchRelationships`,
          - The payload is sent in a RelationshipFilter structure.
          - The data is returned in a RelationshipSearchResponse format.
    """
    get_demisto_version._version = None  # clear cache between runs of the test

    def searchRelationships(args):
        assert demisto_version >= '6.6.0'
        assert isinstance(args.get('entities'), list)
        return {'data': expected_result}

    def executeCommand(command_name, args):
        assert command_name == 'searchRelationships'
        assert demisto_version < '6.6.0'
        assert isinstance(args.get('entities'), str)
        return [{'Contents': {'data': expected_result}, 'Type': 'not_error'}]

    mocker.patch.object(demisto, 'demistoVersion', return_value={'version': demisto_version})
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    mocker.patch.object(demisto, 'searchRelationships', side_effect=searchRelationships)
    result = search_relationships(entities='1.1.1.1,8.8.8.8')
    assert result == expected_result
