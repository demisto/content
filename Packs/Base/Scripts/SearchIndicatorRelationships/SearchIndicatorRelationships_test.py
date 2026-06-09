import json

import demistomock as demisto
import pytest
from CommonServerPython import get_demisto_version
from SearchIndicatorRelationships import handle_stix_types, search_relationships, to_context


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
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
    mock_response = util_load_json("test_data/searchRelationships-response.json")
    response = to_context(mock_response, False)
    expected = util_load_json("test_data/verbose_false_expected.json")
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
    mock_response = util_load_json("test_data/searchRelationships-response.json")
    response = to_context(mock_response, True)
    expected = util_load_json("test_data/verbose_true_expected.json")
    assert expected == response


def test_handle_stix_types(mocker):
    mocker.patch.object(demisto, "demistoVersion", return_value={"version": "6.1.0"})

    entity_types = "STIX Malware,STIX Attack Pattern,STIX Threat Actor,STIX Tool"
    entity_types = handle_stix_types(entity_types)
    assert entity_types == "STIX Malware,STIX Attack Pattern,STIX Threat Actor,STIX Tool"


@pytest.mark.parametrize(
    "demisto_version, expected_result", [("6.5.0", ["mock_result_1"]), ("6.6.0", ["mock_result_2"]), ("7.0.0", ["mock_result_3"])]
)
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
        assert demisto_version >= "6.6.0"
        assert isinstance(args.get("entities"), list)
        return {"data": expected_result}

    def executeCommand(command_name, args):
        assert command_name == "searchRelationships"
        assert demisto_version < "6.6.0"
        assert isinstance(args.get("entities"), str)
        return [{"Contents": {"data": expected_result}, "Type": "not_error"}]

    mocker.patch.object(demisto, "demistoVersion", return_value={"version": demisto_version})
    mocker.patch.object(demisto, "executeCommand", side_effect=executeCommand)
    mocker.patch.object(demisto, "searchRelationships", side_effect=searchRelationships)
    result = search_relationships(entities="1.1.1.1,8.8.8.8")
    result = result.get("data", [])  # handle both old and new response formats
    assert result == expected_result


@pytest.mark.parametrize("search_after, expected_type", [(["timestamp1", "id1"], dict), (None, dict), ([], dict)])
def test_search_relationships_with_search_after(mocker, search_after, expected_type):
    """
    Given:
        Different searchAfter parameter values:
        1. searchAfter as list ["timestamp1", "id1"]
        2. searchAfter as None
        3. searchAfter as empty list []
    When:
        Calling search_relationships method with searchAfter parameter.
    Then:
        Make sure that search_relationships returns a dict for all searchAfter parameter variations.
    """
    mocker.patch.object(demisto, "demistoVersion", return_value={"version": "6.6.0"})
    mocker.patch.object(demisto, "searchRelationships", return_value={"data": []})

    result = search_relationships(searchAfter=search_after)
    assert isinstance(result, expected_type), "search_relationships should return a dict"


@pytest.mark.parametrize(
    "search_after, expected_pagination", [(["test_timestamp", "test_id"], [["test_timestamp", "test_id"]]), (None, [])]
)
def test_to_context_with_search_after(search_after, expected_pagination):
    """
    Given:
        Mock relationships data with different SearchAfter values:
        1. SearchAfter as list ["test_timestamp", "test_id"]
        2. SearchAfter as None
    When:
        Calling to_context method with the mock relationships data.
    Then:
        Make sure that:
        - Context contains RelationshipsPagination key
        - RelationshipsPagination contains the expected value based on SearchAfter
        - When SearchAfter is None, RelationshipsPagination should be empty
    """
    mock_relationships_data = {"SearchAfter": search_after, "data": []}
    context = to_context(mock_relationships_data, False)
    assert "RelationshipsPagination" in context, "Context should contain RelationshipsPagination"
    assert context["RelationshipsPagination"] == expected_pagination
