"""Base Script for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all funcion names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

"""

import json


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


def test_get_relationships_no_parameters_returns_empty_list():
    """
    Given: No parameters are provided to get_relationships function
    When: Calling get_relationships()
    Then: An empty list should be returned
    """
    from SearchIndicatorRelationshipsAgentix import get_relationships

    result = get_relationships()

    assert result == []


def test_get_relationships_with_entities_only(mocker):
    """
    Given: A list of entities is provided to get_relationships function
    When: Calling get_relationships with entities parameter
    Then: SearchIndicatorRelationships command should be executed and relationships returned
    """
    from SearchIndicatorRelationshipsAgentix import get_relationships

    mock_execute_command = mocker.patch("SearchIndicatorRelationshipsAgentix.demisto.executeCommand")
    mock_get = mocker.patch("SearchIndicatorRelationshipsAgentix.demisto.get")

    mock_execute_command.return_value = [{"Contents": {"Relationships": [{"id": "rel1", "type": "related-to"}]}}]
    mock_get.return_value = {"Relationships": [{"id": "rel1", "type": "related-to"}]}

    result = get_relationships(entities=["example.com"])

    mock_execute_command.assert_called_once_with("SearchIndicatorRelationships", {"entities": ["example.com"], "limit": 20})
    assert result == [{"id": "rel1", "type": "related-to"}]


def test_get_relationships_with_entities_types_calls_filter_function(mocker):
    """
    Given: Entities and entity types are provided to get_relationships function
    When: Calling get_relationships with entities and entities_types parameters
    Then: The filter_relationships_by_entity_types function should be called with correct parameters
    """
    from SearchIndicatorRelationshipsAgentix import get_relationships

    mock_filter = mocker.patch("SearchIndicatorRelationshipsAgentix.filter_relationships_by_entity_types")
    mock_filter.return_value = [{"id": "filtered_rel", "type": "indicates"}]

    result = get_relationships(entities=["malware.exe"], entities_types=["File"], limit=10)

    mock_filter.assert_called_once_with(["malware.exe"], ["File"], None, 10)
    assert result == [{"id": "filtered_rel", "type": "indicates"}]


def test_filter_relationships_by_entity_types_single_page_results(mocker):
    """
    Given: A single page of relationships with matching entity types
    When: Calling filter_relationships_by_entity_types function
    Then: Only relationships matching the specified entity types should be returned
    """
    from SearchIndicatorRelationshipsAgentix import filter_relationships_by_entity_types

    mock_execute_command = mocker.patch("SearchIndicatorRelationshipsAgentix.demisto.executeCommand")
    mock_get = mocker.patch("SearchIndicatorRelationshipsAgentix.demisto.get")

    mock_execute_command.return_value = [
        {
            "Contents": {
                "Relationships": [
                    {"EntityAType": "File", "EntityBType": "Domain", "id": "rel1"},
                    {"EntityAType": "IP", "EntityBType": "Domain", "id": "rel2"},
                ]
            }
        }
    ]

    mock_get.side_effect = [
        {
            "Relationships": [
                {"EntityAType": "File", "EntityBType": "Domain", "id": "rel1"},
                {"EntityAType": "IP", "EntityBType": "Domain", "id": "rel2"},
            ],
            "RelationshipsPagination": [],
        }
    ]

    result = filter_relationships_by_entity_types(["test.exe"], ["File"], None, 10)

    assert len(result) == 1
    assert result[0]["EntityAType"] == "File"
    assert result[0]["id"] == "rel1"


def test_filter_relationships_by_entity_types_multiple_pages(mocker):
    """
    Given: Multiple pages of relationships with pagination tokens
    When: Calling filter_relationships_by_entity_types function
    Then: All pages should be fetched and matching relationships returned
    """
    from SearchIndicatorRelationshipsAgentix import filter_relationships_by_entity_types

    mock_execute_command = mocker.patch("SearchIndicatorRelationshipsAgentix.demisto.executeCommand")
    mock_get = mocker.patch("SearchIndicatorRelationshipsAgentix.demisto.get")

    mock_execute_command.side_effect = [
        [
            {
                "Contents": {
                    "Relationships": [{"EntityAType": "File", "EntityBType": "Domain", "id": "rel1"}],
                    "RelationshipsPagination": ["token1"],
                }
            }
        ],
        [
            {
                "Contents": {
                    "Relationships": [{"EntityAType": "File", "EntityBType": "IP", "id": "rel2"}],
                    "RelationshipsPagination": [],
                }
            }
        ],
    ]

    mock_get.side_effect = [
        {
            "Relationships": [{"EntityAType": "File", "EntityBType": "Domain", "id": "rel1"}],
            "RelationshipsPagination": ["token1"],
        },
        {
            "Relationships": [{"EntityAType": "File", "EntityBType": "IP", "id": "rel2"}],
            "RelationshipsPagination": [],
        },
    ]

    result = filter_relationships_by_entity_types(["test.exe"], ["File"], None, 10)

    assert len(result) == 2
    assert mock_execute_command.call_count == 2


def test_filter_relationships_by_entity_types_limit_reached_early(mocker):
    """
    Given: More relationships available than the specified limit
    When: Calling filter_relationships_by_entity_types function with a limit
    Then: Only the number of relationships up to the limit should be returned
    """
    from SearchIndicatorRelationshipsAgentix import filter_relationships_by_entity_types

    mock_execute_command = mocker.patch("SearchIndicatorRelationshipsAgentix.demisto.executeCommand")
    mock_get = mocker.patch("SearchIndicatorRelationshipsAgentix.demisto.get")

    mock_execute_command.return_value = [
        {
            "Contents": {
                "Relationships": [
                    {"EntityAType": "File", "EntityBType": "Domain", "id": "rel1"},
                    {"EntityAType": "File", "EntityBType": "IP", "id": "rel2"},
                    {"EntityAType": "File", "EntityBType": "URL", "id": "rel3"},
                ]
            }
        }
    ]

    mock_get.return_value = {
        "Relationships": [
            {"EntityAType": "File", "EntityBType": "Domain", "id": "rel1"},
            {"EntityAType": "File", "EntityBType": "IP", "id": "rel2"},
            {"EntityAType": "File", "EntityBType": "URL", "id": "rel3"},
        ],
        "RelationshipsPagination": ["token1"],
    }

    result = filter_relationships_by_entity_types(["test.exe"], ["File"], None, 2)

    assert len(result) == 2


def test_filter_relationships_by_entity_types_no_matching_types(mocker):
    """
    Given: Relationships exist but none match the specified entity types
    When: Calling filter_relationships_by_entity_types function
    Then: An empty list should be returned
    """
    from SearchIndicatorRelationshipsAgentix import filter_relationships_by_entity_types

    mock_execute_command = mocker.patch("SearchIndicatorRelationshipsAgentix.demisto.executeCommand")
    mock_get = mocker.patch("SearchIndicatorRelationshipsAgentix.demisto.get")

    mock_execute_command.return_value = [
        {
            "Contents": {
                "Relationships": [
                    {"EntityAType": "IP", "EntityBType": "Domain", "id": "rel1"},
                    {"EntityAType": "URL", "EntityBType": "Domain", "id": "rel2"},
                ]
            }
        }
    ]

    mock_get.return_value = {
        "Relationships": [
            {"EntityAType": "IP", "EntityBType": "Domain", "id": "rel1"},
            {"EntityAType": "URL", "EntityBType": "Domain", "id": "rel2"},
        ],
        "RelationshipsPagination": [],
    }

    result = filter_relationships_by_entity_types(["test.exe"], ["File"], None, 10)

    assert len(result) == 0


def test_filter_relationships_by_entity_types_empty_response(mocker):
    """
    Given: An empty response from the SearchIndicatorRelationships command
    When: Calling filter_relationships_by_entity_types function
    Then: An empty list should be returned
    """
    from SearchIndicatorRelationshipsAgentix import filter_relationships_by_entity_types

    mock_execute_command = mocker.patch("SearchIndicatorRelationshipsAgentix.demisto.executeCommand")

    mock_execute_command.return_value = []

    result = filter_relationships_by_entity_types(["test.exe"], ["File"], None, 10)

    assert result == []
