from CopyNotesToIncident import copy_notes_to_target_incident
import demistomock as demisto  # noqa # pylint: disable=unused-wildcard-import
from typing import List, Dict, Any
import json

MOCK_TARGET_INCIDENT_ID = '99'
MOCK_TAG = 'Tag1'


def load_test_data(json_path):
    with open(json_path) as f:
        return json.load(f)


def test_copy_no_note_entries(mocker):
    """
    Given:
        - empty set of source notes
        - arguments (target incident id, tags (empty list))
    When
        - copying note entries (empty set) from current incident to target
    Then
        - no notes are copied
        - a human readable message saying that no notes are found is returned
    """
    mock_source_entries = {}

    mock_target_entries = mock_source_entries

    def executeCommand(name: str, args: Dict[str, Any]) -> List[Dict[str, Any]]:
        if name == 'getEntries':
            return mock_target_entries
        elif name == 'addEntries':
            if 'id' not in args:
                raise ValueError('id must be provided to addEntries')
            if 'entries' not in args or not isinstance(args['entries'], list):
                raise ValueError('a list of entries must be provided to addEntries')
            return [{"OK": "OK"}]

        raise ValueError(f"Error: Unknown command or command/argument pair: {name} {args!r}")

    mocked_ec = mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)

    result = copy_notes_to_target_incident({
        'target_incident': MOCK_TARGET_INCIDENT_ID,
        'tags': []
    })

    assert result.readable_output == "## No notes found"
    assert len(mocked_ec.call_args_list) == 1


def test_copy_all_note_entries(mocker):
    """
    Given:
        - an existing nonempty set of source notes
        - arguments (target incident id, tags (empty list))
    When
        - copying note entries  from current incident to target
    Then
        - all notes are copied
        - a human readable message saying that 2 notes were copied is returned
    """
    mock_source_entries = load_test_data("test_data/entries.json")

    mock_target_entries = [e for e in mock_source_entries if isinstance(e, dict) and 'Note' in e and e['Note'] is True]

    def executeCommand(name: str, args: Dict[str, Any]) -> List[Dict[str, Any]]:
        if name == 'getEntries':
            return mock_target_entries
        elif name == 'addEntries':
            if 'id' not in args:
                raise ValueError('id must be provided to addEntries')
            if 'entries' not in args or not isinstance(args['entries'], list):
                raise ValueError('a list of entries must be provided to addEntries')
            return [{"OK": "OK"}]

        raise ValueError(f"Error: Unknown command or command/argument pair: {name} {args!r}")

    mocked_ec = mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)

    result = copy_notes_to_target_incident({
        'target_incident': MOCK_TARGET_INCIDENT_ID,
        'tags': []
    })

    assert result.readable_output == f"## {len(mock_target_entries)} notes copied"
    assert len(mocked_ec.call_args_list) == 2
    assert mocked_ec.call_args_list[1][0][0] == 'addEntries'
    assert mocked_ec.call_args_list[1][0][1]['entries'] == mock_target_entries


def test_copy_tagged_note_entries(mocker):
    """
    Given:
        - an existing set of source notes
        - arguments (target incident id, tags ("Tag1"))
    When
        - copying only note entries with tag Tag1 from current incident to target
    Then
        - notes with tag Tag1 are copied
        - a human readable message saying that tagged notes were copied is returned
    """
    mock_source_entries = load_test_data("test_data/entries.json")

    mock_target_entries = [
        e for e in mock_source_entries if (
            isinstance(e, dict)
            and 'Note' in e
            and e['Note'] is True
            and 'Tags' in e
            and isinstance(e['Tags'], list)
            and MOCK_TAG in e['Tags']
        )
    ]

    def executeCommand(name: str, args: Dict[str, Any]) -> List[Dict[str, Any]]:
        if name == 'getEntries':
            return mock_target_entries
        elif name == 'addEntries':
            if 'id' not in args:
                raise ValueError('id must be provided to addEntries')
            if 'entries' not in args or not isinstance(args['entries'], list):
                raise ValueError('a list of entries must be provided to addEntries')
            return [{"OK": "OK"}]

        raise ValueError(f"Error: Unknown command or command/argument pair: {name} {args!r}")

    mocked_ec = mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)

    result = copy_notes_to_target_incident({
        'target_incident': MOCK_TARGET_INCIDENT_ID,
        'tags': [MOCK_TAG]
    })

    assert result.readable_output == f"## {len(mock_target_entries)} notes copied"
    assert len(mocked_ec.call_args_list) == 2
    assert mocked_ec.call_args_list[1][0][0] == 'addEntries'
    assert mocked_ec.call_args_list[1][0][1]['entries'] == mock_target_entries
