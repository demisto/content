from IbmConvertCommentsToTable import convert_to_table
import demistomock as demisto
import pytest


def test_convert_to_table_no_incident(mocker):
    import re
    mocker.patch.object(demisto, 'incident', return_value=None)
    with pytest.raises(ValueError, match=re.escape("Error - demisto.incident() expected to return current incident from context "
                                                   "but returned None")):
        convert_to_table()


def test_convert_to_table_no_comments(mocker):
    mock_incident = {'CustomFields': {}, 'dbotMirrorTags': []}
    mocker.patch.object(demisto, 'incident', return_value=mock_incident)
    result = convert_to_table()
    assert result.readable_output == 'No comments were found in the notable'


def test_convert_to_table_with_mirror_tags(mocker):
    import json
    mock_incident = {
        'CustomFields': {
            'ibmsecurityqradarsoarnotes': [
                json.dumps({
                    'id': '1',
                    'text': {'content': 'Test comment with FROM XSOAR'},
                    'create_date': '2023-05-01T12:00:00',
                    'created_by': 'User1'
                })
            ]
        },
        'dbotMirrorTags': ['FROM XSOAR']
    }
    mocker.patch.object(demisto, 'incident', return_value=mock_incident)
    result = convert_to_table()
    assert '|ID|Comment|Created at|Created by|tags|' in result.readable_output
    assert '| 1 | Test comment with | 2023-05-01T12:00:00 | User1 | FROM XSOAR |' in result.readable_output


def test_convert_to_table_multiple_comments(mocker):
    import json
    mock_incident = {
        'CustomFields': {
            'ibmsecurityqradarsoarnotes': [
                json.dumps({
                    'id': '1',
                    'text': {'content': 'First comment FROM XSOAR'},
                    'create_date': '2023-05-01T12:00:00',
                    'created_by': 'User1'
                }),
                json.dumps({
                    'id': '2',
                    'text': {'content': 'Second comment'},
                    'create_date': '2023-05-01T13:00:00',
                    'created_by': 'User2'
                })
            ]
        },
        'dbotMirrorTags': ['FROM XSOAR']
    }
    mocker.patch.object(demisto, 'incident', return_value=mock_incident)
    result = convert_to_table()
    assert '|ID|Comment|Created at|Created by|tags|' in result.readable_output
    assert '| 1 | First comment | 2023-05-01T12:00:00 | User1 | FROM XSOAR |' in result.readable_output
    assert '| 2 | Second comment | 2023-05-01T13:00:00 | User2 |  |' in result.readable_output
