import demistomock as demisto
from IbmAddNote import add_note


def test_add_comment_as_note(mocker):
    """Test if the correct arguments are given to the CommandResults object when
    adding a comment as a note.
    """
    # Mock the demisto.incident() to return a dummy incident with dbotMirrorId
    mocker.patch.object(demisto, 'incident', return_value={'dbotMirrorId': '1000'})

    result = add_note({'note': 'New Note', 'tags': 'FROM XSOAR'})

    assert result.readable_output == 'New Note'
    assert result.tags == ['FROM XSOAR']
    assert result.mark_as_note


def test_add_note_execute_command_called(mocker):
    """Test that executeCommand is called with correct arguments."""
    mocker.patch.object(demisto, 'incident', return_value={'dbotMirrorId': '1000'})
    mock_execute = mocker.patch.object(demisto, 'executeCommand', return_value=[])

    add_note({'note': 'Test note', 'tags': 'FROM XSOAR'})

    mock_execute.assert_called_once_with('rs-add-note', args={
        'note': 'Test note',
        'incident-id': '1000'
    })
