from IbmUpdateNote import update_note
import demistomock as demisto


def test_update_note_with_all_args(mocker):
    """Test update_note function with all arguments."""
    mock_execute_command = mocker.patch.object(demisto, 'executeCommand', return_value=[])
    mocker.patch.object(demisto, 'incident', return_value={'dbotMirrorId': '1000'})
    result = update_note({
        'note_id': '123',
        'note_body': 'Full Update',
        'tags': 'FROM XSOAR'
    })

    mock_execute_command.assert_called_once_with('rs-update-incident-note', args={
        'note_id': '123',
        'note': 'Full Update',
        'incident_id': '1000'
    })
    assert result.readable_output == 'Full Update'
    assert result.tags == ['FROM XSOAR']
    assert result.mark_as_note
