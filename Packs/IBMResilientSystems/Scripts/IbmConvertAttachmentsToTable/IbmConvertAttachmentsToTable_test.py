from IbmConvertAttachmentsToTable import convert_to_table
import demistomock as demisto
import pytest


def test_convert_to_table_no_incident(mocker):
    import re
    mocker.patch.object(demisto, 'incident', return_value=None)
    with pytest.raises(ValueError, match=re.escape(
            "Error - demisto.incident() expected to return current incident from context but returned None")):
        convert_to_table()


def test_convert_to_table_no_attachments(mocker):
    mock_incident = {'CustomFields': {}}
    mocker.patch.object(demisto, 'incident', return_value=mock_incident)
    result = convert_to_table()
    assert result.readable_output == 'No attachments were found for this incident'


def test_convert_to_table_with_attachments(mocker):
    mock_attachments = ['{"name": "file1.txt", "size": 1024}', '{"name": "file2.pdf", "size": 2048}']
    mock_incident = {'CustomFields': {'ibmsecurityqradarsoarattachments': mock_attachments}}
    mocker.patch.object(demisto, 'incident', return_value=mock_incident)
    convert_to_table()
