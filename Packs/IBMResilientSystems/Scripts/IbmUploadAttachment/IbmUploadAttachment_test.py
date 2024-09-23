from IbmUploadAttachment import upload_attachment
import demistomock as demisto


def test_upload_attachment_success(mocker):
    mocker.patch.object(demisto, 'incident', return_value={'dbotMirrorId': '123'})
    mocker.patch.object(demisto, 'executeCommand', return_value=[{'HumanReadable': 'Attachment uploaded successfully'}])
    args = {
        'entry_id': 'TEST ENTRY ID',
    }
    result = upload_attachment(args)
    assert result.readable_output == 'Attachment uploaded successfully'
