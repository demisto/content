from IbmConvertArtifactsToTable import convert_to_table
import demistomock as demisto


def test_convert_to_table_no_artifacts(mocker):
    mock_incident = {
        'CustomFields': {
            'ibmsecurityqradarsoarartifacts': []
        }
    }
    mocker.patch.object(demisto, 'incident', return_value=mock_incident)
    result = convert_to_table()
    assert result.readable_output == 'No artifacts were found for this incident'


def test_convert_to_table_with_artifacts(mocker):
    mock_incident = {
        'CustomFields': {
            'ibmsecurityqradarsoarartifacts': [
                '{"type": "IP", "value": "192.168.1.1"}',
                '{"type": "URL", "value": "https://example.com"}'
            ]
        }
    }
    mocker.patch.object(demisto, 'incident', return_value=mock_incident)
    result = convert_to_table()
    assert '| IP | 192.168.1.1 |' in result.readable_output
    assert '| URL | https://example.com |' in result.readable_output
