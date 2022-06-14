from pytest_mock.plugin import MockerFixture

import demistomock as demisto
import ForescoutEyeInspectButtonGetPCAP
from CommonServerPython import EntryFormat, EntryType
from ForescoutEyeInspectButtonGetPCAP import get_pcap, main


def test_get_pcap(mocker: MockerFixture):
    alert_id = 1
    mock_file_result = {
        'Contents': f'alert_{alert_id}_sniff.pcap',
        'ContentsFormat': 'text',
        'Type': EntryType.ENTRY_INFO_FILE,
        'File': EntryFormat.TEXT,
        'FileID': demisto.uniqueFile()
    }

    mocker.patch.object(demisto, 'incident', return_value={'CustomFields': {'alertid': '1'}})
    mocker.patch.object(demisto, 'executeCommand', return_value=mock_file_result)

    assert get_pcap() == mock_file_result


def return_error_mock(message: str, *_):
    raise Exception(message)


def test_command_error(mocker: MockerFixture):
    mocker.patch.object(demisto, 'incident', return_value={'CustomFields': {'alertid': '1'}})
    mocker.patch.object(demisto, 'error')
    mocker.patch.object(ForescoutEyeInspectButtonGetPCAP, 'return_error', return_error_mock)
    mocker.patch.object(demisto,
                        'executeCommand',
                        side_effect=Exception('Failed to communicate with Forescout EyeInspect'))

    try:
        main()
    except Exception as e:
        assert 'Failed to communicate with Forescout EyeInspect' in str(e)
