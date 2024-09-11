import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from FileToBase64List import main, get_file_data
import os
import base64
import zlib

TEST_FILE_PATH = os.path.join('test_data', 'file.txt')


def executeCommand(command, args=None):
    if command == 'createList':
        return [
            {
                'Type': entryTypes['note'],
                'Contents': 'List created successfully'
            }
        ]
    raise ValueError(f'Unimplemented command called: {command}')


def test_file_to_base64_list(mocker):
    args = {
        'listName': 'test',
        'zipFile': 'no',
        'entryId': 1
    }
    mocker.patch.object(demisto, 'args', return_value=args)
    mocker.patch.object(demisto, 'getFilePath', return_value={'path': TEST_FILE_PATH})
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    mocker.patch.object(demisto, 'results')
    result_entry = main()
    assert result_entry['HumanReadable'] == (
        '### File successfully stored in list\n|File Entry ID|List Name|Size|\n|---|---|---|\n| 1 | test | 28 |\n')
    assert len(result_entry['Contents']) > 0


def test_get_file_data(mocker):
    data = get_file_data(TEST_FILE_PATH)
    assert base64.b64decode(data).strip() == b"this is a test file"
    data = get_file_data(TEST_FILE_PATH, True)
    assert zlib.decompress(base64.b64decode(data)).strip() == b"this is a test file"
