import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from FileToBase64List import main, get_file_data
import os
import base64
import zlib

TEST_FILE_PATH = os.path.join('test_data', 'file.txt')


def executeCommand(name, args=None):
    if name == 'getFilePath':
        return [
            {
                'Type': entryTypes['note'],
                'Contents': {
                    'path': TEST_FILE_PATH,
                    'name': 'file.txt'
                }
            }
        ]

    elif name == 'createList':
        return [
            {
                'Type': entryTypes['note'],
                'Contents': 'List created successfully'
            }
        ]
    else:
        raise ValueError('Unimplemented command called: {}'.format(name))


def test_file_to_base64_list(mocker):
    args = {
        'listName': 'test',
        'zipFile': 'no',
        'entryId': 1
    }
    mocker.patch.object(demisto, 'args', return_value=args)
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    mocker.patch.object(demisto, 'results')
    assert main().startswith("success store list")


def test_get_file_data(mocker):
    data = get_file_data(TEST_FILE_PATH)
    assert base64.b64decode(data).strip() == "this is a test file"
    data = get_file_data(TEST_FILE_PATH, True)
    assert zlib.decompress(base64.b64decode(data)).strip() == "this is a test file"
