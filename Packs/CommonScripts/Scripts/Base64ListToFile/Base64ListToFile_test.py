import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import base64
import zlib


def test_valid_base64_file_in_list(mocker, tmp_path):
    import Base64ListToFile

    encoded = base64.b64encode(bytes('hello world!', 'utf-8')).decode('utf-8')

    mocker.patch.object(demisto, 'executeCommand', return_value=[{'Type': EntryType.NOTE,
                                                                  'Contents': encoded}])
    args = {
        'listname': 'test_list'
    }
    res = Base64ListToFile.base64_list_to_file(args)

    create_file_name = '1_' + res['FileID']
    with open(create_file_name, mode='rb') as f:
        assert f.read() == bytes('hello world!', 'utf-8')

    assert res['File'] == args['listname']


def test_valid_base64_file_in_list_zip(mocker):
    import Base64ListToFile

    encoded = base64.b64encode(zlib.compress(bytes('hello world!', 'utf-8'))).decode('utf-8')

    mocker.patch.object(demisto, 'executeCommand', return_value=[{'Type': EntryType.NOTE,
                                                                  'Contents': encoded}])

    args = {
        'filename': 'test_filename',
        'listname': 'test_list',
        'isZipFile': 'yes'
    }
    res = Base64ListToFile.base64_list_to_file(args)

    create_file_name = '1_' + res['FileID']

    with open(create_file_name, mode='rb') as f:
        assert f.read() == bytes('hello world!', 'utf-8')

    assert res['File'] == args['filename']


def test_invalid_base64_file_in_list(mocker):
    import Base64ListToFile

    mocker.patch.object(demisto, 'executeCommand', return_value=[{'Type': EntryType.NOTE,
                                                                  'Contents': 'INVALID_BASE64_STRING'}])

    args = {
        'listname': 'test_list',
    }

    try:
        Base64ListToFile.base64_list_to_file(args)
        assert False
    except Exception:
        assert True
