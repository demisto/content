import demistomock as demisto
import json
import sys
import pytest
from pathlib import Path
from CommonServerPython import DemistoException
from pytest_mock import MockerFixture
from FileCreateAndUploadV2 import get_data_from_file, decode_data, main


def side_effect_sys_exit(code):
    pass


def test_main(mocker):
    from FileCreateAndUploadV2 import main

    mocker.patch.object(sys, 'exit', side_effect=side_effect_sys_exit)

    with open('./test_data/test-1.json') as f:
        test_list = json.load(f)

    for eval in test_list:
        mocker.patch.object(demisto, 'args', return_value={
            'filename': eval['filename'],
            'data': eval.get('data'),
            'data_encoding': eval.get('data_encoding'),
            'entryId': eval.get('entryId')
        })
        mocker.patch.object(demisto, 'results')
        main()
        assert demisto.results.call_count == 1
        results = demisto.results.call_args[0][0]
        assert (eval['ok'] and results['Type'] == 3) or ((not eval['ok']) and results['Type'] != 3)


def test_main_with_entry_id(mocker: MockerFixture):
    """
    Given valid arguments including an entry_id,
    When the main function is called,
    Then it should not raise any exceptions.
    """
    mocker.patch.object(demisto, 'args', return_value={
        'filename': 'test_file',
        'data': 'test_data',
        'data_encoding': 'raw',
        'entryId': 'test_entry_id'
    })
    mocker.patch('FileCreateAndUploadV2.get_data_from_file', return_value=b'test_data')
    mocker.patch('FileCreateAndUploadV2.decode_data', return_value=b'test_data')
    mocker.patch.object(demisto, 'results')

    main()
    results = demisto.results.call_args[0][0]

    assert results["File"] == 'test_file'
    assert results["ContentsFormat"] == 'text'


def test_main_without_entry_id(mocker: MockerFixture):
    """
    Given valid arguments without an entry_id,
    When the main function is called,
    Then it should not raise any exceptions.
    """
    mocker.patch.object(demisto, 'args', return_value={
        'filename': 'test_file',
        'data': 'test_data',
        'data_encoding': 'raw'
    })
    mocker.patch('FileCreateAndUploadV2.decode_data', return_value=b'test_data')
    mocker.patch.object(demisto, 'results')
    main()
    results = demisto.results.call_args[0][0]

    assert results["File"] == 'test_file'
    assert results["ContentsFormat"] == 'text'


def test_get_data_from_file(mocker: MockerFixture):
    """
    Given a valid entry_id,
    When the get_data_from_file function is called,
    Then it should return the data read from the file.
    """
    mocker.patch.object(Path, 'read_bytes', return_value=b'test_data')
    mocker.patch.object(demisto, 'getFilePath', return_value={'path': 'test_path'})
    assert get_data_from_file('test_entry_id') == b'test_data'


def test_get_data_from_file_exception(mocker: MockerFixture):
    """
    Given an invalid entry_id,
    When the get_data_from_file function is called,
    Then it should raise a DemistoException.
    """
    mocker.patch.object(Path, 'read_bytes', side_effect=Exception('Error'))
    mocker.patch.object(demisto, 'getFilePath', return_value={'path': 'test_path'})
    with pytest.raises(DemistoException, match='There was a problem opening or reading the file.\nError is: Error'):
        get_data_from_file('test_entry_id')


def test_decode_data_base64():
    """
    Given a base64 encoded data,
    When the decode_data function is called with data_encoding as 'base64',
    Then it should return the decoded data.
    """
    assert decode_data(b'dGVzdF9kYXRh', 'base64') == b'test_data'


def test_decode_data_raw():
    """
    Given a raw data,
    When the decode_data function is called with data_encoding as 'raw',
    Then it should return the same data.
    """
    assert decode_data(b'test_data', 'raw') == b'test_data'


def test_decode_data_invalid():
    """
    Given a data,
    When the decode_data function is called with an invalid data_encoding,
    Then it should raise a ValueError.
    """
    with pytest.raises(ValueError, match='Invalid data encoding value: invalid, must be either `base64` or `raw`'):
        decode_data(b'test_data', 'invalid')
