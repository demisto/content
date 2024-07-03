import json
import sys
from pathlib import Path

import pytest
from FileCreateAndUploadV2 import (
    EntryType,
    decode_data,
    get_data_from_file,
    main,
    get_data_entry,
)
from pytest_mock import MockerFixture

import demistomock as demisto
from CommonServerPython import DemistoException


def side_effect_sys_exit(code):
    pass


def test_main(mocker):

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


def test_main_with_entry_id(mocker):
    """
    Given an entry ID as an argument,
    When the main function is called,
    Then it should fetch the entry metadata, get the data associated with the entry, decode the data, and return the result.
    """
    mocker.patch.object(demisto, "args", return_value={
        "filename": "test.txt",
        "data": "test_file_data",
        "data_encoding": "raw_encoding",
        "entryId": "1234",
    })
    mock_file_data = b"test_file_data"
    mock_get_entry_metadata = mocker.patch('FileCreateAndUploadV2.get_entry_metadata',
                                           return_value={"Type": EntryType.FILE, "ID": "1234"})
    mock_get_data_entry = mocker.patch('FileCreateAndUploadV2.get_data_entry', return_value=mock_file_data)
    mock_decode_data = mocker.patch('FileCreateAndUploadV2.decode_data', return_value=mock_file_data)

    mocker.patch.object(demisto, "results")
    main()
    results = demisto.results.call_args[0][0]
    assert results["File"] == "test.txt"
    assert results["ContentsFormat"] == "text"
    mock_get_entry_metadata.assert_called_once_with("1234")
    mock_get_data_entry.assert_called_once_with(mock_get_entry_metadata.return_value)
    mock_decode_data.assert_called_once_with(mock_get_data_entry.return_value, "raw_encoding")


def test_main_without_entry_id(mocker: MockerFixture) -> None:
    """Given valid arguments without an entry_id,
    When the main function is called,
    Then it should not raise any exceptions.
    """
    mocker.patch.object(demisto, "args", return_value={
        "filename": "test_file",
        "data": "test_data",
        "data_encoding": "raw",
    })
    mocker.patch("FileCreateAndUploadV2.decode_data", return_value=b"test_data")
    mocker.patch.object(demisto, "results")
    main()
    results = demisto.results.call_args[0][0]

    assert results["File"] == "test_file"
    assert results["ContentsFormat"] == "text"


def test_get_data_from_file(mocker: MockerFixture) -> None:
    """Given a valid entry_id,
    When the get_data_from_file function is called,
    Then it should return the data read from the file.
    """
    mocker.patch.object(Path, "read_bytes", return_value=b"test_data")
    mocker.patch.object(demisto, "getFilePath", return_value={"path": "test_path"})
    assert get_data_from_file("test_entry_id") == b"test_data"


def test_get_data_from_file_exception(mocker: MockerFixture) -> None:
    """Given an invalid entry_id,
    When the get_data_from_file function is called,
    Then it should raise a DemistoException.
    """
    mocker.patch.object(Path, "read_bytes", side_effect=Exception("Error"))
    mocker.patch.object(demisto, "getFilePath", return_value={"path": "test_path"})
    with pytest.raises(DemistoException, match="There was a problem opening or reading the file.\nError is: Error"):
        get_data_from_file("test_entry_id")


def test_decode_data_base64() -> None:
    """Given a base64 encoded data,
    When the decode_data function is called with data_encoding as 'base64',
    Then it should return the decoded data.
    """
    assert decode_data(b"dGVzdF9kYXRh", "base64") == b"test_data"


def test_decode_data_raw() -> None:
    """Given a raw data,
    When the decode_data function is called with data_encoding as 'raw',
    Then it should return the same data.
    """
    assert decode_data(b"test_data", "raw") == b"test_data"


def test_decode_data_invalid() -> None:
    """Given a data,
    When the decode_data function is called with an invalid data_encoding,
    Then it should raise a ValueError.
    """
    with pytest.raises(ValueError, match="Invalid data encoding value: invalid, must be either `base64` or `raw`"):
        decode_data(b"test_data", "invalid")


@pytest.mark.parametrize(
    "entry_type",
    [
        pytest.param(EntryType.FILE, id="entry file type"),
        pytest.param(EntryType.IMAGE, id="entry image type"),
        pytest.param(EntryType.ENTRY_INFO_FILE, id="entry info file type"),
        pytest.param(EntryType.VIDEO_FILE, id="entry video file type"),
    ],
)
def test_get_data_entry_with_various_file_types(mocker: MockerFixture, entry_type: int) -> None:
    """
    Given a dictionary with entry metadata,
    When the entry type is one of the file types (FILE, IMAGE, ENTRY_INFO_FILE, VIDEO_FILE),
    Then the function should return the data from the file associated with the entry ID.
    """
    mock_get_data_from_file = mocker.patch(
        "FileCreateAndUploadV2.get_data_from_file", return_value=b"test file data"
    )
    entry_metadata = {"Type": entry_type, "ID": "1234"}
    result = get_data_entry(entry_metadata)
    assert result == b"test file data"
    mock_get_data_from_file.assert_called_once_with("1234")


def test_get_data_entry_no_file_type(mocker: MockerFixture) -> None:
    """
    Given a dictionary with entry metadata,
    When the entry type is not FILE, IMAGE, ENTRY_INFO_FILE, or VIDEO_FILE,
    Then the function should return the contents from the entry metadata.
    """
    mock_get_data_from_file = mocker.patch("FileCreateAndUploadV2.get_data_from_file")
    entry_metadata = {"Type": 0, "ID": "1234", "Contents": "other data"}
    result = get_data_entry(entry_metadata)
    assert result == "other data"
    mock_get_data_from_file.assert_not_called()
