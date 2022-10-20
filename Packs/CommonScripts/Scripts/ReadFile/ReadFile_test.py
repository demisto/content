import pytest
from ReadFile import *


def test_extract_indicators(mocker):
    """
        Given:
            A file containing text.

        When:
            Running script on file

        Then:
            Validate the right output returns.
        """
    mocker.patch.object(demisto, 'executeCommand', return_value=[{'Contents': {'path': './test_data/test_file.txt'}}])
    results = read_file({})
    assert results == {'Type': 1, 'ContentsFormat': 'text', 'Contents': {'FileData': 'abcabcabc'},
                       'HumanReadable': 'Read 9 bytes from file.', 'EntryContext': {'FileData': 'abcabcabc'}}


def test_extract_indicators_empty_file(mocker):
    """
        Given:
            Name of empty file.

        When:
            Running script on file

        Then:
            Validate the right output returns.
        """
    args = {'maxFileSize': 1024 ** 2}
    mocker.patch.object(demisto, 'executeCommand', return_value=[{'Contents': {'path': './test_data/test_file_empty.txt'}}])

    with pytest.raises(Exception) as e:
        read_file(args)
        if not e:
            assert False


def test_read_binary_to_base64(mocker):
    """
        Given:
            A file containing binary data.

        When:
            Running script on file to convert it in base64

        Then:
            Validate the right output returns.
        """
    args = {
        'encoding': 'binary',
        'output_data_type': 'base64'
    }
    expected = {
        'Type': 1,
        'ContentsFormat': 'text',
        'Contents': {
            'FileData': 'ASNFZ4k='
        },
        'HumanReadable': 'Read 5 bytes from file.',
        'EntryContext': {
            'FileData': 'ASNFZ4k='
        }
    }

    mocker.patch.object(demisto, 'executeCommand', return_value=[{'Contents': {'path': './test_data/test_binary.bin'}}])
    results = read_file(args)
    assert results == expected


def test_read_utf8_to_json(mocker):
    """
        Given:
            A file containing a json text in UTF-8.

        When:
            Running script on file to convert it in json structure.

        Then:
            Validate the right output returns.
        """
    args = {
        'encoding': 'utf-8',
        'output_data_type': 'json'
    }
    expected = {
        'Type': 1,
        'ContentsFormat': 'text',
        'Contents': {
            'FileData': {
                'a': 'b'
            }
        },
        'HumanReadable': 'Read 9 bytes from file.',
        'EntryContext': {
            'FileData': {
                'a': 'b'
            }
        }
    }

    mocker.patch.object(demisto, 'executeCommand', return_value=[{'Contents': {'path': './test_data/test_json_utf8.bin'}}])
    results = read_file(args)
    assert results == expected


def test_read_utf16be_to_json(mocker):
    """
        Given:
            A file containing a json text in UTF-16BE.

        When:
            Running script on file to convert it in json structure.

        Then:
            Validate the right output returns.
        """
    args = {
        'encoding': 'utf-16',
        'output_data_type': 'json'
    }
    expected = {
        'Type': 1,
        'ContentsFormat': 'text',
        'Contents': {
            'FileData': {
                'a': 'b'
            }
        },
        'HumanReadable': 'Read 10 bytes from file.',
        'EntryContext': {
            'FileData': {
                'a': 'b'
            }
        }
    }

    mocker.patch.object(demisto, 'executeCommand', return_value=[{'Contents': {'path': './test_data/test_json_utf16be.bin'}}])
    results = read_file(args)
    assert results == expected


def test_read_utf16le_to_json(mocker):
    """
        Given:
            A file containing a json text in UTF-16LE.

        When:
            Running script on file to convert it in json structure.

        Then:
            Validate the right output returns.
        """
    args = {
        'encoding': 'utf-16',
        'output_data_type': 'json'
    }
    expected = {
        'Type': 1,
        'ContentsFormat': 'text',
        'Contents': {
            'FileData': {
                'a': 'b'
            }
        },
        'HumanReadable': 'Read 10 bytes from file.',
        'EntryContext': {
            'FileData': {
                'a': 'b'
            }
        }
    }

    mocker.patch.object(demisto, 'executeCommand', return_value=[{'Contents': {'path': './test_data/test_json_utf16le.bin'}}])
    results = read_file(args)
    assert results == expected
