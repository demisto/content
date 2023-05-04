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
    mocker.patch("ReadFile.execute_command", return_value={'path': './test_data/test_file.txt'})

    mocker.patch.object(demisto, 'results')
    read_file({})
    results = demisto.results.call_args[0][0]

    assert results == {'Type': 1, 'ContentsFormat': 'text', 'Contents': {'FileData': 'abcabcabc'},
                       'HumanReadable': 'Read 9 bytes from file:\nabcabcabc', 'EntryContext': {'FileData': 'abcabcabc'}}


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
    mocker.patch("ReadFile.execute_command", return_value={'path': './test_data/test_file_empty.txt'})

    with pytest.raises(Exception) as e:
        read_file(args)
        if not e:
            assert False


def test_read_binary_to_raw_decode_error(mocker):
    """
        Given:
            A file containing binary data which cannot convert to utf-8.

        When:
            Running script on file without encoding

        Then:
            Cause an exception.
        """
    args = {
        'input_encoding': 'binary',
        'output_data_type': 'raw'
    }
    mocker.patch("ReadFile.execute_command", return_value={'path': './test_data/test_binary.bin'})

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
        'input_encoding': 'binary',
        'output_data_type': 'base64'
    }
    expected = {
        'Type': 1,
        'ContentsFormat': 'text',
        'Contents': {
            'FileData': 'ASNFZ4k='
        },
        'HumanReadable': 'Read 5 bytes from file:\nASNFZ4k=',
        'EntryContext': {
            'FileData': 'ASNFZ4k='
        }
    }

    mocker.patch("ReadFile.execute_command", return_value={'path': './test_data/test_binary.bin'})

    mocker.patch.object(demisto, 'results')
    read_file(args)
    results = demisto.results.call_args[0][0]
    assert results == expected


def test_read_binary_to_json_decode_error(mocker):
    """
        Given:
            A file containing binary data which cannot convert to utf-8 with output_data_type = json

        When:
            Running script on file without encoding

        Then:
            Cause an exception.
        """
    args = {
        'input_encoding': 'binary',
        'output_data_type': 'json'
    }
    mocker.patch("ReadFile.execute_command", return_value={'path': './test_data/test_binary.bin'})

    with pytest.raises(Exception) as e:
        read_file(args)
        if not e:
            assert False


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
        'input_encoding': 'utf-8',
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
        'HumanReadable': 'Read 9 bytes from file:\n' + str({"a": "b"}),
        'EntryContext': {
            'FileData': {
                'a': 'b'
            }
        }
    }

    mocker.patch("ReadFile.execute_command", return_value={'path': './test_data/test_json_utf8.bin'})

    mocker.patch.object(demisto, 'results')
    read_file(args)
    results = demisto.results.call_args[0][0]
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
        'input_encoding': 'utf-16',
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
        'HumanReadable': 'Read 10 bytes from file:\n' + str({"a": "b"}),
        'EntryContext': {
            'FileData': {
                'a': 'b'
            }
        }
    }

    mocker.patch("ReadFile.execute_command", return_value={'path': './test_data/test_json_utf16be.bin'})

    mocker.patch.object(demisto, 'results')
    read_file(args)
    results = demisto.results.call_args[0][0]
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
        'input_encoding': 'utf-16',
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
        'HumanReadable': 'Read 10 bytes from file:\n' + str({"a": "b"}),
        'EntryContext': {
            'FileData': {
                'a': 'b'
            }
        }
    }

    mocker.patch("ReadFile.execute_command", return_value={'path': './test_data/test_json_utf16le.bin'})

    mocker.patch.object(demisto, 'results')
    read_file(args)
    results = demisto.results.call_args[0][0]
    assert results == expected


def test_read_file_default_with_meta(mocker):
    """
        Given:
            A file containing text with `output_metadata' = true

        When:
            Running script on file

        Then:
            Validate the right output returns.
    """
    mocker.patch("ReadFile.execute_command", return_value={'path': './test_data/test_file.txt'})

    mocker.patch.object(demisto, 'args', return_value={
        'entryID': '1',
        'output_metadata': True,
    })

    file_info = {
        'Data': 'abcabcabc',
        'EntryID': '1',
        'FileSize': 9,
        'EOF': True
    }

    expected = {
        'Type': 1,
        'ContentsFormat': 'json',
        'Contents': file_info,
        'HumanReadable': 'Read 9 bytes from file:\nabcabcabc',
        'EntryContext': {
            'ReadFile(obj.EntryID===val.EntryID)': file_info
        }
    }

    mocker.patch.object(demisto, 'results')
    main()
    results = demisto.results.call_args[0][0]
    for k, v in expected.items():
        assert k in results
        assert v == results[k]


def test_read_file_as_binary_with_meta(mocker):
    """
        Given:
            A file containing text with `output_metadata' = true.

        When:
            Running script to read a file as binary

        Then:
            Validate the right output returns.
    """
    mocker.patch("ReadFile.execute_command", return_value={'path': './test_data/test_file.txt'})

    mocker.patch.object(demisto, 'args', return_value={
        'entryID': '1',
        'input_encoding': 'binary',
        'output_metadata': True,
    })

    file_info = {
        'Data': 'abcabcabc',
        'EntryID': '1',
        'FileSize': 9,
        'EOF': True
    }

    expected = {
        'Type': 1,
        'ContentsFormat': 'json',
        'Contents': file_info,
        'HumanReadable': 'Read 9 bytes from file:\nabcabcabc',
        'EntryContext': {
            'ReadFile(obj.EntryID===val.EntryID)': file_info
        }
    }

    mocker.patch.object(demisto, 'results')
    main()
    results = demisto.results.call_args[0][0]
    for k, v in expected.items():
        assert k in results
        assert v == results[k]


def test_read_file_incomplete_with_meta(mocker):
    """
        Given:
            A file containing text with `output_metadata' = true.

        When:
            Running script to read a file over maxFileSize

        Then:
            Validate the right output returns.
    """
    mocker.patch("ReadFile.execute_command", return_value={'path': './test_data/test_file.txt'})

    mocker.patch.object(demisto, 'args', return_value={
        'entryID': '1',
        'maxFileSize': 3,
        'output_metadata': True,
    })

    file_info = {
        'Data': 'abc',
        'EntryID': '1',
        'FileSize': 9,
        'EOF': False
    }

    expected = {
        'Type': 1,
        'ContentsFormat': 'json',
        'Contents': file_info,
        'HumanReadable': 'Read 3 bytes from file:\nabc',
        'EntryContext': {
            'ReadFile(obj.EntryID===val.EntryID)': file_info
        }
    }

    mocker.patch.object(demisto, 'results')
    main()
    results = demisto.results.call_args[0][0]
    for k, v in expected.items():
        assert k in results
        assert v == results[k]


def test_read_empty_file_with_meta(mocker):
    """
        Given:
            Name of empty file with `output_metadata' = true.

        When:
            Running script on file

        Then:
            Validate the right output returns.
    """
    mocker.patch("ReadFile.execute_command", return_value={'path': './test_data/test_file_empty.txt'})

    mocker.patch.object(demisto, 'args', return_value={
        'entryID': '1',
        'output_metadata': True,
    })

    file_info = {
        'Data': '',
        'EntryID': '1',
        'FileSize': 0,
        'EOF': True
    }

    expected = {
        'Type': 1,
        'ContentsFormat': 'json',
        'Contents': file_info,
        'HumanReadable': 'Read 0 bytes from file:\n',
        'EntryContext': {
            'ReadFile(obj.EntryID===val.EntryID)': file_info
        }
    }

    mocker.patch.object(demisto, 'results')
    main()
    results = demisto.results.call_args[0][0]
    for k, v in expected.items():
        assert k in results
        assert v == results[k]


def test_read_binary_to_base64_with_meta(mocker):
    """
        Given:
            A file containing binary data with `output_metadata' = true.

        When:
            Running script on file to convert it in base64

        Then:
            Validate the right output returns.
    """
    mocker.patch("ReadFile.execute_command", return_value={'path': './test_data/test_binary.bin'})

    mocker.patch.object(demisto, 'args', return_value={
        'entryID': '1',
        'input_encoding': 'binary',
        'output_data_type': 'base64',
        'output_metadata': True,
    })

    file_info = {
        'Data': 'ASNFZ4k=',
        'EntryID': '1',
        'FileSize': 5,
        'EOF': True
    }

    expected = {
        'Type': 1,
        'ContentsFormat': 'json',
        'Contents': file_info,
        'HumanReadable': 'Read 5 bytes from file:\nASNFZ4k=',
        'EntryContext': {
            'ReadFile(obj.EntryID===val.EntryID)': file_info
        }
    }

    mocker.patch.object(demisto, 'results')
    main()
    results = demisto.results.call_args[0][0]
    for k, v in expected.items():
        assert k in results
        assert v == results[k]


def test_read_utf8_to_json_with_meta(mocker):
    """
        Given:
            A file containing a json text in UTF-8 with `output_metadata' = true.

        When:
            Running script on file to convert it in json structure.

        Then:
            Validate the right output returns.
    """
    mocker.patch("ReadFile.execute_command", return_value={'path': './test_data/test_json_utf8.bin'})

    mocker.patch.object(demisto, 'args', return_value={
        'entryID': '1',
        'input_encoding': 'utf-8',
        'output_data_type': 'json',
        'output_metadata': True,
    })

    file_info = {
        'Data': {
            'a': 'b'
        },
        'EntryID': '1',
        'FileSize': 9,
        'EOF': True
    }

    expected = {
        'Type': 1,
        'ContentsFormat': 'json',
        'Contents': file_info,
        'HumanReadable': 'Read 9 bytes from file:\n' + str({"a": "b"}),
        'EntryContext': {
            'ReadFile(obj.EntryID===val.EntryID)': file_info
        }
    }

    mocker.patch.object(demisto, 'results')
    main()
    results = demisto.results.call_args[0][0]
    for k, v in expected.items():
        assert k in results
        assert v == results[k]


def test_read_utf16be_to_json_with_meta(mocker):
    """
        Given:
            A file containing a json text in UTF-16BE with `output_metadata' = true.

        When:
            Running script on file to convert it in json structure.

        Then:
            Validate the right output returns.
    """
    mocker.patch("ReadFile.execute_command", return_value={'path': './test_data/test_json_utf16be.bin'})

    mocker.patch.object(demisto, 'args', return_value={
        'entryID': '1',
        'input_encoding': 'utf-16',
        'output_data_type': 'json',
        'output_metadata': True,
    })

    file_info = {
        'Data': {
            'a': 'b'
        },
        'EntryID': '1',
        'FileSize': 22,
        'EOF': True
    }

    expected = {
        'Type': 1,
        'ContentsFormat': 'json',
        'Contents': file_info,
        'HumanReadable': 'Read 10 bytes from file:\n' + str({"a": "b"}),
        'EntryContext': {
            'ReadFile(obj.EntryID===val.EntryID)': file_info
        }
    }

    mocker.patch.object(demisto, 'results')
    main()
    results = demisto.results.call_args[0][0]
    for k, v in expected.items():
        assert k in results
        assert v == results[k]


def test_read_utf16le_to_json_with_meta(mocker):
    """
        Given:
            A file containing a json text in UTF-16LE with `output_metadata' = true.

        When:
            Running script on file to convert it in json structure.

        Then:
            Validate the right output returns.
    """
    mocker.patch("ReadFile.execute_command", return_value={'path': './test_data/test_json_utf16le.bin'})

    mocker.patch.object(demisto, 'args', return_value={
        'entryID': '1',
        'input_encoding': 'utf-16',
        'output_data_type': 'json',
        'output_metadata': True,
    })

    file_info = {
        'Data': {
            'a': 'b'
        },
        'EntryID': '1',
        'FileSize': 22,
        'EOF': True
    }

    expected = {
        'Type': 1,
        'ContentsFormat': 'json',
        'Contents': file_info,
        'HumanReadable': 'Read 10 bytes from file:\n' + str({"a": "b"}),
        'EntryContext': {
            'ReadFile(obj.EntryID===val.EntryID)': file_info
        }
    }

    mocker.patch.object(demisto, 'results')
    main()
    results = demisto.results.call_args[0][0]
    for k, v in expected.items():
        assert k in results
        assert v == results[k]


def test_read_file_with_chinese_characters(mocker):
    """
        Given:
            File with chinese characters.
            'input_encoding': 'gbk'.
        When:
            Running script on file

        Then:
            Validate the right output returns.
        """
    args = {'input_encoding': 'gbk'}
    mocker.patch("ReadFile.execute_command", return_value={'path': './test_data/file_with_chinese_characters.txt'})

    mocker.patch.object(demisto, 'results')
    read_file(args)
    results = demisto.results.call_args[0][0]
    assert '锟斤拷锟斤拷' in results.get('Contents').get('FileData')
