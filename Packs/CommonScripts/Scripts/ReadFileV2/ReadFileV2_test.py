from ReadFileV2 import main
import demistomock as demisto


def test_read_file_default(mocker):
    """
        Given:
            A file containing text.

        When:
            Running script on file

        Then:
            Validate the right output returns.
    """
    mocker.patch("ReadFileV2.execute_command", return_value={'path': './test_data/test_file.txt'})

    mocker.patch.object(demisto, 'args', return_value={
        'entry_id': '1'
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
        'HumanReadable': 'Read 9 charactors from file.',
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


def test_read_file_as_binary(mocker):
    """
        Given:
            A file containing text.

        When:
            Running script to read a file as binary

        Then:
            Validate the right output returns.
    """
    mocker.patch("ReadFileV2.execute_command", return_value={'path': './test_data/test_file.txt'})

    mocker.patch.object(demisto, 'args', return_value={
        'entry_id': '1',
        'input_encoding': 'binary'
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
        'HumanReadable': 'Read 9 bytes from file.',
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


def test_read_file_incomplete(mocker):
    """
        Given:
            A file containing text.

        When:
            Running script to read a file over max_file_size

        Then:
            Validate the right output returns.
    """
    mocker.patch("ReadFileV2.execute_command", return_value={'path': './test_data/test_file.txt'})

    mocker.patch.object(demisto, 'args', return_value={
        'entry_id': '1',
        'max_file_size': 3
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
        'HumanReadable': 'Read 3 charactors from file.',
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


def test_read_empty_file(mocker):
    """
        Given:
            Name of empty file.

        When:
            Running script on file

        Then:
            Validate the right output returns.
    """
    mocker.patch("ReadFileV2.execute_command", return_value={'path': './test_data/test_file_empty.txt'})

    mocker.patch.object(demisto, 'args', return_value={
        'entry_id': '1'
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
        'HumanReadable': 'Read 0 charactors from file.',
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


def test_read_binary_to_base64(mocker):
    """
        Given:
            A file containing binary data.

        When:
            Running script on file to convert it in base64

        Then:
            Validate the right output returns.
    """
    mocker.patch("ReadFileV2.execute_command", return_value={'path': './test_data/test_binary.bin'})

    mocker.patch.object(demisto, 'args', return_value={
        'entry_id': '1',
        'input_encoding': 'binary',
        'output_data_type': 'base64'
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
        'HumanReadable': 'Read 5 bytes from file.',
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


def test_read_utf8_to_json(mocker):
    """
        Given:
            A file containing a json text in UTF-8.

        When:
            Running script on file to convert it in json structure.

        Then:
            Validate the right output returns.
    """
    mocker.patch("ReadFileV2.execute_command", return_value={'path': './test_data/test_json_utf8.bin'})

    mocker.patch.object(demisto, 'args', return_value={
        'entry_id': '1',
        'input_encoding': 'utf-8',
        'output_data_type': 'json'
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
        'HumanReadable': 'Read 9 charactors from file.',
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


def test_read_utf16be_to_json(mocker):
    """
        Given:
            A file containing a json text in UTF-16BE.

        When:
            Running script on file to convert it in json structure.

        Then:
            Validate the right output returns.
    """
    mocker.patch("ReadFileV2.execute_command", return_value={'path': './test_data/test_json_utf16be.bin'})

    mocker.patch.object(demisto, 'args', return_value={
        'entry_id': '1',
        'input_encoding': 'utf-16',
        'output_data_type': 'json'
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
        'HumanReadable': 'Read 10 charactors from file.',
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


def test_read_utf16le_to_json(mocker):
    """
        Given:
            A file containing a json text in UTF-16LE.

        When:
            Running script on file to convert it in json structure.

        Then:
            Validate the right output returns.
    """
    mocker.patch("ReadFileV2.execute_command", return_value={'path': './test_data/test_json_utf16le.bin'})

    mocker.patch.object(demisto, 'args', return_value={
        'entry_id': '1',
        'input_encoding': 'utf-16',
        'output_data_type': 'json'
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
        'HumanReadable': 'Read 10 charactors from file.',
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
