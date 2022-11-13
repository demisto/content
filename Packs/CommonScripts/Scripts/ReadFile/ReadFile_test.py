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
