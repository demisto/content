import pytest

from ExtractIndicatorsFromTextFile import *


def execute_command(command, args):
    if command == 'getFilePath':
        return [{'Contents': {'path': './test_data/test_file.txt'}}]
    if command == "extractIndicators":
        return [{'Contents': '1.1.1.1'}]


def test_extract_indicators(mocker):
    """
        Given:
            A file containing an indicator.

        When:
            Running script on file

        Then:
            Validate the right output returns.
        """
    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)
    args = {}
    results = extract_indicators_from_file(args)
    assert {'Contents': '1.1.1.1', 'ContentsFormat': 'text', 'HumanReadable': '1.1.1.1', 'Type': 1} == results


def test_extract_indicators_no_file():
    """
        Given:
            Name of file that does not exist.

        When:
            Running script on file

        Then:
            Validate the right output returns.
        """
    args = {'maxFileSize': 1024 ** 2}
    with pytest.raises(FileNotFoundError) as e:
        extract_indicators_from_file(args)
        if not e:
            assert False
