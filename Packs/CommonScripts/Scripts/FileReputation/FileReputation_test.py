import demistomock as demisto
import pytest


@pytest.mark.parametrize('contents', ({'Error': 'error'}, None))
def test_file_reputation(mocker, contents):
    """
    Given:
        - Script args:  MD5 hash string.

    When:
        - Running the file_reputation function.

    Then:
        - Validating the outputs as expected.
    """
    from FileReputation import file_reputation
    mocker.patch.object(demisto, 'args', return_value={'file': 'somefile'})
    execute_command_res = [{'Type': 4, 'Contents': contents, 'Brand': 'brand'}]
    execute_mock = mocker.patch.object(demisto, 'executeCommand', return_value=execute_command_res)
    results_mock = mocker.patch.object(demisto, 'results')
    file_reputation()
    assert execute_mock.call_count == 1
    assert 'returned an error' in results_mock.call_args[0][0][0]['Contents']


def test_file_reputation_ignore_offset_error(mocker):
    """
    Given:
        - Script args: MD5 hash string.

    When:
        - Running file_reputation function using VT integration and an error entry (type 4) of "offset 1" is returned.

    Then:
        - Ensure the script will ignore the offset 1 error.
    """
    from FileReputation import file_reputation
    mocker.patch.object(demisto, 'args', return_value={'file': 'somefile'})
    execute_command_res = [{'Type': 4, 'Contents': {'Offset': 1}, 'Brand': 'VirusTotal (API v3)'}]
    execute_mock = mocker.patch.object(demisto, 'executeCommand', return_value=execute_command_res)
    results_mock = mocker.patch.object(demisto, 'results')
    file_reputation()
    assert execute_mock.call_count == 1
    assert results_mock.call_args[0][0] == []
