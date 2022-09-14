from FireEyeDetonateFile import get_results, detonate_file, poll_stage
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import pytest


@pytest.mark.parametrize('feDone, profiles, status, feSubmissionKeys, file, mock_value, expected_results', [
    (False, [], None, None, None, None, {'Type': 4, 'ContentsFormat': 'text',
     'Contents': 'Could not retrieve results from FireEye (may be due to timeout).'}),
    (True, ["profile_1"], {"profile_1": "Done"}, {"profile_1": "sub1"}, "x",
     [{"Type": 3, "Contents": {"alerts": {"alert": {"info": "test"}}}}],
     {'ContentsFormat': 'markdown', 'Type': 1, 'Contents': '### profile_1\n|info|\n|---|\n| test |\n'}),
    (True, ["profile_1"], {"profile_1": "Done"}, {"profile_1": "sub1"}, "x",
     [{"Type": 3, "Contents": {"alert": {"alert": {"info": "test"}}}}], "No results."),
    (True, ["profile_1"], {"profile_1": "in progress"},
     {"profile_1": "sub2"}, "x", [{"Type": 3, "Contents": {"alert": {"alert": {"info": "test"}}}}],
     {'Type': 4, 'ContentsFormat': 'text', 'Contents': 'FireEye: Failed to detonate file x, exit status = in progress'})
])
def test_get_results(mocker, feDone, profiles, status, feSubmissionKeys, file, mock_value, expected_results):
    """
    Given
    - case 1: get_results function args, including False 'feDone' argument and empty profiles list.
    - case 2: get_results function args, succesful fe-submit-result response mock with "Contents.alerts.alert" section.
    - case 3: get_results function args, succesful fe-submit-result response mock without "Contents.alerts.alert" section.
    - case 4: get_results function args, an errored fe-submit-result response mock.
    When
    - Running get_results function.
    Then
    - Ensure the right results were given and that the function paused the execution.
    """
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'executeCommand', return_value=mock_value)
    get_results(feDone, profiles, status, feSubmissionKeys, file)
    res = demisto.results
    content = res.call_args[0][0]
    assert content == expected_results


@pytest.mark.parametrize('args, first_mock_value, second_mock_value, expected_results', [
    ({"profiles": ["prof1"], "file": "x"}, [{'Contents': 'no'}], None,
     {'Type': 4, 'ContentsFormat': 'text', 'Contents': 'FireEye: Integration not available.'}),
    ({"profiles": ["prof1"], "file": "x"}, [{'Contents': 'yes'}], [{"Type": 4, "Contents": {"ale": {"alert": {"info": "test"}}}}],
     [{'Type': 4, 'Contents': {'ale': {'alert': {'info': 'test'}}}}])
])
def test_denote_file(mocker, args, first_mock_value, second_mock_value, expected_results):
    """
    Given
    - case 1: function args, IsIntegrationAvailable command mock that return 'no'.
    - case 2: function args, IsIntegrationAvailable command mock that return 'yes' and an errored fe-submit mock response.
    When
    - Running denote_file function.
    Then
    - Ensure the right results were given and that the function paused the execution.
    """
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'executeCommand', side_effect=[first_mock_value, second_mock_value])
    detonate_file(args)
    res = demisto.results
    content = res.call_args[0][0]
    assert content == expected_results


@pytest.mark.parametrize('feDone, feSubmissionKeys, profiles, mock_val, expected_results', [
    (False, {"prof1": "prof"}, ["prof1"], [{"Type": 4, "Contents": {"ale": {"alert": {"info": "test"}}}}],
     [{'Type': 4, 'Contents': {'ale': {'alert': {'info': 'test'}}}}])
])
def test_poll_stage(mocker, feDone, feSubmissionKeys, profiles, mock_val, expected_results):
    """
    Given
    - poll_stage function args and an errored mock_response

    When
    - Running poll_stage function.

    Then
    - Ensure the right results were given and that the function paused the execution.
    """
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'executeCommand', side_effect=[mock_val])
    poll_stage(feDone, feSubmissionKeys, profiles, None)
    res = demisto.results
    content = res.call_args[0][0]
    assert content == expected_results
