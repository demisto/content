from FireEyeDetonateFile import get_results, denote_file, poll_stage
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
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'executeCommand', return_value=mock_value)
    get_results(feDone, profiles, status, feSubmissionKeys, file)
    res = demisto.results
    content = res.call_args[0][0]
    assert content == expected_results
