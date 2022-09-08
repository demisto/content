from FireEyeDetonateFile import get_results, denote_file, poll_stage
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import pytest


@pytest.mark.parametrize('feDone, profiles, status', [
    (False, ["profile_1", "profile_2"], {"profile_1": "Done", "profile_2": "in progress"})
])
def test_get_results(mocker, feDone, profiles, status):
    mocker.patch.object(demisto, 'results')
    get_results(feDone, profiles, status, None, None)
    res = demisto.results
    content = res.call_args[0][0]
    print(content)
    assert False
