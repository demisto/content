import demistomock as demisto
import CheckPhish
import pytest
from CommonServerPython import DBotScoreReliability

RESULTS = {
    'status': 'DONE',
    'job_id': 'jobid1234',
    'url': 'http://test.com/',
    'brand': 'unknown',
    'url_sha256': '33f57dd894c986dadb1f0c9bde11bea035833560d889607bf63971093abf0695',
    'error': False
}

cases = [
    (
        'phish',
        3
    ),
    (
        'bad',
        0
    )
]


@pytest.mark.parametrize('bad_disp, expected_score', cases)
def test_reliability_in_get_result_checkphish(requests_mock, mocker, bad_disp, expected_score):
    """
        Given:
            - The user reliability param and the bad_disp param
        When:
            - Running get_result_checkphish
        Then:
            - Verify reliability as excepted
            - Verify dbot score is expected according the bad disposition
    """
    mocked_results = RESULTS
    mocked_results['disposition'] = bad_disp
    requests_mock.post('https://developers.checkphish.ai/api/neo/scan/status', json=mocked_results)

    mocker.patch.object(demisto, 'results')
    CheckPhish.get_result_checkphish('jobid1234', 'apikey', 'https://developers.checkphish.ai/api/neo/scan', False,
                                     DBotScoreReliability.B)

    assert demisto.results.call_args_list[0][0][0]['Contents'] == RESULTS
    assert demisto.results.call_args_list[0][0][0]['EntryContext']['DBotScore']['Reliability'] == DBotScoreReliability.B
    assert demisto.results.call_args_list[0][0][0]['EntryContext']['DBotScore']['Score'] == expected_score
