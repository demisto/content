import demistomock as demisto
import CheckPhish
from CommonServerPython import DBotScoreReliability

RESULTS = {
    'status': 'DONE',
    'job_id': 'jobid1234',
    'url': 'http://test.com/',
    'brand': 'unknown',
    'url_sha256': '33f57dd894c986dadb1f0c9bde11bea035833560d889607bf63971093abf0695',
    'error': False
}


def test_reliability_in_get_result_checkphish(requests_mock, mocker):
    """
        Given:
            - The user reliability param and the bad_disp param that exist in the default list
        When:
            - Running get_result_checkphish
        Then:
            - Verify reliability as excepted
            - Verify dbot score is expected according the bad disposition
    """
    mocked_results = RESULTS
    mocked_results['disposition'] = 'phish'
    requests_mock.post('https://developers.checkphish.ai/api/neo/scan/status', json=mocked_results)

    mocker.patch.object(demisto, 'results')
    CheckPhish.get_result_checkphish('jobid1234', 'apikey', 'https://developers.checkphish.ai/api/neo/scan', False,
                                     DBotScoreReliability.B)

    assert demisto.results.call_args_list[0][0][0]['Contents'] == RESULTS
    assert demisto.results.call_args_list[0][0][0]['EntryContext']['DBotScore']['Reliability'] == DBotScoreReliability.B
    assert demisto.results.call_args_list[0][0][0]['EntryContext']['DBotScore']['Score'] == 3


def test_bad_disp_param(requests_mock, mocker):
    """
        Given:
            - The user bad_disp param which does not exist in the default list
        When:
            - Running get_result_checkphish
        Then:
            - Verify reliability as excepted
            - Verify dbot score is expected according the bad disposition
    """
    mocked_results = RESULTS
    mocked_results['disposition'] = 'bad_disp_which_is_not_default'
    requests_mock.post('https://developers.checkphish.ai/api/neo/scan/status', json=mocked_results)

    mocker.patch.object(demisto, 'results')
    CheckPhish.get_result_checkphish('jobid1234', 'apikey', 'https://developers.checkphish.ai/api/neo/scan', False,
                                     DBotScoreReliability.B)

    assert demisto.results.call_args_list[0][0][0]['Contents'] == RESULTS
    assert demisto.results.call_args_list[0][0][0]['EntryContext']['DBotScore']['Score'] == 0
