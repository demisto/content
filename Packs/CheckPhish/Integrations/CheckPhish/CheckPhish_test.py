import demistomock as demisto
import CheckPhish
from CommonServerPython import DBotScoreReliability

RESULTS = {
    'status': 'DONE',
    'job_id': 'jobid1234',
    'url': 'http://test.com/',
    'brand': 'unknown',
    'url_sha256': '33f57dd894c986dadb1f0c9bde11bea035833560d889607bf63971093abf0695',
    'disposition': 'clean',
    'error': False
}


def test_reliability_in_get_result_checkphish(requests_mock, mocker):
    """
        Given:
            - The user reliability param
        When:
            - Running get_result_checkphish
        Then:
            - Verify reliability as excepted
    """

    requests_mock.post('https://developers.checkphish.ai/api/neo/scan/status', json=RESULTS)

    mocker.patch.object(demisto, 'results')
    CheckPhish.unite_dispositions('adult', 'cryptojacking', 'clean')
    CheckPhish.get_result_checkphish('jobid1234', 'apikey', 'https://developers.checkphish.ai/api/neo/scan', False,
                                     DBotScoreReliability.B)

    assert demisto.results.call_args_list[0][0][0]['Contents'] == RESULTS
    assert demisto.results.call_args_list[0][0][0]['EntryContext']['DBotScore']['Reliability'] == DBotScoreReliability.B
