import requests
import demistomock as demisto
import json
from CommonServerPython import DBotScoreReliability
import URLHaus


def test_reliability_in_dbot(mocker):
    """
        Given:
            - The user reliability param
        When:
            - Running url_command
        Then:
            - Verify reliability as excepted
    """

    params = {
        'api_url': 'http://test.com'.rstrip('/'),
        'use_ssl': False,
        'threshold': 1,
        'reliability': DBotScoreReliability.C
    }

    mocker.patch.object(demisto, 'args', return_value={'url': 'http://test.com'})

    response = requests.models.Response()
    response._content = json.dumps({'query_status': 'no_results'}).encode('utf-8')
    mocker.patch.object(URLHaus, 'query_url_information', return_value=response)

    mocker.patch.object(demisto, 'results')
    URLHaus.url_command(**params)

    assert demisto.results.call_args_list[0][0][0]['EntryContext']['DBotScore']['Reliability'] == DBotScoreReliability.C
