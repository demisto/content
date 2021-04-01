import time
from threading import Thread
import pytest
import requests
import demistomock as demisto
import json
from CommonServerPython import DBotScoreReliability
import URLHaus


def test_reliability_in_dbot(mocker):
    params = {
        'api_url': 'http://test.com'.rstrip('/'),
        'use_ssl': False,
        'threshold': 1,
        'reliability': DBotScoreReliability.C
    }

    a = {'Type': 1, 'ContentsFormat': 'json', 'Contents': {'query_status': 'no_results'},
         'HumanReadable': '## URLhaus reputation for http://test.com\nNo results!', 'HumanReadableFormat': 'markdown',
         'EntryContext': {'URL': {'Data': 'http://test.com'},
                          'DBotScore': {'Type': 'url', 'Vendor': 'URLhaus', 'Indicator': 'http://test.com',
                                        'Reliability': DBotScoreReliability.C, 'Score': 0}}}
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'args', return_value={'url': 'http://test.com'})
    response = requests.models.Response()
    response._content = json.dumps({'query_status': 'no_results'}).encode('utf-8')
    mocker.patch.object(URLHaus, 'query_url_information', return_value=response)

    URLHaus.url_command(**params)
    assert demisto.results.assert_called_with(a)
    # assert mocked_results.assert_called_with() == 1
