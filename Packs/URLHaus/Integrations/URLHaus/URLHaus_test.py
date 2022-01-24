import requests
import demistomock as demisto
import json
from CommonServerPython import DBotScoreReliability
import URLHaus
import pytest


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


url_command_test_reliability_dbot_score = [
    ('online', (3, "The URL is active (online) and currently serving a payload")),
    ('offline', (2, "The URL is inadctive (offline) and serving no payload")),
    ('unknown', (1, "The URL status could not be determined")),
    ('test_no_status', (0, "The URL is not listed")),
    (None, (0, "The URL is not listed"))
]


@pytest.mark.parametrize('status,excepted_output', url_command_test_reliability_dbot_score)
def test_reliability_dbot_score_url(status, excepted_output):
    """

    Given:
        - Url status from URLhaus database.

    When:
        - You calculate dbot score.

    Then:
        - Successes with excepted output.

    """

    output = URLHaus.calculate_dbot_score('url', status)
    for i in range(2):
        assert output[i] == excepted_output[i]


def test_url_command_without_url_fails():
    """

        Given:
            - Indicator raw value from response

        When:
            - Processing raw indicators to real indicators

        Then:
            - Returns extracted value and hashes

    """

    expected_error_msg = "In order to query url," \
                         "please provide url. "
    with pytest.raises(Exception) as e:
        URLHaus.url_command()
    assert str(e.value) == expected_error_msg
