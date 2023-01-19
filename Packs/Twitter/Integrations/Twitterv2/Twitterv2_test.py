import json
import io
import freezegun
import pytest
import requests


class ResponseMock:
    def __init__(self, _json={}):
        self.status_code = 200
        self._json = _json

    def json(self):
        return self._json


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


test_data = util_load_json('test_data/test_data.json')


@pytest.mark.parametrize('response, expected_output, expected_human_readable, expected_raw', [
                         (test_data['search_tweets_response'], test_data['search_tweet_output'],
                          test_data['search_tweets_human_readable'], test_data['search_tweets_response'])])
def test_twitter_tweet_search_command(mocker, response, expected_output, expected_human_readable, expected_raw):
    """
    Given:
        - script_results
    When:
        - after running a script on the XDRIR integration
    Then:
        - choose the last script that is related to the process list.
        (contains the Name,CPU,Memory in the entry).
    """
    from Twitterv2 import Client, twitter_tweet_search_command

    client = Client(base_url='some_base_url', verify=False,
                    headers={'Authorization': 'Bearer 000'})
    args = {
        'query': 'some_tweet_text',
        'start_time': '',
        'end_time': '',
        'limit': '10',
        'next_token': '',
    }
    mocker.patch.object(requests, 'request', return_value=ResponseMock(response))
    result = twitter_tweet_search_command(client, args)

    assert result[0].outputs == expected_output
    assert result[0].readable_output == expected_human_readable
    assert result[0].raw_response == expected_raw


@pytest.mark.parametrize('response, expected_output, expected_human_readable, expected_raw', [
                         (test_data['user_get_response'], test_data['result_user_get_response'],
                          test_data['user_get_human_readable'], test_data['user_get_response'])])
def test_twitter_user_get_command(mocker, response, expected_output, expected_human_readable, expected_raw):
    """
    Given:
        - script_results
    When:
        - after running a script on the XDRIR integration
    Then:
        - choose the last script that is related to the process list.
        (contains the Name,CPU,Memory in the entry).
    """
    from Twitterv2 import Client, twitter_user_get_command

    client = Client(base_url='some_base_url', verify=False,
                    headers={'Authorization': 'Bearer 000'})
    args = {
        'user_name': 'some_username',
        'return_pinned_tweets': 'True',
        'limit': '100',
    }
    mocker.patch.object(requests, 'request', return_value=ResponseMock(response))
    result = twitter_user_get_command(client, args)

    mocker.patch.object(requests, 'request', return_value=ResponseMock(response))

    assert result.readable_output == expected_human_readable
    assert result.outputs == expected_output
    assert result.raw_response == expected_raw


@freezegun.freeze_time('2020-11-25T11:57:28Z')
@pytest.mark.parametrize('date, expected_result', [
                         ('7 Days ago', '2020-11-18T11:57:28Z'),
                         ('2020-11-18T13:57:28Z', '2020-11-18T13:57:28Z'),
                         ('2020-11-18', '2020-11-18T00:00:00Z'),
                         ('2020/11/18', '2020-11-18T00:00:00Z'),
                         ('18/11/2020', '2020-11-18T00:00:00Z')])
def test_date_to_iso_format(date, expected_result):
    """
    Tests date_to_iso_format
    Given:
        - date representation
    When:
        - calling date_to_iso_format
    Then:
        - return an ISO format
    """
    from Twitterv2 import date_to_iso_format

    result = date_to_iso_format(date)
    assert result == expected_result


@pytest.mark.parametrize('human_readable, expected_human_readable', [
                         (test_data['input_user_get_response'], test_data['result_create_human_readable'])])
def test_create_human_readable(human_readable, expected_human_readable):
    """
    Tests create_human_readable
    Given:
        - list of nested dictionaries
    When:
        - calling create_human_readable
    Then:
        - return a list of non nest dictionaries
    """
    from Twitterv2 import create_human_readable

    result = create_human_readable(human_readable)
    assert result == expected_human_readable
