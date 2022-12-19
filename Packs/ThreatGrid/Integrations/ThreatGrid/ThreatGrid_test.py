import os
import pytest
import json
import io
import demistomock as demisto  # noqa: F401

os.environ["HTTP_PROXY"] = "test"
os.environ["HTTPS_PROXY"] = "test"
os.environ["http_proxy"] = "test"
os.environ["https_proxy"] = "test"
PARAMS = {
    'server': 'test',
    'proxy': True,
    'disregard_quota': True,
}

Submit_url_input = {
    'url': 'www.example.com'
}

def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


LIST_MOCK = [
    {
        'Country': 'IL',
        'event_timestamp': '2022-03-02T10: 06: 09Z',
        'identity_display_name': 'paanalyticstest',
        'ip': 'ip',
        'location': '32.0123, 34.7705'
    },
    {
        'Country': 'BE',
        'event_timestamp': '2022-03-02T10: 06: 09Z',
        'identity_display_name': 'paanalyticstest',
        'ip': 'ip',
        'location': '50.8847, 4.5049'
    }]


def test_get_with_limit_list(mocker):
    """
    Given:
        demisto context
    When:
        Executing get_with_limit function
    Then
        ensure limit was made
    """
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    from ThreatGrid import get_with_limit

    mocker.patch.object(demisto, 'get', return_value=LIST_MOCK)

    res = get_with_limit('mock_obj', 'mock_path', 1)
    assert len(res) == 1


DICT_MOCK = {
    'Country': 'IL',
    'event_timestamp': '2022-03-02T10: 06: 09Z',
    'identity_display_name': 'paanalyticstest',
    'ip': 'ip',
    'location': '32.0123, 34.7705'
}



def test_get_with_limit_dict(mocker):
    """
    Given:
        demisto context
    When:
        Executing get_with_limit function
    Then
        ensure limit was made
    """
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    from ThreatGrid import get_with_limit

    mocker.patch.object(demisto, 'get', return_value=DICT_MOCK)

    res = get_with_limit('mock_obj', 'mock_path', 1)
    assert len(res) == 1
    assert len(res.get('Country'))


def test_submit_urls(mocker, requests_mock):
    """
    Given:
        demisto context
    When:
        Executing get_with_limit function
    Then
        ensure limit was made
    """
    mocker.patch.object(demisto, 'args', return_value=Submit_url_input)
    from ThreatGrid import submit_urls
    args = demisto.args
    # Load assertions and mocked request data
    testing_url = Submit_url_input.get('url')
    mock_response = util_load_json('test_data/submit_url.json')
    expected_results = util_load_json('test_data/submit_url_results.json')
    mocker.patch.object(submit_urls, 'req', return_value=mock_response)

    res = submit_urls(args)
    assert res.outputs == expected_results


def test_get_with_limit_fail(mocker):
    """
    Given:
        demisto context
    When:
        Executing get_with_limit function
    Then
        ensure limit was made
    """
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    from ThreatGrid import get_with_limit

    mocker.patch.object(demisto, 'get', return_value="Some string")

    res = get_with_limit('mock_obj', 'mock_path', 1)
    assert res == 'Some string'


@pytest.mark.parametrize('test_dict, expected_result', [
    (
        {'Sample': {'File': [],
                    'Domain': {},
                    'Regitry Keys Created': ['test'],
                    'Sample': {'test': 'test'}},
         'File': 'test',
         'Artifact': 'test'},
        {'Sample': {'File': []}, 'File': 'test', 'Artifact': 'test'}
    )
])
def test_create_analysis_json_human_readable(mocker, test_dict, expected_result):

    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    from ThreatGrid import create_analysis_json_human_readable
    mocker.patch('ThreatGrid.tableToMarkdown', return_value='test')
    create_analysis_json_human_readable(test_dict)
    assert test_dict == expected_result


def test_feed_helper_byte_response(mocker):
    from ThreatGrid import feeds_helper

    class MockResponse:
        def __init__(self):
            self.content = b'{"api_version":2,"id":1234,"request_id":"req-7","data":' \
                           b'{"items":[{"path":"w.dll","sample_id":"123","severity":100,"aid":1}],' \
                           b'"items_per_page":1000}}'

    res = MockResponse()
    mocker.patch('ThreatGrid.req', return_value=res)
    demisto_results_mocker = mocker.patch.object(demisto, 'results')

    feeds_helper('artifacts')
    assert demisto_results_mocker.call_args[0][0][0]['Contents'][0]['id'] == 1234
