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

Search_query_input = {
    'query': '{\r\n\\\"query\\\": \\\"query get_sample($q_json:\r\nString) {sample(, q_json: $q_json,limit: 3) {submitted_at id submitted_file_type status threat_score state login url}}\\\",\\\"variables\\\": {\\\"q_json\\\": \\\"{\\\\\\\"op\\\\\\\": \\\\\\\"and\\\\\\\",\\\\\\\"clauses\\\\\\\": [{\\\\\\\"op\\\\\\\": \\\\\\\"attr\\\\\\\",\\\\\\\"attr\\\\\\\": \\\\\\\"submitted_file_name\\\\\\\",\\\\\\\"comp_op\\\\\\\": \\\\\\\"eq\\\\\\\",\\\\\\\"value\\\\\\\": \\\\\\\"www.example.com_.url\\\\\\\"}]}\\\"}}'
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


def test_submit_urls(mocker):
    # API_KEY = 'API_KEY'
    def mock_req(*args, **kwargs):
        class MockResponse:
            def __init__(self, json_data, status_code):
                self.json_data = json_data
                self.status_code = status_code

            def json(self):
                return self.json_data

        return MockResponse(mock_response, 200)
    # def mock_req(method, path, params={'api_key': API_KEY}, body=None):
    #     return mock_response

    from ThreatGrid import submit_urls
    mock_response = util_load_json('test_data/submit_url.json')
    expected_results = util_load_json('test_data/submit_url_results.json')
    args = Submit_url_input

    res = submit_urls(args, req=mock_req)
    assert res.outputs == expected_results

def test_advanced_seach(mocker, requests_mock):

    mocker.patch.object(demisto, 'args', return_value=Search_query_input)
    from ThreatGrid import advanced_search
    args = demisto.args
    # Load assertions and mocked request data
    testing_url = Submit_url_input.get('url')
    mock_response = util_load_json('test_data/advanced_search.json')
    expected_results = util_load_json('test_data/advanced_search_results.json')
    mocker.patch.object(advanced_search, 'req', return_value=mock_response)

    res = advanced_search(args)
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
