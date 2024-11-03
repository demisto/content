import pytest
import requests_mock
import requests

MOCK_ADDR = 'mock://'


def custom_matcher(request: requests.Request) -> requests.Response | None:
    if request.url == f'{MOCK_ADDR}http://example.com':
        first_history = requests.Response()
        first_history.url = 'http://example.com/'
        first_history.status_code = 301

        second_history = requests.Response()
        second_history.url = 'https://example.com/'
        second_history.status_code = 301

        resp = requests.Response()
        resp.status_code = 200
        resp.url = 'https://www.example.org/'
        resp.history = [first_history, second_history]
        return resp
    return None


REDIRECTED_URL_CASES = [
    (
        {'url': 'http://example.com', 'useHead': 'true'},
        [
            {
                "Data": "http://example.com/",
                "Status": 301
            },
            {
                "Data": "https://example.com/",
                "Status": 301
            },
            {
                "Data": "https://www.example.org/",
                "Status": 200
            }
        ]
    ),
    (
        {'url': 'http://example.com', 'useHead': 'false'},
        [
            {
                "Data": "http://example.com/",
                "Status": 301
            },
            {
                "Data": "https://example.com/",
                "Status": 301
            },
            {
                "Data": "https://www.example.org/",
                "Status": 200
            }
        ]
    ),
]


@pytest.mark.parametrize('params, expected_results', REDIRECTED_URL_CASES)
def test_valid_response_history(params, expected_results):
    """
    Given:
        - A url and whether to use requests.head or requests.get

    When:
        - Running function get_response_history to retrieve the response's history

    Then:
        - Validating the structure of the returned array

    """
    from HTTPListRedirects import get_response_history

    url = params['url']
    use_head = params['useHead']
    request_using_head = True if use_head == 'true' else False

    adapter = requests_mock.Adapter()
    adapter.add_matcher(custom_matcher)
    session = requests.Session()
    session.mount(prefix=MOCK_ADDR, adapter=adapter)
    if request_using_head:
        response = session.head(f'{MOCK_ADDR}{url}')
    else:
        response = session.get(f'{MOCK_ADDR}{url}')
    urls = get_response_history(response=response)
    assert urls == expected_results


HISTORY_URLS_CASES = [
    (
        [
            {
                "Data": "http://example.com/",
                "Status": 301
            },
            {
                "Data": "https://example.com/",
                "Status": 301
            },
            {
                "Data": "https://www.example.org/",
                "Status": 200
            }
        ]
    )
]


@pytest.mark.parametrize('history_urls', HISTORY_URLS_CASES)
def test_valid_command_result(history_urls):
    """
    Given:
        - A valid parsed response history

    When:
        - Running the function create_command_result to create the output for the command

    Then:
        - Validating the structure of the returned result to the user

    """
    from CommonServerPython import (formats, entryTypes, tableToMarkdown)
    from HTTPListRedirects import create_command_result
    ec = {'URL(val.Data == obj.Data)': [{'Data': history_url['Data']} for history_url in history_urls]}
    expected_command_result = {'ContentsFormat': formats['json'], 'Type': entryTypes['note'], 'Contents': history_urls,
                               'ReadableContentsFormat': formats['markdown'],
                               'HumanReadable': tableToMarkdown('URLs', history_urls, ['Data', 'Status']), 'EntryContext': ec}
    command_result = create_command_result(history_urls=history_urls)
    assert command_result == expected_command_result


SYSTEM_PROXY_CASES = [
    (
        {'use_system_proxy': 'false'}
    )
]


@pytest.mark.parametrize('params', SYSTEM_PROXY_CASES)
def test_environment_variables(params):
    """
    Given:
        - The condition where we don't want to use the system's proxy

    When:
        - Running the function delete_environment_variables to delete specific environment variables

    Then:
        - Validating that the specific environment variables got deleted

    """
    from HTTPListRedirects import delete_environment_variables
    import os
    use_system_proxy = params['use_system_proxy']
    delete_environment_variables(use_system_proxy=use_system_proxy)
    env_variables = ['HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy']
    for env_var in env_variables:
        with pytest.raises(KeyError):
            os.environ[env_var]


USE_HEAD_CASES = [
    (
        {'useHead': 'false'}
    ),
    (
        {'useHead': 'true'}
    )
]


@pytest.mark.parametrize('params', USE_HEAD_CASES)
def test_use_head_variable(requests_mock, params):
    """
    Given:
        - The argument that states if we want to use requests.head or requests.get

    When:
        - Running the function get_response to retrieve the response of a url

    Then:
        - Validating that the request used was requests.head if useHead is true and requests.get otherwise

    """
    from HTTPListRedirects import get_response
    use_head = params['useHead']
    requests_mock.get('http://examples.test.com')
    requests_mock.head('http://examples.test.com')
    get_response(url='http://examples.test.com', use_head=use_head, verify_ssl=False)
    assert (requests_mock.request_history[0].method == 'HEAD' if use_head == 'true'
            else requests_mock.request_history[0].method == 'GET')
