from typing import Union
import pytest
import requests_mock
import requests

MOCK_ADDR = 'mock://'


def custom_matcher(request: requests.Request) -> Union[requests.Response, None]:
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
        - Running command get_response_history

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
