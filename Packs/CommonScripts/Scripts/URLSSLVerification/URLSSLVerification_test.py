import pytest
import demistomock as demisto  # noqa: F401
from URLSSLVerification import mark_http_as_suspicious, arg_to_list_with_regex, group_urls, main
import re
import requests


@pytest.mark.parametrize('arg, expected_result', [
    ('false', False),
    ('true', True),
    (None, True)
])
def test_is_http_should_be_suspicious(arg, expected_result):
    assert mark_http_as_suspicious(arg) == expected_result


@pytest.mark.parametrize('arg, expected_result', [
    (None, []),
    (['some_url'], ['some_url']),
    ('["some_url"]', ['some_url']),
    ('https://some_url.com', ['https://some_url.com'])
])
def test_arg_to_list_with_regex(arg, expected_result):
    assert arg_to_list_with_regex(arg) == expected_result


def test_group_urls(requests_mock):
    urls = [
        'https://some_url.com',
        'https://some_url.com/resource_1',
        'https://some_url.com/resource_2',
        'https://some_url.com?a=a'
    ]
    requests_mock.get(re.compile('https://some_url.com.*'), exc=requests.exceptions.RequestException)

    assert group_urls(urls) == {'https://some_url.com': set(urls)}


def test_urls_of_same_domain(requests_mock, mocker):
    """
    Given: List of urls from the same malicious domain.

    When: Run the URLSSLVerification script.

    Then: Ensure that all urls marked as malicious.

    """
    urls = [
        'https://some_url.com',
        'https://some_url.com/resource_1',
        'https://some_url.com/resource_2',
        'https://some_url.com?a=a'
    ]
    mocker.patch.object(demisto, 'args', return_value={'url': urls})
    mocker.patch.object(demisto, 'results')
    requests_mock.get(re.compile('https://some_url.com.*'), exc=requests.exceptions.RequestException)

    main()

    contents = demisto.results.call_args[0][0]['Contents']
    assert len(contents) == len(urls)
    assert all(item['Data'] in urls and item['Verified'] is False for item in contents)
