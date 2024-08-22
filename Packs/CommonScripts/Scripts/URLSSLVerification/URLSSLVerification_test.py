import pytest
from URLSSLVerification import mark_http_as_suspicious, arg_to_list_with_regex, unique_urls


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


def test_unique_urls():
    urls = [
        'https://some_url.com',
        'https://some_url.com/resource_1',
        'https://some_url.com/resource_2',
        'https://some_url.com?a=a'
    ]
    assert unique_urls(urls) == {'https://some_url.com'}
