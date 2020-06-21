import demistomock as demisto
import CommonServerPython
import pytest
import json
import requests_mock


class ResponseMock:
    def __init__(self, response):
        self._json = response
        self.content = json.dumps(response)

    def json(self):
        return self._json


def run_command_test(command_func, args, response_path, expected_result_path, mocker):
    with open(response_path, 'r') as response_f:
        response = ResponseMock(json.load(response_f))
    mocker.patch('Zscaler.http_request', return_value=response)
    if command_func.__name__ == 'url_lookup':
        res = command_func(args)
    else:
        res = command_func(**args)
    with open(expected_result_path, 'r') as ex_f:
        expected_result = json.load(ex_f)
        assert expected_result == res


@pytest.fixture(autouse=True)
def init_tests(mocker):
    params = {
        'cloud': 'http://cloud',
        'credentials': {
            'identifier': 'security',
            'password': 'ninja'
        },
        'key': 'api'
    }
    mocker.patch.object(demisto, 'params', return_value=params)


def test_validate_urls_invalid(mocker):
    return_error_mock = mocker.patch.object(CommonServerPython, 'return_error')
    import Zscaler
    invalid_urls = ['http://not_very_valid', 'https://maybe_valid.', 'www.valid_url.com']
    Zscaler.validate_urls(invalid_urls)
    assert return_error_mock.call_count == 2


def test_url_command(mocker):
    """url"""
    import Zscaler
    run_command_test(command_func=Zscaler.url_lookup,
                     args={'url': 'www.demisto22.com'},
                     response_path='test_data/responses/url.json',
                     expected_result_path='test_data/results/url.json',
                     mocker=mocker)


def test_ip_command(mocker):
    """ip"""
    import Zscaler
    run_command_test(command_func=Zscaler.ip_lookup,
                     args={'ip': '1.22.33.4'},
                     response_path='test_data/responses/ip.json',
                     expected_result_path='test_data/results/ip.json',
                     mocker=mocker)


def test_undo_blacklist_url_command(mocker):
    """zscaler-undo-blacklist-url"""
    import Zscaler
    run_command_test(command_func=Zscaler.unblacklist_url,
                     args={'url': 'www.demisto22.com, www.demisto33.com'},
                     response_path='test_data/responses/blacklist_urls.json',
                     expected_result_path='test_data/results/blacklist_urls.json',
                     mocker=mocker)


def test_category_remove_url(mocker):
    """zscaler-category-remove-url"""
    import Zscaler
    run_command_test(command_func=Zscaler.category_remove_url,
                     args={'url': "demisto.com, dbot.com,www.demisto22.com", 'category_id': 'CUSTOM_1'},
                     response_path='test_data/responses/categories.json',
                     expected_result_path='test_data/results/remove_url.json',
                     mocker=mocker)


def test_category_remove_ip(mocker):
    """zscaler-category-remove-ip"""
    import Zscaler
    run_command_test(command_func=Zscaler.category_remove_ip,
                     args={'ip': "1.2.3.4,8.8.8.8", 'category_id': 'CUSTOM_1'},
                     response_path='test_data/responses/categories2.json',
                     expected_result_path='test_data/results/remove_ip.json',
                     mocker=mocker)


def test_get_categories(mocker):
    # zscaler-get-categories
    import Zscaler
    run_command_test(command_func=Zscaler.get_categories_command,
                     args={'display_url': 'true'},
                     response_path='test_data/responses/categories2.json',
                     expected_result_path='test_data/results/get_categories.json',
                     mocker=mocker)


def test_get_blacklist(mocker):
    # zscaler-get-blacklist
    import Zscaler
    run_command_test(command_func=Zscaler.get_blacklist,
                     args={},
                     response_path='test_data/responses/blacklist_urls.json',
                     expected_result_path='test_data/results/blacklist.json',
                     mocker=mocker)


def test_get_whitelist(mocker):
    # zscaler-get-whitelist
    import Zscaler
    run_command_test(command_func=Zscaler.get_whitelist,
                     args={},
                     response_path='test_data/responses/whitelist_url.json',
                     expected_result_path='test_data/results/whitelist.json',
                     mocker=mocker)


# disable-secrets-detection-start
test_data = [
    ('https://madeup.fake.com/css?family=blah:1,2,3', 'true', ['https://madeup.fake.com/css?family=blah:1', '2', '3']),
    ('https://madeup.fake.com/css?family=blah:1,2,3', 'false', ['https://madeup.fake.com/css?family=blah:1,2,3'])
]
# disable-secrets-detection-end
@pytest.mark.parametrize('url,multiple,expected_data', test_data)
def test_url_multiple_arg(url, multiple, expected_data):
    '''Scenario: Submit a URL with commas in it

    Given
    - A URL with commas in it
    When
    - case A: 'multiple' argument is set to "true" (the default)
    - case B: 'multiple' argument is set to "false"
    Then
    - case A: Ensure the URL is interpreted as multiple values to be sent in the subsequent API call
    - case B: Ensure the URL is interpreted as a single value to be sent in the subsequent API call

    Args:
        url (str): The URL to submit.
        multiple (str): "true" or "false" - whether to interpret the 'url' argument as multiple comma separated values.
        expected_data (list): The data expected to be sent in the API call.
    '''
    import Zscaler
    with requests_mock.mock() as m:
        # 'fake_resp_content' doesn't really matter here since we are checking the data being sent in the call,
        # not what it is that we expect to get in response
        fake_resp_content = '[{"url": "blah", "urlClassifications": [], "urlClassificationsWithSecurityAlert": []}]'
        m.post(Zscaler.BASE_URL + '/urlLookup', content=fake_resp_content)
        args = {
            'url': url,
            'multiple': multiple
        }
        Zscaler.url_lookup(args)
    assert m.called
    assert m.call_count == 1
    request_data = m.last_request.json()
    assert len(request_data) == len(expected_data)
    assert request_data == expected_data
