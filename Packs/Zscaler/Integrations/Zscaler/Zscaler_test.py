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


class ObjectMocker(dict):
    __getattr__ = dict.__getitem__
    __setattr__ = dict.__setitem__
    __delattr__ = dict.__delitem__


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


def test_url_command_with_urlClassificationsWithSecurityAlert(mocker):
    """url"""
    import Zscaler
    run_command_test(command_func=Zscaler.url_lookup,
                     args={'url': 'www.demisto22.com'},
                     response_path='test_data/responses/url_with_urlClassificationsWithSecurityAlert.json',
                     expected_result_path='test_data/results/url_with_urlClassificationsWithSecurityAlert.json',
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
    ('https://madeup.fake.com/css?family=blah:1,2,3', 'true', ['madeup.fake.com/css?family=blah:1', '2', '3']),
    ('https://madeup.fake.com/css?family=blah:1,2,3', 'false', ['madeup.fake.com/css?family=blah:1,2,3'])
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
        fake_resp_content = b'[{"url": "blah", "urlClassifications": [], "urlClassificationsWithSecurityAlert": []}]'
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


def test_login__active_session(mocker):
    """
    Scenario: test login with an active session

    Given:
     - User has authorization to login
     - There is an active session
    When:
     - login is called
    Then:
     - No login request is done
     - Result is as expected
    """
    import Zscaler
    mock_id = 'mock_id'
    mocker.patch.object(demisto, 'debug')
    mocker.patch.object(Zscaler, 'get_integration_context', return_value={Zscaler.SESSION_ID_KEY: mock_id})
    mocker.patch.object(Zscaler, 'test_module')
    Zscaler.login()

    assert Zscaler.DEFAULT_HEADERS['cookie'] == mock_id


def test_login__no_active_session(mocker):
    """
    Scenario: test login when there is no active session

    Given:
     - User has authorization to login
     - There is an active session
    When:
     - User wishes to login using login command
    Then:
     - Result is as expected
    """
    import Zscaler
    mock_header = 'JSESSIONID=MOCK_ID; Path=/; Secure; HttpOnly'
    Zscaler.API_KEY = 'Lcb38EvjtZVc'
    mocker.patch.object(demisto, 'debug')
    mocker.patch.object(Zscaler, 'get_integration_context', return_value={})
    mocker.patch.object(Zscaler, 'test_module')
    mocker.patch.object(Zscaler, 'http_request', return_value=ObjectMocker({'headers': {'Set-Cookie': mock_header}}))
    Zscaler.login()

    assert Zscaler.DEFAULT_HEADERS['cookie'] == 'JSESSIONID=MOCK_ID'


def test_login_command(mocker):
    """
    Scenario: test successful login command

    Given:
     - User provided valid credentials
     - Integration context is empty
    When:
     - zscaler-login command is called
    Then:
     - Ensure logout is not called
     - Ensure login is called
     - Ensure readable output is as expected
    """
    import Zscaler
    mocker.patch.object(demisto, 'debug')
    mocker.patch.object(Zscaler, 'get_integration_context', return_value={})
    logout_mock = mocker.patch.object(Zscaler, 'logout')
    login_mock = mocker.patch.object(Zscaler, 'login')
    raw_res = Zscaler.login_command()

    assert not logout_mock.called
    assert login_mock.called
    assert raw_res.readable_output == 'Zscaler session created successfully.'


def test_login_command__load_from_context(mocker):
    """
    Scenario: test successful login command attempt with load from the context

    Given:
     - User has provided valid credentials
     - Integration context has a previous session
    When:
     - zscaler-login command is called
    Then:
     - Ensure logout is called
     - Ensure login is called
     - Ensure readable output is as expected
    """
    import Zscaler
    mocker.patch.object(demisto, 'debug')
    mocker.patch.object(Zscaler, 'get_integration_context', return_value={Zscaler.SESSION_ID_KEY: 'test_key'})
    logout_mock = mocker.patch.object(Zscaler, 'logout')
    login_mock = mocker.patch.object(Zscaler, 'login')
    raw_res = Zscaler.login_command()

    assert logout_mock.called
    assert login_mock.called
    assert raw_res.readable_output == 'Zscaler session created successfully.'


def test_logout_command__no_context(mocker):
    """
    Scenario: logout when there's no active session

    Given:
     - There is no active session
    When:
     - logout command is performed
    Then:
     - Return readable output detailing no action was performed
    """
    import Zscaler
    mocker.patch.object(Zscaler, 'get_integration_context', return_value={})
    raw_res = Zscaler.logout_command()
    assert raw_res.readable_output == 'No API session was found. No action was performed.'


def test_logout_command__happy_context(mocker):
    """
    Scenario: logout when there's an active session

    Given:
     - There is an active session
    When:
     - logout command is performed
    Then:
     - Return readable output detailing logout was performed
    """
    import Zscaler
    mocker.patch.object(Zscaler, 'get_integration_context', return_value={Zscaler.SESSION_ID_KEY: 'test_key'})
    mocker.patch.object(Zscaler, 'logout', return_value=ResponseMock({}))
    raw_res = Zscaler.logout_command()
    assert raw_res.readable_output == "API session logged out of Zscaler successfully."


def test_logout_command__context_expired(mocker):
    """
    Scenario: fail to logout with AuthorizationError when there's an active session

    Given:
     - There is an active session
    When:
     - logout command is performed
     - logout action fails with AuthorizationError
    Then:
     - Return readable output detailing no logout was done
    """
    import Zscaler
    mocker.patch.object(Zscaler, 'get_integration_context', return_value={Zscaler.SESSION_ID_KEY: 'test_key'})
    mocker.patch.object(Zscaler, 'logout', side_effect=Zscaler.AuthorizationError(''))
    raw_res = Zscaler.logout_command()
    assert raw_res.readable_output == "API session is not authenticated. No action was performed."
