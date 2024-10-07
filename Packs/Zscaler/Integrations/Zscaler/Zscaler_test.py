import demistomock as demisto
import CommonServerPython
from CommonServerPython import urljoin
import pytest
import json
import requests_mock


class ResponseMock:
    def __init__(self, response):
        self._json = response
        self.content = json.dumps(response)
        self.status_code = 200

    def json(self):
        return self._json


class ObjectMocker(dict):
    __getattr__ = dict.__getitem__
    __setattr__ = dict.__setitem__
    __delattr__ = dict.__delitem__


def run_command_test(command_func, args, response_path, expected_result_path, mocker, result_validator=None,
                     resp_type='json'):
    with open(response_path) as response_f:
        response = ResponseMock(json.load(response_f))
    match resp_type:
        case 'json':
            response = response.json()
        case 'content':
            response = response.content

    mocker.patch('Zscaler.http_request', return_value=response)
    if command_func.__name__ in ['url_lookup', 'get_users_command', 'set_user_command',
                                 'get_departments_command', 'get_usergroups_command',
                                 'list_ip_destination_groups', 'create_ip_destination_group',
                                 'edit_ip_destination_group', 'delete_ip_destination_groups']:
        res = command_func(args)
    else:
        res = command_func(**args)
    if result_validator:
        assert result_validator(res)
    else:
        with open(expected_result_path) as ex_f:
            expected_result = json.load(ex_f)
            if isinstance(res, CommonServerPython.CommandResults):
                assert expected_result == res.to_context()
            else:
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

    def validator(res):
        assert res
        assert len(res) == 2
        for command_res in res:
            assert command_res.indicator.url
            assert command_res.indicator.dbot_score
            assert command_res.outputs['urlClassifications']
            assert command_res.outputs_prefix == 'Zscaler.URL'

        return True

    run_command_test(command_func=Zscaler.url_lookup,
                     args={'url': 'https://www.demisto-news.com,https://www.demisto-search.com'},
                     response_path='test_data/responses/url.json',
                     expected_result_path='test_data/results/url.json',
                     mocker=mocker, result_validator=validator,
                     resp_type='content')


def test_url_fails_unknown_error_code(mocker, requests_mock):
    """url"""
    import Zscaler
    Zscaler.BASE_URL = 'http://cloud/api/v1'

    requests_mock.post(urljoin(Zscaler.BASE_URL, 'urlLookup'), status_code=501)
    args = {'url': 'https://www.demisto-news.com,https://www.demisto-search.com'}

    try:
        Zscaler.url_lookup(args)
    except Exception as ex:
        assert 'following error: 501' in str(ex)


def test_url_command_with_urlClassificationsWithSecurityAlert(mocker):
    """url"""
    import Zscaler

    def validator(res):
        assert res
        assert len(res) == 1
        assert res[0].outputs['urlClassifications'] == 'MISCELLANEOUS_OR_UNKNOWN'
        assert res[0].outputs['urlClassificationsWithSecurityAlert'] == 'MALWARE_SITE'
        return True

    run_command_test(command_func=Zscaler.url_lookup,
                     args={'url': 'www.demisto22.com'},
                     response_path='test_data/responses/url_with_urlClassificationsWithSecurityAlert.json',
                     expected_result_path='test_data/results/url_with_urlClassificationsWithSecurityAlert.json',
                     mocker=mocker, result_validator=validator,
                     resp_type='content')


def test_ip_command(mocker):
    """ip"""
    import Zscaler

    def validator(res):
        assert res
        assert len(res) == 2
        for command_res in res:
            assert command_res.indicator.ip
            assert command_res.indicator.dbot_score
            assert command_res.outputs['ipClassifications']
            assert not command_res.outputs.get('urlClassifications')
            assert command_res.outputs_prefix == 'Zscaler.IP'
        return True

    run_command_test(command_func=Zscaler.ip_lookup,
                     args={'ip': '1.22.33.4'},
                     response_path='test_data/responses/ip.json',
                     expected_result_path='test_data/results/ip.json',
                     mocker=mocker, result_validator=validator,
                     resp_type='content')


def test_undo_blacklist_url_command(mocker):
    """zscaler-undo-blacklist-url"""
    import Zscaler
    run_command_test(command_func=Zscaler.unblacklist_url,
                     args={'url': 'www.demisto22.com, www.demisto33.com'},
                     response_path='test_data/responses/blacklist_urls.json',
                     expected_result_path='test_data/results/undo_blacklist_urls.txt',
                     mocker=mocker,
                     resp_type='content')


def test_blacklist_url_command(mocker):
    """zscaler-blacklist-url"""
    import Zscaler
    run_command_test(command_func=Zscaler.blacklist_url,
                     args={'url': 'www.demisto22.com, www.demisto33.com'},
                     response_path='test_data/responses/blacklist_urls.json',
                     expected_result_path='test_data/results/blacklist_urls.txt',
                     mocker=mocker)


def test_category_remove_url(mocker):
    """zscaler-category-remove-url"""
    import Zscaler
    run_command_test(command_func=Zscaler.category_remove,
                     args={'data': "demisto.com, dbot.com,www.demisto22.com",
                           'category_id': 'CUSTOM_1', 'retaining_parent_category_data': None, "data_type": "url"},
                     response_path='test_data/responses/categories.json',
                     expected_result_path='test_data/results/remove_url.json',
                     mocker=mocker)


def test_category_remove_ip(mocker):
    """zscaler-category-remove-ip"""
    import Zscaler
    run_command_test(command_func=Zscaler.category_remove,
                     args={'data': "1.2.3.4,8.8.8.8", 'category_id': 'CUSTOM_1', 'retaining_parent_category_data': None,
                           "data_type": "ip"},
                     response_path='test_data/responses/categories2.json',
                     expected_result_path='test_data/results/remove_ip.json',
                     mocker=mocker)


def test_get_categories(mocker):
    # zscaler-get-categories
    import Zscaler
    run_command_test(command_func=Zscaler.get_categories_command,
                     args={'args': {'displayURL': 'true'}},
                     response_path='test_data/responses/categories2.json',
                     expected_result_path='test_data/results/get_categories.json',
                     mocker=mocker)


def test_get_categories_custom_only(mocker):
    # zscaler-get-categories
    import Zscaler
    run_command_test(command_func=Zscaler.get_categories_command,
                     args={'args': {'displayURL': 'true', 'custom_only': True}},
                     response_path='test_data/responses/categories2.json',
                     expected_result_path='test_data/results/get_categories.json',
                     mocker=mocker)


@pytest.mark.parametrize('display_url, get_ids_and_names_only', [(False, True), (True, True)])
def test_get_categories_ids_and_names_only(mocker, display_url, get_ids_and_names_only):
    # zscaler-get-categories retrieve only categories IDs and names (without urls)
    import Zscaler
    run_command_test(command_func=Zscaler.get_categories_command,
                     args={'args': {'displayURL': display_url, 'get_ids_and_names_only': get_ids_and_names_only}},
                     response_path='test_data/responses/categories2_no_urls.json',
                     expected_result_path='test_data/results/get_categories_no_urls.json',
                     mocker=mocker)


def test_url_quota_command(mocker):
    # zscaler-url-quota
    import Zscaler
    run_command_test(command_func=Zscaler.url_quota_command,
                     args={},
                     response_path='test_data/responses/url_quota.json',
                     expected_result_path='test_data/results/url_quota.json',
                     mocker=mocker)


def test_get_blacklist(mocker):
    # zscaler-get-blacklist
    import Zscaler
    run_command_test(command_func=Zscaler.get_blacklist,
                     args={},
                     response_path='test_data/responses/blacklist_urls.json',
                     expected_result_path='test_data/results/blacklist.json',
                     mocker=mocker,
                     resp_type='content')


def test_get_blacklist_filter(requests_mock):
    """
    Given:
        - The `filter` arg set to `url`
        - API response with a URL and IP

    When:
        - Running the get-blacklist command

    Then:
        - Ensure only the URL is returned
    """
    import Zscaler
    api_res = {
        'blacklistUrls': [
            'demisto.com',
            '8.8.8.8',
        ],
    }
    requests_mock.get(
        'http://cloud/api/v1/security/advanced',
        json=api_res,
    )
    args = {
        'filter': 'url',
    }
    cmd_res = Zscaler.get_blacklist_command(args)
    assert cmd_res['Contents'] == [api_res['blacklistUrls'][0]]


def test_get_blacklist_query(requests_mock):
    """
    Given:
        - The `query` arg set to `demisto`
        - API response with a URL and IP

    When:
        - Running the get-blacklist command

    Then:
        - Ensure only the URL (which contains `demisto`) is returned
    """
    import Zscaler
    api_res = {
        'blacklistUrls': [
            'demisto.com',
            '8.8.8.8',
        ],
    }
    requests_mock.get(
        'http://cloud/api/v1/security/advanced',
        json=api_res,
    )
    args = {
        'query': 'demisto',
    }
    cmd_res = Zscaler.get_blacklist_command(args)
    assert cmd_res['Contents'] == [api_res['blacklistUrls'][0]]


def test_get_blacklist_query_and_filter(requests_mock):
    """
    Given:
        - The `filter` arg set to `ip`
        - The `query` arg set to `8.8.*.8`
        - API response with a URL and IP

    When:
        - Running the get-blacklist command

    Then:
        - Ensure only the IP is returned
    """
    import Zscaler
    api_res = {
        'blacklistUrls': [
            'demisto.com',
            '8.8.8.8',
        ],
    }
    requests_mock.get(
        'http://cloud/api/v1/security/advanced',
        json=api_res,
    )
    args = {
        'filter': 'ip',
        'query': '8.8.*.8',
    }
    cmd_res = Zscaler.get_blacklist_command(args)
    assert cmd_res['Contents'] == [api_res['blacklistUrls'][1]]


def test_get_whitelist(mocker):
    # zscaler-get-whitelist
    import Zscaler
    run_command_test(command_func=Zscaler.get_whitelist,
                     args={},
                     response_path='test_data/responses/whitelist_url.json',
                     expected_result_path='test_data/results/whitelist.json',
                     mocker=mocker,
                     resp_type='content')


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


def test_get_users_command(mocker):
    """zscaler-get-users"""
    import Zscaler
    run_command_test(command_func=Zscaler.get_users_command,
                     args={'pageSize': '100'},
                     response_path='test_data/responses/get_users.json',
                     expected_result_path='test_data/results/get_users.json',
                     mocker=mocker)


def test_set_user_command(mocker):
    """zscaler-update-user"""
    import Zscaler
    user_json = """{
    "department": {"id": "12","name": "user test"},
    "email": "user@test.com",
    "groups": [{"id": 13,"name": "name_test"}],
    "id": 11,
    "name": "name.test.com"
    }"""

    run_command_test(command_func=Zscaler.set_user_command,
                     args={'id': '11',
                           'user': user_json},
                     response_path='test_data/responses/set_user.json',
                     expected_result_path='test_data/results/set_user.json',
                     mocker=mocker,
                     resp_type='response')


def test_get_departments_command(mocker):
    """zscaler-get-departments"""
    import Zscaler
    run_command_test(command_func=Zscaler.get_departments_command,
                     args={'pageSize': '1'},
                     response_path='test_data/responses/get_departments.json',
                     expected_result_path='test_data/results/get_departments.json',
                     mocker=mocker)


def test_get_usergroups_command(mocker):
    """zscaler-get-usergroups"""
    import Zscaler
    run_command_test(command_func=Zscaler.get_usergroups_command,
                     args={'pageSize': '100'},
                     response_path='test_data/responses/get_usergroups.json',
                     expected_result_path='test_data/results/get_usergroups.json',
                     mocker=mocker)


def test_list_ip_destination_groups__command_no_argument(mocker):
    """zscaler-list-ip-destination-groups"""
    import Zscaler
    run_command_test(command_func=Zscaler.list_ip_destination_groups,
                     args={},
                     response_path='test_data/responses/'
                                   + 'list_ip_destination_groups.json',
                     expected_result_path='test_data/results/'
                                          + 'list_ip_destination_groups.json',
                     mocker=mocker)


def test_list_ip_destination_groups__command_with_id_argument(mocker):
    """zscaler-list-ip-destination-groups"""
    import Zscaler
    run_command_test(command_func=Zscaler.list_ip_destination_groups,
                     args={
                         'ip_group_id': '1964949'
                     },
                     response_path='test_data/responses/'
                                   + 'list_ip_destination_groups_with_id.json',
                     expected_result_path='test_data/results/'
                                          + 'list_ip_destination_groups_with'
                                          + '_id.json',
                     mocker=mocker)


def test_list_ip_destination_groups__command_with_exclude_argument(mocker):
    """zscaler-list-ip-destination-groups"""
    import Zscaler
    run_command_test(command_func=Zscaler.list_ip_destination_groups,
                     args={
                         'exclude_type': 'DSTN_OTHER'
                     },
                     response_path='test_data/responses/'
                                   + 'list_ip_destination_groups_with_exclude'
                                   + '.json',
                     expected_result_path='test_data/results/'
                                          + 'list_ip_destination_groups_with'
                                          + '_exclude.json',
                     mocker=mocker)


def test_list_ip_destination_groups_command_with_lite_argument(mocker):
    """zscaler-list-ip-destination-groups-lite"""
    import Zscaler
    run_command_test(command_func=Zscaler.list_ip_destination_groups,
                     args={
                         'lite': 'True'
                     },
                     response_path='test_data/responses/list_ip_destination_groups_lite.json',
                     expected_result_path='test_data/results/list_ip_destination_groups_lite.json',
                     mocker=mocker)


def test_create_ip_destination_group(mocker):
    """zscaler-create-ip-destination-group"""
    import Zscaler
    run_command_test(command_func=Zscaler.create_ip_destination_group,
                     args={
                         'name': 'Test99',
                         'type': 'DSTN_IP',
                         'addresses': [
                             '127.0.0.2',
                             '127.0.0.1'
                         ],
                         'description': 'Localhost'},
                     response_path='test_data/responses/'
                                   + 'create_ip_destination_group.json',
                     expected_result_path='test_data/results/'
                                          + 'create_ip_destination_group.json',
                     mocker=mocker)


def test_edit_ip_destination_group(mocker):
    """zscaler-edit-ip-destination-group"""
    import Zscaler

    run_command_test(command_func=Zscaler.edit_ip_destination_group,
                     args={
                         'ip_group_id': 2000359,
                         'name': 'Test01',
                         'addresses': [
                             '127.0.0.2'
                         ],
                         'description': 'Localhost v2'},
                     response_path='test_data/responses/'
                                   + 'edit_ip_destination_group.json',
                     expected_result_path='test_data/results/'
                                          + 'edit_ip_destination_group.json',
                     mocker=mocker)


def test_delete_ip_destination_groups(mocker):
    """zscaler-delete-ip-destination-group"""
    import Zscaler

    run_command_test(command_func=Zscaler.delete_ip_destination_groups,
                     args={'ip_group_id': '1964949'},
                     response_path='test_data/responses/delete_ip_destination_group.json',
                     expected_result_path='test_data/results/delete_ip_destination_group.json',
                     mocker=mocker)


def test_category_add_url(mocker):
    """
    Given:
        - A category ID, URL, and retaining parent category URL
    When:
        - category_add_url is called
    Then:
        - The URL should be added to the category
    """
    from Zscaler import category_add
    mocker.patch('Zscaler.get_category_by_id', return_value={'urls': []})
    mocker.patch('Zscaler.argToList', side_effect=[['test1.com'], ['test2.com']])
    mocker.patch('Zscaler.add_or_remove_urls_from_category', return_value=None)

    result = category_add('1', 'test1.com', 'test2.com', "url")

    assert result['HumanReadable'].startswith('Added the following URL, retaining-parent-category-url addresses to category 1')


def test_category_add_ip(mocker):
    """
    Given:
        - A category ID, IP address, and retaining parent category IP
    When:
        - category_add_ip is called
    Then:
        - The IP address should be added to the category
    """
    from Zscaler import category_add
    mocker.patch('Zscaler.get_categories', return_value=[{'id': 1, 'urls': [], 'customCategory': 'true'}])
    mocker.patch('Zscaler.add_or_remove_urls_from_category', return_value={})
    result = category_add(1, '1.1.1.1', '1.1.1.1', "ip")
    assert result['HumanReadable'].startswith('Added the following IP, retaining-parent-category-ip addresses to category 1')


def test_return_error_is_called_on_error(mocker, requests_mock):
    """
    Given:
        - Any command run
    When:
        - Calling login() which fails on 429
    Then:
        - Ensure an error entry is returned
    """
    from Zscaler import main
    requests_mock.get('http://cloud/api/v1/status', status_code=429)
    return_error_mock = mocker.patch.object(CommonServerPython, 'return_error')
    main()
    assert return_error_mock.called_once
