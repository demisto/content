import json
from datetime import datetime


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


def get_headers_for_login():
    headers_for_login = {
        'Authorization': 'Basic some-alphanumeric',
        'X-Domain': 'Domain-1',
        'grant_type': 'client_credentials',
        'Content-Type': 'application/json'
    }
    return headers_for_login


def get_headers_for_query():
    headers_for_query = {
        'Cookie': 'COOKIE',
        'X-Domain': 'DOMAIN',
        'grant_type': 'client_credentials',
        'client_id': 'CLIENT_ID',
        'Content-Type': 'application/json'
    }
    return headers_for_query


def setup():
    from ConcentricAI import LoginClient, QueryClient, initialise_scrolls_and_rules
    headers_login = get_headers_for_login()
    loginClient = LoginClient(base_url='https://mock-url.com',
                              verify='False',
                              headers=headers_login,
                              proxy='False')
    headers_query = get_headers_for_query()
    queryClient = QueryClient(
        base_url='https://mock-url.com',
        headers=headers_query,
        proxy='False')
    initialise_scrolls_and_rules()
    return loginClient, queryClient


def test_test_module(requests_mock):

    from ConcentricAI import LoginClient, test_module
    headers = get_headers_for_login()
    loginClient = LoginClient(base_url='https://mock-url.com',
                              verify='False',
                              headers=headers,
                              proxy='False')

    mock_response = {
        'accessToken': 'token'
    }
    requests_mock.get('https://mock-url.com/api/v1/login', json=mock_response)
    response = test_module(loginClient)
    assert response == 'ok'


def test_fetch_incidents(requests_mock):
    # given : Mock response and arguments needed for the given call
    from ConcentricAI import fetch_incidents
    loginClient, queryClient = setup()
    last_run: dict = {}
    max_results = '100'
    fetch_time = '3 days'
    mock_response = util_load_json('test_data/mock_incident.json')
    requests_mock.post('https://mock-url.com/graphql-third-party', json=mock_response['response'])
    # when : Actual function call
    _, new_incidents = fetch_incidents(loginClient, queryClient, last_run, max_results, fetch_time)
    t = datetime.fromtimestamp(int('1600114903415') / 1000)
    inced_time = t.strftime('%Y-%m-%dT%H:%M:%SZ')
    rawJson = '{"cid": "8f4619ebc927276a5908db0e46be2e7da14df3bd", "rule_name": "risk1,risk3", ' \
              '"service": "sharepoint", "name": "file-name-1", "file-path": "file-path", ' \
              '"owner": ["joe@company.com"], "risk": "high", "risk_timestamp": "1600114903415"}'
    # then : Assert values of the incident populated.
    assert new_incidents == [
        {
            'name': 'file-name-1',
            'occurred': inced_time,
            'severity': 3,
            'rawJSON': rawJson
        }
    ]


def test_fetch_file_information(requests_mock):
    # given : Mock response and arguments needed for the given call
    from ConcentricAI import fetch_file_information
    loginClient, queryClient = setup()
    path = 'path'
    name = 'file-name-1'
    mock_response = util_load_json('test_data/mock_file_information.json')
    requests_mock.post('https://mock-url.com/graphql-third-party', json=mock_response['response'])
    # when : Actual function call
    result = fetch_file_information(loginClient, queryClient, path, name)
    # then : Assert values of the Output prefix
    assert result.outputs_prefix == 'ConcentricAI.FileInfo'
    assert result.outputs_key_field == 'ownerDetails'
    assert result.outputs == mock_response['output']


def test_get_users_overview(requests_mock):
    # given : Mock response and arguments needed for the given call
    from ConcentricAI import get_users_overview
    loginClient, queryClient = setup()
    mock_response = util_load_json('test_data/mock_user_overview.json')
    requests_mock.post('https://mock-url.com/graphql-third-party', json=mock_response['response'])
    max_users = '10'
    # when : Actual function call
    result = get_users_overview(loginClient, queryClient, max_users)
    # then : Assert values of the Output prefix
    assert result.outputs_prefix == 'ConcentricAI.UserInfo'
    assert result.outputs_key_field == 'info'


def test_get_user_details(requests_mock):
    # given : Mock response and arguments needed for the given call
    from ConcentricAI import get_user_details
    loginClient, queryClient = setup()
    mock_response = util_load_json('test_data/mock_user_details.json')
    requests_mock.post('https://mock-url.com/graphql-third-party', json=mock_response['response'])
    user = 'joe'
    # when : Actual function call
    result = get_user_details(loginClient, queryClient, user)
    # then : Assert values of the Output prefix
    assert result.outputs_prefix == 'ConcentricAI.UserDetails'
    assert result.outputs_key_field == 'info'


def test_get_file_sharing_details(requests_mock):
    # given : Mock response and arguments needed for the given call
    from ConcentricAI import get_file_sharing_details
    loginClient, queryClient = setup()
    mock_response = util_load_json('test_data/mock_file_permissions.json')
    requests_mock.post('https://mock-url.com/graphql-third-party', json=mock_response['response'])
    cid = 'lsknadkl12312'
    # when : Actual function call
    result = get_file_sharing_details(loginClient, queryClient, cid)
    # then : Assert values of the Output prefix
    assert result.outputs_prefix == 'ConcentricAI.FileSharingInfo'
    assert result.outputs_key_field == 'info'
