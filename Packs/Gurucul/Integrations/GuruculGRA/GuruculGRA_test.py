import json
import io


raise Exception("Test")
def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_gra_fetch_users(requests_mock):
    """Unit test
        Given
        - fetch gra users
        - command args page , max
        - command raw response
        When
        - mock the Client's send_request.
        Then
        - run the gra fetch users command using the Client
        Validate the output with mock response
        Validate the output prefix
        Validate key field
    """
    from GuruculGRA import Client, fetch_record_command
    mock_response = util_load_json('test_data/gra-fetch-users.json')
    requests_mock.get('https://test.com/api/users',
                      json=mock_response)
    api_url = '/users'
    params = {'page': 1, 'max': 10}
    client = Client(
        base_url='https://test.com/api',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )
    response = fetch_record_command(client, api_url, 'Gra.Users', 'employeeId', params)
    assert response.outputs == mock_response
    assert response.outputs_prefix == 'Gra.Users'
    assert response.outputs_key_field == 'employeeId'


def test_gra_fetch_accounts(requests_mock):
    """Unit test
        Given
        - fetch gra accounts
        - command args page , max
        - command raw response
        When
        - mock the Client's send_request.
        Then
        - run the gra fetch users command using the Client
        Validate the output with mock response
        Validate the output prefix
        Validate key field
    """
    from GuruculGRA import Client, fetch_record_command
    mock_response = util_load_json('test_data/gra-fetch-accounts.json')
    requests_mock.get('https://test.com/api/accounts',
                      json=mock_response)
    api_url = '/accounts'
    params = {'page': 1, 'max': 10}
    client = Client(
        base_url='https://test.com/api',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )
    response = fetch_record_command(client, api_url, 'Gra.Accounts', 'id', params)
    assert response.outputs == mock_response
    assert response.outputs_prefix == 'Gra.Accounts'
    assert response.outputs_key_field == 'id'


def test_gra_fetch_active_resource_accounts(requests_mock):
    """Unit test
        Given
        - fetch gra active resource accounts
        - command args page , max
        - command raw response
        When
        - mock the Client's send_request.
        Then
        - run the gra fetch users command using the Client
        Validate the output with mock response
        Validate the output prefix
        Validate key field
    """
    from GuruculGRA import Client, fetch_record_command
    mock_response = util_load_json('test_data/gra-fetch-active-resource-accounts.json')
    requests_mock.get('https://test.com/api/resources/Linux/accounts',
                      json=mock_response)
    api_url = '/resources/Linux/accounts'
    params = {'page': 1, 'max': 10}
    client = Client(
        base_url='https://test.com/api',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )
    response = fetch_record_command(client, api_url, 'Gra.Active.Resource.Accounts', 'id', params)
    assert response.outputs == mock_response
    assert response.outputs_prefix == 'Gra.Active.Resource.Accounts'
    assert response.outputs_key_field == 'id'


def test_gra_fetch_user_accounts(requests_mock):
    """Unit test
        Given
        - fetch gra users accounts
        - command args page , max
        - command raw response
        When
        - mock the Client's send_request.
        Then
        - run the gra fetch users command using the Client
        Validate the output with mock response
        Validate the output prefix
        Validate key field
    """
    from GuruculGRA import Client, fetch_record_command
    mock_response = util_load_json('test_data/gra-fetch-user-accounts.json')
    requests_mock.get('https://test.com/api/users/AB1234/accounts',
                      json=mock_response)
    api_url = '/users/AB1234/accounts'
    params = {'page': 1, 'max': 10}
    client = Client(
        base_url='https://test.com/api',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )
    response = fetch_record_command(client, api_url, 'Gra.User.Accounts', 'id', params)
    assert response.outputs == mock_response
    assert response.outputs_prefix == 'Gra.User.Accounts'
    assert response.outputs_key_field == 'id'


def test_gra_fetch_resource_highrisk_accounts(requests_mock):
    """Unit test
        Given
        - fetch gra resource high risk accounts
        - command args page , max
        - command raw response
        When
        - mock the Client's send_request.
        Then
        - run the gra fetch users command using the Client
        Validate the output with mock response
        Validate the output prefix
        Validate key field
    """
    from GuruculGRA import Client, fetch_record_command
    mock_response = util_load_json('test_data/gra-fetch-resource-highrisk-accounts.json')
    requests_mock.get('https://test.com/api/resources/Linux/accounts/highrisk',
                      json=mock_response)
    api_url = '/resources/Linux/accounts/highrisk'
    params = {'page': 1, 'max': 10}
    client = Client(
        base_url='https://test.com/api',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )
    response = fetch_record_command(client, api_url, 'Gra.Resource.Highrisk.Accounts', 'id', params)
    assert response.outputs == mock_response
    assert response.outputs_prefix == 'Gra.Resource.Highrisk.Accounts'
    assert response.outputs_key_field == 'id'


def test_gra_fetch_hpa(requests_mock):
    """Unit test
        Given
        - fetch high privileged accounts
        - command args page , max
        - command raw response
        When
        - mock the Client's send_request.
        Then
        - run the gra fetch users command using the Client
        Validate the output with mock response
        Validate the output prefix
        Validate key field
    """
    from GuruculGRA import Client, fetch_record_command
    mock_response = util_load_json('test_data/gra-fetch-hpa.json')
    requests_mock.get('https://test.com/api/accounts/highprivileged',
                      json=mock_response)
    api_url = '/accounts/highprivileged'
    params = {'page': 1, 'max': 10}
    client = Client(
        base_url='https://test.com/api',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )
    response = fetch_record_command(client, api_url, 'Gra.Hpa', 'id', params)
    assert response.outputs == mock_response
    assert response.outputs_prefix == 'Gra.Hpa'
    assert response.outputs_key_field == 'id'


def test_gra_fetch_resource_hpa(requests_mock):
    """Unit test
        Given
        - fetch high privileged accounts for resource
        - command args page, max
        - command raw response
        When
        - mock the Client's send_request.
        Then
        - run the gra fetch users command using the Client
        Validate the output with mock response
        Validate the output prefix
        Validate key field
    """
    from GuruculGRA import Client, fetch_record_command
    mock_response = util_load_json('test_data/gra-fetch-resource-hpa.json')
    requests_mock.get('https://test.com/api/resources/Linux/accounts/highprivileged',
                      json=mock_response)
    api_url = '/resources/Linux/accounts/highprivileged'
    params = {'page': 1, 'max': 10}
    client = Client(
        base_url='https://test.com/api',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )
    response = fetch_record_command(client, api_url, 'Gra.Resource.Hpa', 'id', params)
    assert response.outputs == mock_response
    assert response.outputs_prefix == 'Gra.Resource.Hpa'
    assert response.outputs_key_field == 'id'


def test_gra_fetch_orphan_accounts(requests_mock):
    """Unit test
        Given
        - fetch orphan accounts
        - command args page, max
        - command raw response
        When
        - mock the Client's send_request.
        Then
        - run the gra fetch users command using the Client
        Validate the output with mock response
        Validate the output prefix
        Validate key field
    """
    from GuruculGRA import Client, fetch_record_command
    mock_response = util_load_json('test_data/gra-fetch-orphan-accounts.json')
    requests_mock.get('https://test.com/api/accounts/orphan',
                      json=mock_response)
    api_url = '/accounts/orphan'
    params = {'page': 1, 'max': 10}
    client = Client(
        base_url='https://test.com/api',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )
    response = fetch_record_command(client, api_url, 'Gra.Orphan.Accounts', 'id', params)
    assert response.outputs == mock_response
    assert response.outputs_prefix == 'Gra.Orphan.Accounts'
    assert response.outputs_key_field == 'id'


def test_gra_fetch_resource_orphan_accounts(requests_mock):
    """Unit test
        Given
        - fetch orphan accounts for resource
        - command args page, max, resource
        - command raw response
        When
        - mock the Client's send_request.
        Then
        - run the gra fetch users command using the Client
        Validate the output with mock response
        Validate the output prefix
        Validate key field
    """
    from GuruculGRA import Client, fetch_record_command
    mock_response = util_load_json('test_data/gra-fetch-resource-orphan-accounts.json')
    requests_mock.get('https://test.com/api/resources/Linux/accounts/orphan',
                      json=mock_response)
    api_url = '/resources/Linux/accounts/orphan'
    params = {'page': 1, 'max': 10}
    client = Client(
        base_url='https://test.com/api',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )
    response = fetch_record_command(client, api_url, 'Gra.Resource.Orphan.Accounts', 'id', params)
    assert response.outputs == mock_response
    assert response.outputs_prefix == 'Gra.Resource.Orphan.Accounts'
    assert response.outputs_key_field == 'id'


def test_gra_user_activities(requests_mock):
    """Unit test
        Given
        - fetch gra user activities
        - command args page, max
        - command raw response
        When
        - mock the Client's send_request.
        Then
        - run the gra fetch users command using the Client
        Validate the output with mock response
        Validate the output prefix
        Validate key field
    """
    from GuruculGRA import Client, fetch_record_command
    mock_response = util_load_json('test_data/gra-user-activities.json')
    requests_mock.get('https://test.com/api/user/AB1234/activity',
                      json=mock_response)
    api_url = '/user/AB1234/activity'
    params = {'page': 1, 'max': 10}
    client = Client(
        base_url='https://test.com/api',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )
    response = fetch_record_command(client, api_url, 'Gra.User.Activity', 'id', params)
    assert response.outputs == mock_response
    assert response.outputs_prefix == 'Gra.User.Activity'
    assert response.outputs_key_field == 'id'


def test_fetch_gra_users_details(requests_mock):
    """Unit test
        Given
        - fetch gra user details
        - command args page, max, employeeId
        - command raw response
        When
        - mock the Client's send_request.
        Then
        - run the gra fetch users command using the Client
        Validate the output with mock response
        Validate the output prefix
        Validate key field
    """
    from GuruculGRA import Client, fetch_record_command
    mock_response = util_load_json('test_data/gra-fetch-users-details.json')
    requests_mock.get('https://test.com/api/users/AB1234',
                      json=mock_response)
    api_url = '/users/AB1234'
    params = {'page': 1, 'max': 10}
    client = Client(
        base_url='https://test.com/api',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )
    response = fetch_record_command(client, api_url, 'Gra.User', 'employeeId', params)
    assert response.outputs == mock_response
    assert response.outputs_prefix == 'Gra.User'
    assert response.outputs_key_field == 'employeeId'


def test_gra_highRisk_users(requests_mock):
    """Unit test
        Given
        - fetch gra high risk users
        - command args page, max
        - command raw response
        When
        - mock the Client's send_request.
        Then
        - run the gra fetch users command using the Client
        Validate the output with mock response
        Validate the output prefix
        Validate key field
    """
    from GuruculGRA import Client, fetch_record_command
    mock_response = util_load_json('test_data/gra-highRisk-users.json')
    requests_mock.get('https://test.com/api/users/highrisk',
                      json=mock_response)
    api_url = '/users/highrisk'
    params = {'page': 1, 'max': 10}
    client = Client(
        base_url='https://test.com/api',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )
    response = fetch_record_command(client, api_url, 'Gra.Highrisk.Users', 'employeeId', params)
    assert response.outputs == mock_response
    assert response.outputs_prefix == 'Gra.Highrisk.Users'
    assert response.outputs_key_field == 'employeeId'


def test_gra_cases(requests_mock):
    """Unit test
        Given
        - fetch gra cases as per status
        - command args page, max
        - command raw response
        When
        - mock the Client's send_request.
        Then
        - run the gra fetch users command using the Client
        Validate the output with mock response
        Validate the output prefix
        Validate key field
    """
    from GuruculGRA import Client, fetch_record_command
    mock_response = util_load_json('test_data/gra-cases.json')
    requests_mock.get('https://test.com/api/cases/OPEN',
                      json=mock_response)
    api_url = '/cases/OPEN'
    params = {'page': 1, 'max': 10}
    client = Client(
        base_url='https://test.com/api',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )
    response = fetch_record_command(client, api_url, 'Gra.Cases', 'caseId', params)
    assert response.outputs == mock_response
    assert response.outputs_prefix == 'Gra.Cases'
    assert response.outputs_key_field == 'caseId'


def test_fetch_user_anomalies(requests_mock):
    """Unit test
        Given
        - fetch gra user anomalies
        - command args page, max
        - command raw response
        When
        - mock the Client's send_request.
        Then
        - run the gra fetch users command using the Client
        Validate the output with mock response
        Validate the output prefix
        Validate key field
    """
    from GuruculGRA import Client, fetch_record_command
    mock_response = util_load_json('test_data/gra-user-anomalies.json')
    requests_mock.get('https://test.com/api/users/AB1234/anomalies/',
                      json=mock_response)
    anomaly_url = '/users/AB1234/anomalies/'
    params = {'page': 1, 'max': 10}
    client = Client(
        base_url='https://test.com/api',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )
    response = fetch_record_command(client, anomaly_url, 'Gra.User.Anomalies', 'anomaly_name', params)
    assert response.outputs == mock_response
    assert response.outputs_prefix == 'Gra.User.Anomalies'
    assert response.outputs_key_field == 'anomaly_name'


def test_module(mocker):
    """
    Given
    - Gurucul GRA test application
    When
    - mock the demisto params.
    - mock the Client's generate_token
    Then
    - run the test_module command using the Client
    Validate The response is ok.
    """
    from GuruculGRA import Client, test_module_command
    client = Client(
        base_url='https://test.com/api',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )
    mocker.patch.object(client, 'validate_api_key')
    result = test_module_command(client)
    assert result == 'ok'
