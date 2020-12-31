import io
import json


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_get_demisto_severity():
    from LogPoint_SIEM_Integration import get_demisto_severity
    assert get_demisto_severity('low') == 1
    assert get_demisto_severity('anything-else') == 0


def test_get_incidents_command(requests_mock):
    """Tests lp-get-incidents command function.

    Configures requests_mock instance to generate the appropriate
    /incidents API response, loaded from a json file. Checks
    the output of the command function with the expected output.
    """
    from LogPoint_SIEM_Integration import Client, get_incidents_command
    mock_response = util_load_json('test_data/sample_incident_response.json')
    requests_mock.get(
        'https://test.com/incidents',
        json=mock_response)

    client = Client(
        base_url='https://test.com',
        verify=False,
        proxy=False,
        username='username',
        apikey='apikey',
        headers={
            'Content-Type': 'application/json'
        }
    )
    args = {
        'ts_from': 1607314566,
        'ts_to': 1607228166,
    }

    response = get_incidents_command(client, args)

    assert response.outputs_prefix == 'LogPoint.Incidents'
    assert response.outputs_key_field == 'id'
    assert response.outputs == mock_response['incidents']


def test_get_incident_data_command(requests_mock):
    """Tests lp-get-incident-data command function.

    Configures requests_mock instance to generate the appropriate
    /get_data_from_incident API response, loaded from a json file. Checks
    the output of the command function with the expected output.
    """
    from LogPoint_SIEM_Integration import Client, get_incident_data_command
    mock_response = util_load_json('test_data/sample_incident_data_response.json')
    requests_mock.get(
        'https://test.com/get_data_from_incident',
        json=mock_response)

    client = Client(
        base_url='https://test.com',
        verify=False,
        proxy=False,
        username='username',
        apikey='apikey',
        headers={
            'Content-Type': 'application/json'
        }
    )
    args = {
        "incident_obj_id": "5af12974007da85b99a3230b",
        "incident_id": "347b897e1f752cab7ae380918690b11e",
        "date": 1525754228.171028
    }

    response = get_incident_data_command(client, args)

    assert response.outputs_prefix == 'LogPoint.Incidents.data'
    assert response.outputs_key_field == ''
    assert response.outputs == mock_response['rows']


def test_get_incident_states_command(requests_mock):
    """Tests lp-get-incident-states command function.

    Configures requests_mock instance to generate the appropriate
    /incident_states API response, loaded from a json file. Checks
    the output of the command function with the expected output.
    """
    from LogPoint_SIEM_Integration import Client, get_incident_states_command
    # mock_response = SAMPLE_INCIDENT_STATES_RESPONSE
    mock_response = util_load_json('test_data/sample_incident_states_response.json')
    requests_mock.get(
        'https://test.com/incident_states',
        json=mock_response)

    client = Client(
        base_url='https://test.com',
        verify=False,
        proxy=False,
        username='username',
        apikey='apikey',
        headers={
            'Content-Type': 'application/json'
        }
    )
    args = {
        'ts_from': 1607314566,
        'ts_to': 1607228166,
    }

    response = get_incident_states_command(client, args)

    assert response.outputs_prefix == 'LogPoint.Incidents.states'
    assert response.outputs_key_field == 'id'
    assert response.outputs == mock_response['states']


def test_add_incident_comment_command(requests_mock):
    """Tests lp-add-incident-comment command function.

    Configures requests_mock instance to generate the appropriate
    /add_incident_comment API response. Checks
    the output of the command function with the expected output.
    """
    from LogPoint_SIEM_Integration import Client, add_incident_comment_command
    sample_add_incident_comment_response = {
        "success": True,
        "message": "Comments added"
    }
    mock_response = sample_add_incident_comment_response
    requests_mock.post(
        'https://test.com/add_incident_comment',
        json=mock_response)

    client = Client(
        base_url='https://test.com',
        verify=False,
        proxy=False,
        username='username',
        apikey='apikey',
        headers={
            'Content-Type': 'application/json'
        }
    )
    args = {
        'id': "1262bd8cce113de890854455",
        'comment': "Hello world"
    }

    response = add_incident_comment_command(client, args)

    assert response.outputs_prefix == 'LogPoint.Incidents.comment'
    assert response.outputs_key_field == ''
    assert response.outputs == mock_response['message']


def test_assign_incidents_command(requests_mock):
    """Tests lp-assign-incidents command function.

    Configures requests_mock instance to generate the appropriate
    /assign_incident API response. Checks
    the output of the command function with the expected output.
    """
    from LogPoint_SIEM_Integration import Client, assign_incidents_command
    sample_assign_incidents_response = {
        "success": True,
        "message": "Incidents re-assigned"
    }
    mock_response = sample_assign_incidents_response
    requests_mock.post(
        'https://test.com/assign_incident',
        json=mock_response)

    client = Client(
        base_url='https://test.com',
        verify=False,
        proxy=False,
        username='username',
        apikey='apikey',
        headers={
            'Content-Type': 'application/json'
        }
    )
    args = {
        'incident_ids': "1262bd8cce113de890854455",
        'new_assignee': "12b0eacfd8cce4334eef1700"
    }

    response = assign_incidents_command(client, args)

    assert response.outputs_prefix == 'LogPoint.Incidents.assign'
    assert response.outputs_key_field == ''
    assert response.outputs == mock_response['message']


def test_resolve_incidents_command(requests_mock):
    """Tests lp-resolve-incidents command function.

    Configures requests_mock instance to generate the appropriate
    /resolve_incident API response. Checks
    the output of the command function with the expected output.
    """
    from LogPoint_SIEM_Integration import Client, resolve_incidents_command
    sample_resolve_incidents_response = {
        "success": True,
        "message": "Incidents resolved"
    }
    mock_response = sample_resolve_incidents_response
    requests_mock.post(
        'https://test.com/resolve_incident',
        json=mock_response)

    client = Client(
        base_url='https://test.com',
        verify=False,
        proxy=False,
        username='username',
        apikey='apikey',
        headers={
            'Content-Type': 'application/json'
        }
    )
    args = {
        "version": "0.1",
        'incident_ids': "1262bd8cce113de890854455,1262bd8cce113de890854456"
    }

    response = resolve_incidents_command(client, args)

    assert response.outputs_prefix == 'LogPoint.Incidents.resolve'
    assert response.outputs_key_field == ''
    assert response.outputs == mock_response['message']


def test_close_incidents_command(requests_mock):
    """Tests lp-close-incidents command function.

        Configures requests_mock instance to generate the appropriate
        /close_incident API response. Checks
        the output of the command function with the expected output.
        """
    from LogPoint_SIEM_Integration import Client, close_incidents_command
    sample_close_incidents_response = {
        "success": True,
        "message": "Incidents closed"
    }
    mock_response = sample_close_incidents_response
    requests_mock.post(
        'https://test.com/close_incident',
        json=mock_response)

    client = Client(
        base_url='https://test.com',
        verify=False,
        proxy=False,
        username='username',
        apikey='apikey',
        headers={
            'Content-Type': 'application/json'
        }
    )
    args = {
        "version": "0.1",
        'incident_ids': "1262bd8cce113de890854455,1262bd8cce113de890854456"
    }

    response = close_incidents_command(client, args)

    assert response.outputs_prefix == 'LogPoint.Incidents.close'
    assert response.outputs_key_field == ''
    assert response.outputs == mock_response['message']


def test_reopen_incidents_command(requests_mock):
    """Tests lp-reopen-incidents command function.

        Configures requests_mock instance to generate the appropriate
        /reopen_incident API response. Checks
        the output of the command function with the expected output.
        """
    from LogPoint_SIEM_Integration import Client, reopen_incidents_command
    sample_reopen_incidents_response = {
        "success": True,
        "message": "Incidents reopened"
    }
    mock_response = sample_reopen_incidents_response
    requests_mock.post(
        'https://test.com/reopen_incident',
        json=mock_response)

    client = Client(
        base_url='https://test.com',
        verify=False,
        proxy=False,
        username='username',
        apikey='apikey',
        headers={
            'Content-Type': 'application/json'
        }
    )
    args = {
        "version": "0.1",
        'incident_ids': "1262bd8cce113de890854455,1262bd8cce113de890854456"
    }

    response = reopen_incidents_command(client, args)

    assert response.outputs_prefix == 'LogPoint.Incidents.reopen'
    assert response.outputs_key_field == ''
    assert response.outputs == mock_response['message']


def test_get_users_command(requests_mock):
    """Tests lp-get-users command function.

        Configures requests_mock instance to generate the appropriate
        /get_users API response, loaded from a json file. Checks
        the output of the command function with the expected output.
        """
    from LogPoint_SIEM_Integration import Client, get_users_command
    mock_response = util_load_json('test_data/sample_get_users_response.json')
    requests_mock.get(
        'https://test.com/get_users',
        json=mock_response)

    client = Client(
        base_url='https://test.com',
        verify=False,
        proxy=False,
        username='username',
        apikey='apikey',
        headers={
            'Content-Type': 'application/json'
        }
    )

    response = get_users_command(client)

    assert response.outputs_prefix == 'LogPoint.Incidents.users'
    assert response.outputs_key_field == 'id'
    assert response.outputs == mock_response['users']


def test_fetch_incidents(requests_mock):
    """Tests fetch-incidents command function.
    """
    from LogPoint_SIEM_Integration import Client, fetch_incidents
    mock_response = util_load_json('test_data/sample_incident_response.json')
    requests_mock.get(
        'https://test.com/incidents',
        json=mock_response)

    client = Client(
        base_url='https://test.com',
        verify=False,
        proxy=False,
        username='username',
        apikey='apikey',
        headers={
            'Content-Type': 'application/json'
        }
    )
    first_fetch = "1608189921"
    response = fetch_incidents(client, first_fetch)
    assert response == [
        {
            'name': 'Potential SQL Injection attack',
            'occurred': '2018-05-08T04:37:08.171028Z',
            'severity': 4,
            'rawJSON': json.dumps(mock_response['incidents'][0])
        }
    ]
