import json
import io


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def util_load_bytes(path):
    with io.open(path, mode='r') as f:
        return f.read()


def test_list_users(requests_mock):
    """
    Tests synapse-list-users command function.
    """
    from Synapse import Client, list_users_command

    mock_response = util_load_json('test_data/list_users.json')
    requests_mock.get('https://test.com/api/v1/auth/users', json=mock_response)
    mock_roles = util_load_json('test_data/list_roles.json')
    requests_mock.get('https://test.com/api/v1/auth/roles', json=mock_roles)

    client = Client(
        base_url='https://test.com/api/v1',
        username='test',
        password='test',
        verify=False,
        proxy=False
    )

    response = list_users_command(client)

    assert response.outputs_prefix == 'Synapse.Users'
    assert response.outputs_key_field == 'Iden'
    assert response.outputs[0]['Iden'] == mock_response['result'][0]['iden']


def test_list_roles(requests_mock):
    """
    Tests synapse-list-users command function.
    """
    from Synapse import Client, list_roles_command

    mock_response = util_load_json('test_data/list_roles.json')
    requests_mock.get('https://test.com/api/v1/auth/roles', json=mock_response)
    mock_roles = util_load_json('test_data/list_roles.json')
    requests_mock.get('https://test.com/api/v1/auth/roles', json=mock_roles)

    client = Client(
        base_url='https://test.com/api/v1',
        username='test',
        password='test',
        verify=False,
        proxy=False
    )

    response = list_roles_command(client)

    assert response.outputs_prefix == 'Synapse.Roles'
    assert response.outputs_key_field == 'Iden'
    assert response.outputs[0]['Iden'] == mock_response['result'][0]['iden']


def test_create_user(requests_mock):
    """
    Tests synapse-create-user command function.
    """
    from Synapse import Client, add_user_command

    mock_response = util_load_json('test_data/add_user.json')
    requests_mock.post('https://test.com/api/v1/auth/adduser', json=mock_response)
    mock_roles = util_load_json('test_data/list_roles.json')
    requests_mock.get('https://test.com/api/v1/auth/roles', json=mock_roles)

    client = Client(
        base_url='https://test.com/api/v1',
        username='test',
        password='test',
        verify=False,
        proxy=False
    )

    args = {
        'username': 'new_user',
        'password': 'new_pass'
    }

    response = add_user_command(client, args)

    assert response.outputs_prefix == 'Synapse.Users'
    assert response.outputs_key_field == 'Iden'
    assert response.outputs['Iden'] == mock_response['result']['iden']
    assert response.outputs['Name'] == mock_response['result']['name']


def test_create_role(requests_mock):
    """
    Tests synapse-create-role command function.
    """
    from Synapse import Client, add_role_command

    mock_response = util_load_json('test_data/add_role.json')
    requests_mock.post('https://test.com/api/v1/auth/addrole', json=mock_response)

    client = Client(
        base_url='https://test.com/api/v1',
        username='test',
        password='test',
        verify=False,
        proxy=False
    )

    args = {
        'name': 'new_role'
    }

    response = add_role_command(client, args)

    assert response.outputs_prefix == 'Synapse.Roles'
    assert response.outputs_key_field == 'Iden'
    assert response.outputs['Iden'] == mock_response['result']['iden']


def test_grant_user_role(requests_mock):
    """
    Tests synapse-grant-user-role command function.
    """
    from Synapse import Client, grant_user_role_command

    mock_response = util_load_json('test_data/grant_role.json')
    requests_mock.post('https://test.com/api/v1/auth/grant', json=mock_response)
    mock_roles = util_load_json('test_data/list_roles.json')
    requests_mock.get('https://test.com/api/v1/auth/roles', json=mock_roles)

    client = Client(
        base_url='https://test.com/api/v1',
        username='test',
        password='test',
        verify=False,
        proxy=False
    )

    args = {
        'user': '01f39e62cdff72b3abf65e1b4f3667de',
        'role': 'f45bacf3583360ce3d92cd52f6369da8'
    }

    response = grant_user_role_command(client, args)

    assert response.outputs_prefix == 'Synapse.Users'
    assert response.outputs_key_field == 'Iden'
    assert response.outputs['Iden'] == mock_response['result']['iden']


def test_query_model(requests_mock):
    """
    Tests synapse-query-model command function.
    """
    from Synapse import Client, query_model_command

    mock_response = util_load_json('test_data/query_model.json')
    requests_mock.get('https://test.com/api/v1/model', json=mock_response)

    client = Client(
        base_url='https://test.com/api/v1',
        username='test',
        password='test',
        verify=False,
        proxy=False
    )

    args = {
        'query': 'inet:ipv4'
    }

    response = query_model_command(client, args)

    assert response.outputs_prefix == 'Synapse.Model'
    assert response.outputs_key_field == 'Valu'
    assert response.outputs['Doc'] == mock_response['result']['types']['inet:ipv4']['info']['doc']
    assert response.outputs['Properties']['asn'] == \
        mock_response['result']['forms']['inet:ipv4']['props']['asn']['doc']


"""
Unclear how to test async requests that stream data
via aiohttp using iter_chunks().

Same goes for other command functions that rely on the
storm async streaming API. Leaving this here as a placeholder.


def test_storm_query(requests_mock):
    '''
    Tests synapse-storm-query command function.
    '''
    from Synapse import Client, storm_query_command

    mock_response = util_load_bytes('test_data/storm_query.blob')
    requests_mock.get('https://test.com/api/v1/storm', json=mock_response)

    client = Client(
        base_url='https://test.com/api/v1/storm',
        username='test',
        password='test',
        verify=False,
        proxy=False
    )

    args = {
        'query': 'inet:ipv4=1.2.3.4'
    }

    response = storm_query_command(client, args)

    assert response.outputs_prefix == 'Synapse.Nodes'
    assert response.outputs_key_field == 'valu'
    assert response.outputs['form'] == 'inet:ipv4'
    assert response.outputs['valu'] == '1.2.3.4'
"""
