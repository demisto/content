import json
import io


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_list_cases_command(requests_mock):

    from TheHiveProject import list_cases_command, Client

    mock_response = util_load_json('test_data/cases_list.json')

    requests_mock.get('https://test/api/case',
                      json=mock_response)
    requests_mock.get('https://test/api/status',
                      json={'versions': {'TheHive': 'version'}})

    requests_mock.post('https://test/api/case/task/_search',
                       json=[])

    requests_mock.post('https://test/api/case/artifact/_search',
                       json=[])

    client = Client(
        base_url='https://test/api',
        verify=False,
        headers={
            'Authorization': 'Bearer APIKEY'
        },
        proxy=False,
        mirroring='both'
    )

    args = {}
    response = list_cases_command(client, args)

    assert len(response.outputs) == len(mock_response)
    assert response.outputs_prefix == 'TheHive.Cases'
    assert response.outputs_key_field == 'id'


def test_get_case_command(requests_mock):

    from TheHiveProject import get_case_command, Client

    mock_response = util_load_json('test_data/cases_list.json')

    requests_mock.get('https://test/api/case/1',
                      json=mock_response[0])
    requests_mock.get('https://test/api/status',
                      json={'versions': {'TheHive': 'version'}})

    requests_mock.post('https://test/api/case/task/_search',
                       json=[])

    requests_mock.post('https://test/api/case/artifact/_search',
                       json=[])

    client = Client(
        base_url='https://test/api',
        verify=False,
        headers={
            'Authorization': 'Bearer APIKEY'
        },
        proxy=False,
        mirroring='both'
    )

    args = {'id': '1'}
    response = get_case_command(client, args)

    assert response.outputs == mock_response[0]
    assert response.outputs_prefix == 'TheHive.Cases'
    assert response.outputs_key_field == 'id'


def test_update_case_command(requests_mock):

    from TheHiveProject import update_case_command, Client

    mock_original_response = util_load_json('test_data/cases_list.json')
    mock_response = mock_original_response.copy()
    mock_response[0]["title"] = "updated title"
    mock_response[0]["description"] = "updated description"

    requests_mock.get('https://test/api/case/1',
                      json=mock_original_response[0])
    requests_mock.patch('https://test/api/case/1',
                        json=mock_response[0])
    requests_mock.get('https://test/api/status',
                      json={'versions': {'TheHive': 'version'}})

    requests_mock.post('https://test/api/case/task/_search',
                       json=[])

    requests_mock.post('https://test/api/case/artifact/_search',
                       json=[])

    client = Client(
        base_url='https://test/api',
        verify=False,
        headers={
            'Authorization': 'Bearer APIKEY'
        },
        proxy=False,
        mirroring='both'
    )

    args = {'id': '1',
            'title': 'updated title',
            'description': 'updated description'}
    response = update_case_command(client, args)

    assert response.outputs == mock_response[0]
    assert response.outputs_prefix == 'TheHive.Cases'
    assert response.outputs_key_field == 'id'


def test_create_case_command(requests_mock):

    from TheHiveProject import create_case_command, Client

    mock_response = {"_id": "4",
                     "id": "4",
                     "instance": "",
                     "mirroring": "both",
                     "observables": [],
                     "caseId": "4",
                     "createdBy": "example@example.com",
                     "createdAt": "2021-07-22T09:15:09Z",
                     "updatedAt": "2021-07-22T09:15:09Z",
                     "_type": "case",
                     "title": "added case title",
                     "description": "added case description",
                     "severity": 2,
                     "status": "Open",
                     "tasks": [],
                     "owner": "example@example.com"}

    requests_mock.post('https://test/api/case',
                       json=mock_response)
    requests_mock.get('https://test/api/status',
                      json={'versions': {'TheHive': 'version'}})

    client = Client(
        base_url='https://test/api',
        verify=False,
        headers={
            'Authorization': 'Bearer APIKEY'
        },
        proxy=False,
        mirroring='both'
    )

    args = {'title': 'added case title',
            'description': 'added case description',
            'owner': 'example@example.com'}
    response = create_case_command(client, args)

    assert response.outputs == mock_response
    assert response.outputs_prefix == 'TheHive.Cases'
    assert response.outputs_key_field == 'id'


def test_merge_cases_command(requests_mock):

    from TheHiveProject import merge_cases_command, Client

    mock_response = util_load_json('test_data/merged_cases.json')

    requests_mock.post('https://test/api/case/1/_merge/2',
                       json=mock_response)
    requests_mock.get('https://test/api/status',
                      json={'versions': {'TheHive': 'version'}})

    client = Client(
        base_url='https://test/api',
        verify=False,
        headers={
            'Authorization': 'Bearer APIKEY'
        },
        proxy=False,
        mirroring='both'
    )

    args = {'firstCaseID': '1',
            'secondCaseID': '2'}
    response = merge_cases_command(client, args)

    assert response.outputs == mock_response
    assert response.outputs_prefix == 'TheHive.Cases'
    assert response.outputs_key_field == 'id'


def test_get_case_tasks_command(requests_mock):

    from TheHiveProject import get_case_tasks_command, Client

    mock_response = util_load_json('test_data/cases_list.json')

    requests_mock.post('https://test/api/case/task/_search',
                       json=mock_response[1]['tasks'])
    requests_mock.get('https://test/api/status',
                      json={'versions': {'TheHive': 'version'}})
    requests_mock.get('https://test/api/case/2',
                      json=mock_response[1])
    requests_mock.get('https://test/api/case/task/1/log',
                      json=[])
    requests_mock.get('https://test/api/case/task/2/log',
                      json=[])
    requests_mock.post('https://test/api/case/artifact/_search',
                       json=[])

    client = Client(
        base_url='https://test/api',
        verify=False,
        headers={
            'Authorization': 'Bearer APIKEY'
        },
        proxy=False,
        mirroring='both'
    )

    args = {'id': '2'}
    response = get_case_tasks_command(client, args)

    assert response.outputs == mock_response[1]['tasks']
    assert response.outputs_prefix == 'TheHive.Tasks'
    assert response.outputs_key_field == 'id'


def test_get_task_command(requests_mock):

    from TheHiveProject import get_task_command, Client

    mock_response = util_load_json('test_data/cases_list.json')[1]['tasks'][0]

    requests_mock.get('https://test/api/status',
                      json={'versions': {'TheHive': 'version'}})
    requests_mock.get('https://test/api/task/1',
                      json=mock_response)
    requests_mock.get('https://test/api/case/task/1',
                      json=mock_response)
    requests_mock.get('https://test/api/case/task/1/log',
                      json=[])

    client = Client(
        base_url='https://test/api',
        verify=False,
        headers={
            'Authorization': 'Bearer APIKEY'
        },
        proxy=False,
        mirroring='both'
    )

    args = {'id': '1'}
    response = get_task_command(client, args)

    assert response.outputs == mock_response
    assert response.outputs_prefix == 'TheHive.Tasks'
    assert response.outputs_key_field == 'id'


def test_update_task_command(requests_mock):

    from TheHiveProject import update_task_command, Client

    mock_original_response = util_load_json('test_data/cases_list.json')[1]['tasks'][0]
    mock_response = mock_original_response.copy()
    mock_response['title'] = 'updated title'

    requests_mock.get('https://test/api/status',
                      json={'versions': {'TheHive': 'version'}})
    requests_mock.get('https://test/api/task/1',
                      json=mock_original_response)
    requests_mock.get('https://test/api/case/task/1',
                      json=mock_original_response)
    requests_mock.patch('https://test/api/case/task/1',
                        json=mock_response)
    requests_mock.get('https://test/api/case/task/1/log',
                      json=[])

    client = Client(
        base_url='https://test/api',
        verify=False,
        headers={
            'Authorization': 'Bearer APIKEY'
        },
        proxy=False,
        mirroring='both'
    )

    args = {'id': '1'}
    response = update_task_command(client, args)

    assert response.outputs == mock_response
    assert response.outputs_prefix == 'TheHive.Tasks'
    assert response.outputs_key_field == 'id'


def test_get_users_list_command(requests_mock):

    from TheHiveProject import get_users_list_command, Client

    mock_response = util_load_json('test_data/users_list.json')

    requests_mock.get('https://test/api/status',
                      json={'versions': {'TheHive': 'version'}})

    requests_mock.post('https://test/api/user/_search',
                       json=mock_response)

    client = Client(
        base_url='https://test/api',
        verify=False,
        headers={
            'Authorization': 'Bearer APIKEY'
        },
        proxy=False,
        mirroring='both'
    )

    response = get_users_list_command(client, {})

    assert response.outputs == mock_response
    assert response.outputs_prefix == 'TheHive.Users'
    assert response.outputs_key_field == 'id'


def test_get_user_command(requests_mock):

    from TheHiveProject import get_user_command, Client

    mock_response = util_load_json('test_data/users_list.json')[0]

    requests_mock.get('https://test/api/status',
                      json={'versions': {'TheHive': 'version'}})

    requests_mock.get('https://test/api/user/1',
                      json=mock_response)

    client = Client(
        base_url='https://test/api',
        verify=False,
        headers={
            'Authorization': 'Bearer APIKEY'
        },
        proxy=False,
        mirroring='both'
    )

    response = get_user_command(client, {'id': '1'})

    assert response.outputs == mock_response
    assert response.outputs_prefix == 'TheHive.Users'
    assert response.outputs_key_field == 'id'


def test_create_local_user_command(requests_mock):

    from TheHiveProject import create_local_user_command, Client

    mock_response = util_load_json('test_data/added_user.json')

    requests_mock.get('https://test/api/status',
                      json={'versions': {'TheHive': 'version'}})

    requests_mock.post('https://test/api/user',
                       json=mock_response)

    client = Client(
        base_url='https://test/api',
        verify=False,
        headers={
            'Authorization': 'Bearer APIKEY'
        },
        proxy=False,
        mirroring='both'
    )
    args = {
        'login': 'example@example.com',
        'name': 'Test User',
        'roles': ["read", "admin"],
        'password': '1234'
    }
    response = create_local_user_command(client, args)

    assert response.outputs == mock_response
    assert response.outputs_prefix == 'TheHive.Users'
    assert response.outputs_key_field == 'id'


def test_list_observables_command(requests_mock):

    from TheHiveProject import list_observables_command, Client

    mock_response = util_load_json('test_data/cases_list.json')[2]

    requests_mock.get('https://test/api/status',
                      json={'versions': {'TheHive': 'version'}})

    requests_mock.get('https://test/api/case/3',
                      json=mock_response)

    requests_mock.post('https://test/api/case/task/_search',
                       json=[])

    requests_mock.post('https://test/api/case/artifact/_search',
                       json=mock_response['observables'])

    client = Client(
        base_url='https://test/api',
        verify=False,
        headers={
            'Authorization': 'Bearer APIKEY'
        },
        proxy=False,
        mirroring='both'
    )
    args = {
        'id': '3'
    }
    response = list_observables_command(client, args)

    assert response.outputs == mock_response['observables']
    assert response.outputs_prefix == 'TheHive.Observables'
    assert response.outputs_key_field == 'id'


def test_create_observable_command(requests_mock):

    from TheHiveProject import create_observable_command, Client

    mock_original_response = util_load_json('test_data/cases_list.json')[0]
    mock_response = mock_original_response.copy()
    mock_response['observables'].append(
        {
            "_id": "4",
            "id": "4",
            "createdBy": "example@example.com",
            "createdAt": 1627206318617,
            "_type": "case_artifact",
            "dataType": "domain",
            "data": "datas for test",
            "startDate": 1627206318617,
            "tlp": 2,
            "tags": [],
            "ioc": False,
            "sighted": False,
            "message": "messages for test",
            "reports": {},
            "stats": {}
        }
    )

    requests_mock.get('https://test/api/status',
                      json={'versions': {'TheHive': 'version'}})

    requests_mock.get('https://test/api/case/1',
                      json=mock_original_response)

    requests_mock.post('https://test/api/case/task/_search',
                       json=[])

    requests_mock.post('https://test/api/case/artifact/_search',
                       json=[])

    requests_mock.post('https://test/api/case/1/artifact',
                       json=mock_response['observables'])

    client = Client(
        base_url='https://test/api',
        verify=False,
        headers={
            'Authorization': 'Bearer APIKEY'
        },
        proxy=False,
        mirroring='both'
    )
    args = {
        'id': '1'
    }
    response = create_observable_command(client, args)

    assert response.outputs == mock_response['observables']
    assert response.outputs_prefix == 'TheHive.Observables'
    assert response.outputs_key_field == 'id'


def test_update_observable_command(requests_mock):

    from TheHiveProject import update_observable_command, Client

    mock_original_response = util_load_json('test_data/cases_list.json')[2]
    mock_response = mock_original_response.copy()
    mock_response['observables'][0]['message'] = "update message for test"

    requests_mock.get('https://test/api/status',
                      json={'versions': {'TheHive': 'version'}})

    requests_mock.patch('https://test/api/case/artifact/1',
                        json=mock_response['observables'][0])

    client = Client(
        base_url='https://test/api',
        verify=False,
        headers={
            'Authorization': 'Bearer APIKEY'
        },
        proxy=False,
        mirroring='both'
    )
    args = {
        'id': '1',
        'message': "update message for test"
    }
    response = update_observable_command(client, args)

    assert response.outputs['message'] == "update message for test"
    assert "Updated Observable" in response.readable_output
    assert response.outputs_prefix == 'TheHive.Observables'
    assert response.outputs_key_field == 'id'
