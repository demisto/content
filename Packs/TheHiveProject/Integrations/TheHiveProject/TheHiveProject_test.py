import json
import io

import dateparser


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

    assert response.outputs == mock_response
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
