import io
import json

import pytest

import TaniumThreatResponseV2

PROCESS_TREE_RAW = [
    {
        'id': 3,
        'ptid': 3,
        'pid': 1,
        'name': '1: <Pruned Process>',
        'parent': '4: System',
        'children': [
            {
                'id': 44,
                'ptid': 44,
                'pid': 4236,
                'name': '4236: mmc.exe',
                'parent': '1: <Pruned Process>',
                'children': []
            },
            {
                'id': 45,
                'ptid': 45,
                'pid': 4840,
                'name': '4840: cmd.exe',
                'parent': '1: <Pruned Process>',
                'children': []
            }
        ]
    }
]

PROCESS_TREE_TWO_GENERATIONS_RAW = [
    {
        'id': 3,
        'ptid': 3,
        'pid': 1,
        'name': '1: <Pruned Process>',
        'parent': '4: System',
        'children': [
            {
                'id': 44,
                'ptid': 44,
                'pid': 4236,
                'name': '4236: mmc.exe',
                'parent': '1: <Pruned Process>',
                'children': [
                    {
                        'id': 420,
                        'ptid': 44,
                        'pid': 4236,
                        'name': '4236: mmc.exe',
                        'parent': '1: <Pruned Process>',
                        'children': []
                    }
                ]
            }
        ]
    }
]

PROCESS_TREE_ITEM_RES = {
    'ID': 3,
    'PTID': 3,
    'PID': 1,
    'Name': '1: <Pruned Process>',
    'Parent': '4: System',
    'Children': [
        {
            'ID': 44,
            'PTID': 44,
            'PID': 4236,
            'Name': '4236: mmc.exe',
            'Parent': '1: <Pruned Process>',
            'Children': []
        },
        {
            'ID': 45,
            'PTID': 45,
            'PID': 4840,
            'Name': '4840: cmd.exe',
            'Parent': '1: <Pruned Process>',
            'Children': []
        }
    ]
}

PROCESS_TREE_ITEM_TWO_GENERATIONS_RES = {
    'ID': 3,
    'PTID': 3,
    'PID': 1,
    'Name': '1: <Pruned Process>',
    'Parent': '4: System',
    'Children': [
        {
            'ID': 44,
            'PTID': 44,
            'PID': 4236,
            'Name': '4236: mmc.exe',
            'Parent': '1: <Pruned Process>',
            'Children': [
                {
                    'id': 420,
                    'ptid': 44,
                    'pid': 4236,
                    'name': '4236: mmc.exe',
                    'parent': '1: <Pruned Process>',
                    'children': []
                }
            ]
        }
    ]
}

PROCESS_TREE_READABLE_RES = {
    'ID': 3,
    'PTID': 3,
    'PID': 1,
    'Name': '1: <Pruned Process>',
    'Parent': '4: System',
    'Children': [
        {
            'ID': 44,
            'PTID': 44,
            'PID': 4236,
            'Name': '4236: mmc.exe',
            'Parent': '1: <Pruned Process>',
            'ChildrenCount': 0
        },
        {
            'ID': 45,
            'PTID': 45,
            'PID': 4840,
            'Name': '4840: cmd.exe',
            'Parent': '1: <Pruned Process>',
            'ChildrenCount': 0
        }
    ]
}

PROCESS_TREE_TWO_GENERATIONS_READABLE_RES = {
    'ID': 3,
    'PTID': 3,
    'PID': 1,
    'Name': '1: <Pruned Process>',
    'Parent': '4: System',
    'Children': [
        {
            'ID': 44,
            'PTID': 44,
            'PID': 4236,
            'Name': '4236: mmc.exe',
            'Parent': '1: <Pruned Process>',
            'ChildrenCount': 1
        }
    ]
}


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def mock_client():
    client = TaniumThreatResponseV2.Client(base_url=BASE_URL, password='TEST', username='TEST')
    return client


BASE_URL = 'https://test.com'
MOCK_CLIENT = mock_client()


def test_get_process_tree_item():
    tree, readable_output = TaniumThreatResponseV2.get_process_tree_item(PROCESS_TREE_RAW[0], 0)

    assert tree == PROCESS_TREE_ITEM_RES
    assert readable_output == PROCESS_TREE_READABLE_RES


def test_get_process_tree_item_two_generations():
    tree, readable_output = TaniumThreatResponseV2.get_process_tree_item(PROCESS_TREE_TWO_GENERATIONS_RAW[0], 0)

    assert tree == PROCESS_TREE_ITEM_TWO_GENERATIONS_RES
    assert readable_output == PROCESS_TREE_TWO_GENERATIONS_READABLE_RES


''' GENERAL HELPER FUNCTIONS TESTS'''


@pytest.mark.parametrize('test_input, expected_output', [('2', 2), (None, None), (2, 2), ('', None)])
def test_convert_to_int(test_input, expected_output):
    res = TaniumThreatResponseV2.convert_to_int(test_input)
    assert res == expected_output


''' INTEL DOCS FUNCTIONS TESTS'''


def test_get_intel_doc(requests_mock):
    api_expected_response = util_load_json('test_files/get_intel_doc_raw_response.json')
    requests_mock.get(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.get(BASE_URL + '/plugin/products/detect3/api/v1/intels/423', json=api_expected_response)

    human_readable, outputs, raw_response = TaniumThreatResponseV2.get_intel_doc(MOCK_CLIENT, {'intel-doc-id': '423'})
    assert '| 423 | get_doc_test |' in human_readable
    assert outputs.get('Tanium.IntelDoc(val.ID && val.ID === obj.ID)', {}).get('Name') == 'get_doc_test'
    assert outputs.get('Tanium.IntelDoc(val.ID && val.ID === obj.ID)', {}).get('ID') == 423


def test_get_intel_docs(requests_mock):
    api_expected_response = util_load_json('test_files/get_intel_docs_raw_response.json')
    requests_mock.get(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.get(BASE_URL + '/plugin/products/detect3/api/v1/intels/?name=test2', json=api_expected_response[1])

    human_readable, outputs, raw_response = TaniumThreatResponseV2.get_intel_docs(MOCK_CLIENT, {'name': 'test2'})
    assert '| 430 | test2 |' in human_readable
    intel_docs = outputs.get('Tanium.IntelDoc(val.ID && val.ID === obj.ID)', [])
    assert len(intel_docs) > 0
    assert intel_docs[0].get('Name') == 'test2'
    assert intel_docs[0].get('ID') == 430


def test_get_intel_docs_labels_list(requests_mock):
    intel_doc_id = 423
    api_expected_response = util_load_json('test_files/get_intel_docs_labels_list_raw_response.json')
    requests_mock.get(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.get(BASE_URL + f'/plugin/products/detect3/api/v1/intels/{intel_doc_id}/labels',
                      json=api_expected_response)

    human_readable, outputs, raw_response = TaniumThreatResponseV2.get_intel_docs_labels_list(MOCK_CLIENT, {
        'intel-doc-id': intel_doc_id})
    assert 'test3 description | 8 | 0 | test3' in human_readable
    assert 'test4 description | 9 | 0 | test4' in human_readable
    intel_docs = outputs.get('Tanium.IntelDocLabels(val.ID && val.ID === obj.ID).423', [])
    assert len(intel_docs) == 5
    assert intel_docs[1].get('Name') == 'test2'
    assert intel_docs[3].get('ID') == 9


def test_add_intel_docs_label(requests_mock):
    intel_doc_id = 423
    label_id = 3
    api_expected_response = util_load_json('test_files/add_intel_docs_labels_raw_response.json')
    requests_mock.get(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    req = requests_mock.put(BASE_URL + f'/plugin/products/detect3/api/v1/intels/{intel_doc_id}/labels',
                            json=api_expected_response)

    human_readable, outputs, raw_response = TaniumThreatResponseV2.add_intel_docs_label(MOCK_CLIENT,
                                                                                        {'intel-doc-id': intel_doc_id,
                                                                                         'label-id': label_id})
    assert 'Successfully created a new label association' in human_readable
    assert 'test6 description | 3 |' in human_readable
    assert json.loads(req.last_request.text) == {'id': label_id}
    intel_docs = outputs.get('Tanium.IntelDocLabels(val.ID && val.ID === obj.ID).423', [])
    assert len(intel_docs) == 6
    assert intel_docs[5].get('Name') == 'test6'
    assert intel_docs[5].get('ID') == 3


def test_remove_intel_docs_label(requests_mock):
    intel_doc_id = 423
    label_id = 3
    api_expected_response = util_load_json('test_files/get_intel_docs_labels_list_raw_response.json')
    requests_mock.get(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.delete(BASE_URL + f'/plugin/products/detect3/api/v1/intels/{intel_doc_id}/labels/{label_id}',
                         json=api_expected_response)

    human_readable, outputs, raw_response = TaniumThreatResponseV2.remove_intel_docs_label(MOCK_CLIENT, {
        'intel-doc-id': intel_doc_id,
        'label-id': label_id})
    assert 'Successfully removed the label (3)' in human_readable
    for item in raw_response:
        assert item.get('id') != 3


def test_create_intel_doc(mocker, requests_mock):
    with open('test_files/test.ioc') as f:
        file_content = f.read()
    entry_id = 'Test'
    file_extension = '.ioc'
    api_expected_response = util_load_json('test_files/create_intel_docs_raw_response.json')
    mocker.patch('TaniumThreatResponseV2.get_file_name_and_content', return_value=("test_name", file_content))
    requests_mock.get(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.post(BASE_URL + '/plugin/products/detect3/api/v1/intels', json=api_expected_response)

    human_readable, outputs, raw_response = TaniumThreatResponseV2.create_intel_doc(MOCK_CLIENT, {
        'entry-id': entry_id,
        'file-extension': file_extension})
    assert 'Generic indicator for the virus test.' in human_readable
    assert outputs.get('Tanium.IntelDoc(val.ID && val.ID === obj.ID)', {}).get('Name') == 'VIRUS TEST'


def test_update_intel_doc(mocker, requests_mock):
    intel_doc_id = 423
    with open('test_files/test.ioc') as f:
        file_content = f.read()
    entry_id = 'Test'
    file_extension = '.ioc'
    api_expected_response = util_load_json('test_files/update_intel_docs_raw_response.json')
    mocker.patch('TaniumThreatResponseV2.get_file_name_and_content', return_value=("test_name", file_content))
    requests_mock.get(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.put(BASE_URL + f'/plugin/products/detect3/api/v1/intels/{str(intel_doc_id)}',
                      json=api_expected_response)

    human_readable, outputs, raw_response = TaniumThreatResponseV2.update_intel_doc(MOCK_CLIENT, {
        'intel-doc-id': intel_doc_id,
        'entry-id': entry_id,
        'file-extension': file_extension})
    assert 'Generic indicator for the virus test updated.' in human_readable
    assert outputs.get('Tanium.IntelDoc(val.ID && val.ID === obj.ID)', {}).get('Name') == 'VIRUS TEST 2'


def test_deploy_intel(requests_mock):
    api_raw_response = {
        'data': {
            'taskId': 750
        }
    }
    requests_mock.get(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.post(BASE_URL + '/plugin/products/threat-response/api/v1/intel/deploy',
                       json=api_raw_response)

    human_readable, outputs, raw_response = TaniumThreatResponseV2.deploy_intel(MOCK_CLIENT, {})
    assert 'Successfully deployed intel.' == human_readable
    assert api_raw_response == raw_response


def test_get_deploy_status(requests_mock):
    api_raw_response = {
        'data': {
            'createdAt': '2021-05-02T19:18:00.685Z',
            'modifiedAt': '2021-07-14T10:17:13.050Z',
            'currentRevision': 10,
            'currentSize': 2000,
            'pendingRevision': None,
            'pendingSize': None
        }
    }
    requests_mock.get(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.get(BASE_URL + '/plugin/products/threat-response/api/v1/intel/status',
                      json=api_raw_response)

    human_readable, outputs, raw_response = TaniumThreatResponseV2.get_deploy_status(MOCK_CLIENT, {})
    assert 'Intel deploy status' in human_readable
    assert outputs.get('Tanium.IntelDeployStatus', {}).get('CurrentRevision') == 10
