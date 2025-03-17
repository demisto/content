import json
from datetime import datetime

import pytest
from dateparser import parse

import TaniumThreatResponseV2


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


def mock_client():
    client = TaniumThreatResponseV2.Client(base_url=BASE_URL, password='TEST', username='TEST', api_version="4.x")
    return client


BASE_URL = 'https://test.com'
MOCK_CLIENT = mock_client()

FILTER_FILE_DOWNLOADS_ARGS = [
    ({'offset': '0', 'limit': '50', 'hostname': 'host1'}, 3),
    ({'offset': '0', 'limit': '50', 'hostname': 'host2'}, 2),
    ({'offset': '0', 'limit': '50', 'hostname': 'host3'}, 2),
    ({'offset': '0', 'limit': '50', 'hostname': 'host2,host3'}, 4),
    (
        {
            'offset': '0',
            'limit': '50',
            'hash': '123',
        },
        2,
    ),
    (
        {
            'offset': '0',
            'limit': '50',
            'hash': '123,1234',
        },
        3,
    ),
]

FILTER_CONNECTIONS_LIST_ARGS = [
    ({'offset': '0', 'limit': '50', 'hostname': 'host1'}, 3),
    ({'offset': '0', 'limit': '50', 'hostname': 'host2'}, 2),
    ({'offset': '0', 'limit': '50', 'hostname': 'host3'}, 2),
    ({'offset': '0', 'limit': '50', 'hostname': 'host1,host2'}, 5),
    ({'offset': '0', 'limit': '50', 'platform': 'Linux'}, 3),
    ({'offset': '0', 'limit': '50', 'platform': 'Windows'}, 4),
    ({'offset': '0', 'limit': '50', 'status': 'connected'}, 2),
    ({'offset': '0', 'limit': '50', 'status': 'disconnected'}, 5),
    ({'offset': '0', 'limit': '50', 'ip': '3.3.3.3'}, 4),
    (
        {
            'offset': '0',
            'limit': '50',
            'ip': '3.3.3.3',
            'hostname': 'host2',
        },
        6
    ),
]

FILTER_EVIDENCE_LIST_ARGS = [
    ({'offset': '0', 'limit': '50', 'hostname': 'host1,host2'}, 6),
    ({'offset': '0', 'limit': '50', 'hostname': 'host1'}, 3),
    ({'offset': '0', 'limit': '50', 'hostname': 'host2'}, 3),
    ({'offset': '0', 'limit': '50', 'hostname': 'host3'}, 2),
    (
        {
            'offset': '0',
            'limit': '50',
            'hostname': 'host1,host3',
            'type': 'event',
        },
        5,
    ),
]

FILTER_GET_SYSTEM_STATUS_ARGS = [
    ({'offset': '0', 'limit': '50', 'status': 'Leader'}, 2),
    ({'offset': '0', 'limit': '50', 'status': 'Normal'}, 1),
    (
        {
            'offset': '0',
            'limit': '50',
            'status': 'Normal',
            'hostname': 'host1',
        },
        3,
    ),
    (
        {
            'offset': '0',
            'limit': '50',
            'hostname': 'host1',
            'ip_client': '3.3.3.3',
        },
        4,
    ),
    (
        {
            'offset': '0',
            'limit': '50',
            'hostname': 'host3',
            'ip_server': '1.1.1.1',
        },
        2,
    ),
    ({'offset': '0', 'limit': '50', 'hostname': 'host1,host2,host4'}, 4),
    ({'offset': '0', 'limit': '50', 'port': '8080'}, 2),
]

""" GENERAL HELPER FUNCTIONS TESTS"""


@pytest.mark.parametrize('test_input, expected_output', [('2', 2), (None, None), (2, 2), ('', None)])
def test_convert_to_int(test_input, expected_output):
    """
    Given -
        An object to convert to int.

    When -
        Running convert_to_int function.

    Then -
        If the object can be converted to int, the function returns the int, otherwise returns None.
    """

    res = TaniumThreatResponseV2.convert_to_int(test_input)
    assert res == expected_output


@pytest.mark.parametrize('test_input, expected_output', [({'testingFunctionFirst': 1, 'testingFunctionSecond': 2},
                                                          {'TestingFunctionFirst': 1, 'TestingFunctionSecond': 2}),

                                                         ([{'testingFunctionFirst': 1}, {'testingFunctionSecond': 2}],
                                                          [{'TestingFunctionFirst': 1}, {'TestingFunctionSecond': 2}])])
def test_format_context_data(test_input, expected_output):
    """
    Given -
        A dict or a list of dicts to format to standard context.

    When -
        Running format_context_data function.
        Running format_context_data function.

    Then -
        A formatted dict should be returned.
    """

    assert TaniumThreatResponseV2.format_context_data(test_input) == expected_output


''' INTEL DOCS FUNCTIONS TESTS'''


def test_get_intel_doc(requests_mock):
    """
    Given -
        A specific intel doc id.

    When -
        Running get_intel_doc function.

    Then -
        The intel doc details should be returned.
    """

    api_expected_response = util_load_json('test_data/get_intel_doc_raw_response.json')
    requests_mock.post(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.get(BASE_URL + '/plugin/products/detect3/api/v1/intels/423', json=api_expected_response)
    requests_mock.get(BASE_URL + '/plugin/products/threat-response/api/v1/intels/423',
                      json={'data': api_expected_response})
    human_readable, outputs, raw_response = TaniumThreatResponseV2.get_intel_doc(MOCK_CLIENT, {'intel_doc_id': '423'})
    assert '| 423 | get_doc_test |' in human_readable
    assert outputs.get('Tanium.IntelDoc(val.ID && val.ID === obj.ID)', {}).get('Name') == 'get_doc_test'
    assert outputs.get('Tanium.IntelDoc(val.ID && val.ID === obj.ID)', {}).get('ID') == 423


def test_get_intel_docs_single(requests_mock):
    """
    Given -
        A specific intel name to obtain.

    When -
        Running get_intel_docs function.

    Then -
        This intel doc details should be returned.
    """

    api_expected_response = util_load_json('test_data/get_intel_docs_raw_response.json')
    requests_mock.post(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.get(BASE_URL + '/plugin/products/detect3/api/v1/intels/?name=test2', json=api_expected_response[1])
    requests_mock.get(BASE_URL + '/plugin/products/threat-response/api/v1/intels/?name=test2',
                      json={'data': api_expected_response[1]})

    human_readable, outputs, raw_response = TaniumThreatResponseV2.get_intel_docs(MOCK_CLIENT, {'name': 'test2'})
    assert '| 430 | test2 |' in human_readable
    intel_docs = outputs.get('Tanium.IntelDoc(val.ID && val.ID === obj.ID)', [])
    assert intel_docs.get('Name') == 'test2'
    assert intel_docs.get('ID') == 430


def test_get_intel_docs_multiple(requests_mock):
    """
    Given -
        Some data args to filter.

    When -
        Running get_intel_docs function.

    Then -
        A list of all intel docs with their details should be returned.
    """

    api_expected_response = util_load_json('test_data/get_intel_docs_raw_response.json')
    requests_mock.post(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.get(BASE_URL + '/plugin/products/detect3/api/v1/intels/', json=api_expected_response)
    requests_mock.get(BASE_URL + '/plugin/products/threat-response/api/v1/intels/',
                      json={'data': api_expected_response})

    human_readable, outputs, raw_response = TaniumThreatResponseV2.get_intel_docs(MOCK_CLIENT, {})
    intel_docs = outputs.get('Tanium.IntelDoc(val.ID && val.ID === obj.ID)', [])
    assert len(intel_docs) == 3


def test_get_intel_docs_labels_list(requests_mock):
    """
    Given -
        A specific intel-doc ID.

    When -
        Running get_intel_docs_labels_list function.

    Then -
        A list of label IDs of this specific intel-doc.
    """

    intel_doc_id = 423
    api_expected_response = util_load_json('test_data/get_intel_docs_labels_list_raw_response.json')
    requests_mock.post(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.get(BASE_URL + f'/plugin/products/detect3/api/v1/intels/{intel_doc_id}/labels',
                      json=api_expected_response)
    requests_mock.get(BASE_URL + f'/plugin/products/threat-response/api/v1/intels/{intel_doc_id}/labels',
                      json={'data': api_expected_response})

    human_readable, outputs, raw_response = TaniumThreatResponseV2.get_intel_docs_labels_list(MOCK_CLIENT, {
        'intel_doc_id': intel_doc_id})
    assert '| 8 | test3 |' in human_readable
    assert '| 9 | test4 |' in human_readable
    intel_docs = outputs.get('Tanium.IntelDocLabel(val.IntelDocID && val.IntelDocID === obj.IntelDocID)', {})
    assert intel_docs.get('IntelDocID') == 423
    labels = intel_docs.get('LabelsList')
    assert len(labels) == 5
    assert labels[1].get('Name') == 'test2'
    assert labels[3].get('ID') == 9


def test_add_intel_docs_label(requests_mock):
    """
    Given -
        A specific intel-doc ID.
        A specific label ID.

    When -
        Running add_intel_docs_label function.

    Then -
        A list of label IDs of this specific intel-doc with the label ID added.
    """

    intel_doc_id = 423
    label_id = 3
    api_expected_response = util_load_json('test_data/add_intel_docs_labels_raw_response.json')
    requests_mock.post(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    req = requests_mock.put(BASE_URL + f'/plugin/products/detect3/api/v1/intels/{intel_doc_id}/labels',
                            json=api_expected_response)
    req_4 = requests_mock.put(BASE_URL + f'/plugin/products/threat-response/api/v1/intels/{intel_doc_id}/labels',
                              json={'data': api_expected_response})

    human_readable, outputs, raw_response = TaniumThreatResponseV2.add_intel_docs_label(MOCK_CLIENT,
                                                                                        {'intel_doc_id': intel_doc_id,
                                                                                         'label_id': label_id})
    assert 'Successfully created a new label (3) association for the identified intel document (423).' in human_readable
    assert '| 3 | test6 |' in human_readable
    test_req = req if MOCK_CLIENT.api_version == '3.x' else req_4
    assert json.loads(test_req.last_request.text) == {'id': label_id}
    intel_docs = outputs.get('Tanium.IntelDocLabel(val.IntelDocID && val.IntelDocID === obj.IntelDocID)', {})
    assert intel_docs.get('IntelDocID') == 423
    labels = intel_docs.get('LabelsList')
    assert len(labels) == 6
    assert labels[1].get('Name') == 'test2'
    assert labels[3].get('ID') == 9


def test_remove_intel_docs_label(requests_mock):
    """
    Given -
        A specific intel-doc ID.
        A specific label ID.

    When -
        Running remove_intel_docs_label function.

    Then -
        A list of label IDs of this specific intel-doc with the label ID removed.
    """

    intel_doc_id = 423
    label_id = 3
    api_expected_response = util_load_json('test_data/get_intel_docs_labels_list_raw_response.json')
    requests_mock.post(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.delete(BASE_URL + f'/plugin/products/detect3/api/v1/intels/{intel_doc_id}/labels/{label_id}',
                         json=api_expected_response)

    requests_mock.delete(BASE_URL + f'/plugin/products/threat-response/api/v1/intels/{intel_doc_id}/labels/{label_id}',
                         json={'data': api_expected_response})

    human_readable, outputs, raw_response = TaniumThreatResponseV2.remove_intel_docs_label(MOCK_CLIENT, {
        'intel_doc_id': intel_doc_id,
        'label_id': label_id})
    assert 'Successfully removed the label (3)' in human_readable
    intel_docs = outputs.get('Tanium.IntelDocLabel(val.IntelDocID && val.IntelDocID === obj.IntelDocID)', {})
    labels = intel_docs.get('LabelsList')
    for item in labels:
        assert item.get('ID') != 3


def test_create_intel_doc(mocker, requests_mock):
    """
    Given -
        An ioc file content.

    When -
        Running create_intel_doc function.

    Then -
        A new intel-doc should be created with that specific file content.
    """

    with open('test_data/test.ioc') as f:
        file_content = f.read()
    entry_id = 'Test'
    file_extension = 'ioc'
    api_expected_response = util_load_json('test_data/create_intel_docs_raw_response.json')
    mocker.patch('TaniumThreatResponseV2.get_file_data',
                 return_value=("test_name", "test_data/test.ioc", file_content))
    requests_mock.post(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.post(BASE_URL + '/plugin/products/detect3/api/v1/intels', json=api_expected_response)
    requests_mock.post(BASE_URL + '/plugin/products/threat-response/api/v1/intels',
                       json={'data': api_expected_response})

    human_readable, outputs, raw_response = TaniumThreatResponseV2.create_intel_doc(MOCK_CLIENT, {
        'entry_id': entry_id,
        'file_extension': file_extension})
    assert 'Intel Doc information' in human_readable
    assert outputs.get('Tanium.IntelDoc(val.ID && val.ID === obj.ID)', {}).get('Name') == 'VIRUS TEST'


def test_update_intel_doc_ioc(mocker, requests_mock):
    intel_doc_id = 423
    with open('test_data/test.ioc') as f:
        file_content = f.read()
    entry_id = 'Test'
    file_extension = 'ioc'
    api_update_expected_response = util_load_json('test_data/update_intel_docs_raw_response.json')
    api_get_expected_response = util_load_json('test_data/get_intel_doc_raw_response.json')
    mocker.patch('TaniumThreatResponseV2.get_file_data',
                 return_value=("test_name", 'test_data/test.ioc', file_content))
    requests_mock.post(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.get(BASE_URL + '/plugin/products/detect3/api/v1/intels/423', json=api_get_expected_response)
    requests_mock.get(BASE_URL + '/plugin/products/threat-response/api/v1/intels/423',
                      json={'data': api_get_expected_response})
    requests_mock.put(BASE_URL + f'/plugin/products/detect3/api/v1/intels/{str(intel_doc_id)}',
                      json=api_update_expected_response,
                      request_headers={'Content-Disposition': 'attachment; filename=file.ioc',
                                       'Content-Type': 'application/xml'})
    requests_mock.put(BASE_URL + f'/plugin/products/threat-response/api/v1/intels/{str(intel_doc_id)}',
                      json={'data': api_update_expected_response},
                      request_headers={'Content-Disposition': 'attachment; filename=file.ioc',
                                       'Content-Type': 'application/xml'})

    human_readable, outputs, raw_response = TaniumThreatResponseV2.update_intel_doc(MOCK_CLIENT, {
        'intel_doc_id': intel_doc_id,
        'entry_id': entry_id,
        'file_extension': file_extension})
    assert outputs.get('Tanium.IntelDoc(val.ID && val.ID === obj.ID)', {}).get('IntrinsicId') == 'test123456'
    assert outputs.get('Tanium.IntelDoc(val.ID && val.ID === obj.ID)', {}).get('RevisionId') == 2


def test_update_intel_doc_yara(mocker, requests_mock):
    intel_doc_id = 423
    with open('test_data/test.yara') as f:
        file_content = f.read()
    entry_id = 'Test'
    file_extension = 'yara'
    api_update_expected_response = util_load_json('test_data/update_intel_docs_raw_response.json')
    api_get_expected_response = util_load_json('test_data/get_intel_doc_raw_response.json')
    mocker.patch('TaniumThreatResponseV2.get_file_data',
                 return_value=("test_name", 'test_data/test.yara', file_content))
    requests_mock.post(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.get(BASE_URL + '/plugin/products/detect3/api/v1/intels/423', json=api_get_expected_response)
    requests_mock.get(BASE_URL + '/plugin/products/threat-response/api/v1/intels/423',
                      json={'data': api_get_expected_response})
    requests_mock.put(BASE_URL + f'/plugin/products/detect3/api/v1/intels/{str(intel_doc_id)}',
                      request_headers={'Content-Disposition': 'filename=test123456',
                                       'Content-Type': 'application/xml'}, json=api_update_expected_response)
    requests_mock.put(BASE_URL + f'/plugin/products/threat-response/api/v1/intels/{str(intel_doc_id)}',
                      request_headers={'Content-Disposition': 'attachment; filename=test123456',
                                       'Content-Type': 'application/xml'}, json={'data': api_update_expected_response})

    human_readable, outputs, raw_response = TaniumThreatResponseV2.update_intel_doc(MOCK_CLIENT, {
        'intel_doc_id': intel_doc_id,
        'entry_id': entry_id,
        'file_extension': file_extension})
    assert outputs.get('Tanium.IntelDoc(val.ID && val.ID === obj.ID)', {}).get('IntrinsicId') == 'test123456'
    assert outputs.get('Tanium.IntelDoc(val.ID && val.ID === obj.ID)', {}).get('RevisionId') == 2


def test_delete_intel_doc(mocker, requests_mock):
    """
    Given -
        A specific intel-doc ID.

    When -
        Running delete_intel_doc function.

    Then -
        Specified intel-doc is deleted.
    """

    requests_mock.post(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.delete(BASE_URL + '/plugin/products/detect3/api/v1/intels/?id=431', json={})
    requests_mock.delete(BASE_URL + '/plugin/products/threat-response/api/v1/intels/?id=431', json={})

    human_readable, outputs, raw_response = TaniumThreatResponseV2.delete_intel_doc(MOCK_CLIENT, {'intel_doc_id': 431})
    assert 'Intel doc deleted' in human_readable
    assert isinstance(raw_response, str)


def test_start_quick_scan(mocker, requests_mock):
    """
    Given -
        A specific intel-doc ID.
        A Tanium Computer Group Name

    When -
        Running start_quick_scan function.

    Then -
        A quick scan is started.
    """

    api_get_expected_response = util_load_json('test_data/get_computer_group_name_raw_response.json')
    api_post_expected_response = util_load_json('test_data/start_quick_scan_raw_response.json')
    requests_mock.post(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.get(BASE_URL + '/api/v2/groups/by-name/All%20Computers', json=api_get_expected_response)
    requests_mock.post(BASE_URL + '/plugin/products/detect3/api/v1/quick-scans/', json=api_post_expected_response)
    requests_mock.post(BASE_URL + '/plugin/products/threat-response/api/v1/on-demand-scans/',
                       json={'data': api_post_expected_response})

    human_readable, outputs, raw_response = TaniumThreatResponseV2.start_quick_scan(MOCK_CLIENT, {
        'intel_doc_id': 431, 'computer_group_name': 'All Computers'})
    assert 'Quick Scan started' in human_readable
    assert outputs.get('Tanium.QuickScan(val.ID && val.ID === obj.ID)', {}).get('IntelDocId') == 431
    assert outputs.get('Tanium.QuickScan(val.ID && val.ID === obj.ID)', {}).get('ComputerGroupId') == 1
    assert outputs.get('Tanium.QuickScan(val.ID && val.ID === obj.ID)', {}).get('ID') == 1000239
    assert outputs.get('Tanium.QuickScan(val.ID && val.ID === obj.ID)', {}).get('AlertCount') == 0
    assert outputs.get('Tanium.QuickScan(val.ID && val.ID === obj.ID)', {}).get(
        'CreatedAt') == "2022-01-05T19:53:43.049Z"
    assert outputs.get('Tanium.QuickScan(val.ID && val.ID === obj.ID)', {}).get('UserId') == 64
    assert outputs.get('Tanium.QuickScan(val.ID && val.ID === obj.ID)', {}).get('QuestionId') == 2025697


def test_deploy_intel(requests_mock):
    """
    Given -
        We want to deploy the intels.

    When -
        Running deploy_intel function.

    Then -
        The deploy process should begin.
    """

    api_raw_response = {
        'data': {
            'taskId': 750
        }
    }
    requests_mock.post(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.post(BASE_URL + '/plugin/products/threat-response/api/v1/intel/deploy',
                       json=api_raw_response)

    human_readable, outputs, raw_response = TaniumThreatResponseV2.deploy_intel(MOCK_CLIENT, {})
    assert human_readable == 'Successfully deployed intel.'
    assert api_raw_response == raw_response


def test_get_deploy_status(requests_mock):
    """
    Given -
        We want to get the last deploy status.

    When -
        Running get_deploy_status function.

    Then -
        The deploy status details should be returned.
    """

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
    requests_mock.post(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.get(BASE_URL + '/plugin/products/threat-response/api/v1/intel/status',
                      json=api_raw_response)

    human_readable, outputs, raw_response = TaniumThreatResponseV2.get_deploy_status(MOCK_CLIENT, {})
    assert 'Intel deploy status' in human_readable
    assert outputs.get('Tanium.IntelDeployStatus', {}).get('CurrentRevision') == 10


def test_get_alerts(requests_mock):
    """
    Given -
        We want to get alerts list.

    When -
        Running get_alerts function.

    Then -
        The alerts list should be returned.
    """

    api_raw_response = util_load_json('test_data/get_alerts_raw_response.json')
    requests_mock.post(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.get(BASE_URL + '/plugin/products/detect3/api/v1/alerts/',
                      json=api_raw_response)
    requests_mock.get(BASE_URL + '/plugin/products/threat-response/api/v1/alerts/',
                      json={'data': api_raw_response})

    human_readable, outputs, raw_response = TaniumThreatResponseV2.get_alerts(MOCK_CLIENT, {})
    assert 'Alerts' in human_readable
    assert len(outputs.get('Tanium.Alert(val.ID && val.ID === obj.ID)', [])) == 2


def test_get_alert(requests_mock):
    """
    Given -
        We want to get alerts by id.

    When -
        Running get_alert function.

    Then -
        The alert should be returned.
    """

    api_raw_response = util_load_json('test_data/get_alert_raw_response.json')
    requests_mock.post(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.get(BASE_URL + '/plugin/products/detect3/api/v1/alerts/1',
                      json=api_raw_response)
    requests_mock.get(BASE_URL + '/plugin/products/threat-response/api/v1/alerts/1',
                      json={'data': api_raw_response})

    human_readable, outputs, raw_response = TaniumThreatResponseV2.get_alert(MOCK_CLIENT, {'alert_id': 1})
    assert 'Alert information' in human_readable
    assert outputs.get('Tanium.Alert(val.ID && val.ID === obj.ID)', {}).get('ID') == 1


def test_alert_update_state(requests_mock):
    """
    Given -
        We want to update alert status.

    When -
        Running get_alert function.

    Then -
        The alert should be returned.
    """
    requests_mock.post(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.put(BASE_URL + '/plugin/products/detect3/api/v1/alerts/', json={})
    requests_mock.put(BASE_URL + '/plugin/products/threat-response/api/v1/alerts/', json={})

    args = {'alert_ids': '1,2,test',
            'state': 'unresolved'}
    human_readable, outputs, _ = TaniumThreatResponseV2.alert_update_state(MOCK_CLIENT, args)
    assert 'Alert state updated to unresolved' in human_readable
    assert outputs == {}


def test_create_snapshot(requests_mock):
    """
    Given - connection to snapshot.


    When -
        Running create_snapshot function.

    Then -
        The Task_id should be returned.
    """

    api_raw_response = util_load_json('test_data/create_snapshot.json')
    requests_mock.post(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.post(BASE_URL + '/plugin/products/threat-response/api/v1/conns/remote:host:123:/snapshot',
                       json=api_raw_response)

    args = {'connection_id': 'remote:host:123:'}
    human_readable, outputs, _ = TaniumThreatResponseV2.create_snapshot(MOCK_CLIENT, args)
    assert 'Initiated snapshot creation request for' in human_readable
    assert 'Task id: 1' in human_readable
    assert outputs.get('Tanium.SnapshotTask(val.taskId === obj.taskId && val.connection === obj.connection)',
                       {}).get('taskId') == 1
    assert outputs.get('Tanium.SnapshotTask(val.taskId === obj.taskId && val.connection === obj.connection)',
                       {}).get('connection') == 'remote:host:123:'


def test_delete_snapshot(requests_mock):
    """
    Given - snapshot ids to delete

    When -
        Running delete_snapshot function.

    Then -
        The human_readable should be returned.
    """

    requests_mock.post(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.delete(BASE_URL + '/plugin/products/threat-response/api/v1/snapshot',
                         json={})

    args = {'snapshot_ids': '1,2,3'}
    human_readable, outputs, _ = TaniumThreatResponseV2.delete_snapshot(MOCK_CLIENT, args)
    assert 'deleted successfully.' in human_readable
    assert outputs == {}


def test_list_snapshots(requests_mock):
    """
    Given - list_snapshots command, with limit 2.

    When -
        Running list_snapshots function.

    Then -
        The 2 snapshots should be returned.
    """

    api_raw_response = util_load_json('test_data/list_snapshots.json')
    requests_mock.post(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.get(BASE_URL + '/plugin/products/threat-response/api/v1/snapshot',
                      json=api_raw_response)

    args = {'limit': 2, 'offset': 0}
    human_readable, outputs, _ = TaniumThreatResponseV2.list_snapshots(MOCK_CLIENT, args)
    assert 'Snapshots:' in human_readable
    assert outputs.get('Tanium.Snapshot(val.uuid === obj.uuid)', [{}])[0].get('uuid') == '1234567890'


def test_delete_local_snapshot(requests_mock):
    """
    Given - connection id to delete its local snapshot

    When -
        Running delete_local_snapshot function.

    Then -
        The human_readable should be returned.
    """

    requests_mock.post(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.delete(BASE_URL + '/plugin/products/threat-response/api/v1/conns/remote:host:123:',
                         json={})

    args = {'connection_id': 'remote:host:123:'}
    human_readable, outputs, _ = TaniumThreatResponseV2.delete_local_snapshot(MOCK_CLIENT, args)
    assert ' was deleted successfully.' in human_readable
    assert outputs == {}


def test_get_connections(requests_mock):
    """
    Given - get_connections command and limit=2.

    When -
        Running get_connections function.

    Then -
        2 connections should be returned.
    """

    api_raw_response = util_load_json('test_data/get_connections.json')
    requests_mock.post(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.get(BASE_URL + '/plugin/products/threat-response/api/v1/conns',
                      json=api_raw_response)

    args = {'limit': '2', 'offset': '0'}
    human_readable, outputs, _ = TaniumThreatResponseV2.get_connections(MOCK_CLIENT, args)
    assert 'Connections' in human_readable
    assert outputs.get('Tanium.Connection(val.id === obj.id)', [{}])[0].get('hostname') == 'hostname'
    assert len(outputs.get('Tanium.Connection(val.id === obj.id)')) == 2


@pytest.mark.parametrize(
    'command_args, expected_output_len', FILTER_CONNECTIONS_LIST_ARGS
)
def test_filter_get_connections(
        requests_mock, command_args, expected_output_len
):
    """
    Given -
        offset, limit, hostname/platform/status/ip as filter parameters to 'get_connections' function

    When -
        Running 'get_connections' function

    Then -
        'get_connections' function will filter and return response output length the same as expected_output_len
    """
    api_raw_response = util_load_json('test_data/filter_get_connections.json')
    requests_mock.get(
        BASE_URL + '/api/v2/session/login',
        json={'data': {'session': 'session-id'}},
    )
    requests_mock.get(
        BASE_URL + '/plugin/products/threat-response/api/v1/conns',
        json=api_raw_response,
    )

    _, outputs, _ = TaniumThreatResponseV2.get_connections(
        client=MOCK_CLIENT, command_args=command_args
    )
    response = outputs.get('Tanium.Connection(val.id === obj.id)', {})
    full_response_len = len(response)
    assert full_response_len == expected_output_len, f'Actual: {full_response_len}, Expected: {expected_output_len}'


def test_create_connection(requests_mock):
    """
    Given - ip, client_id, hostname to create new connection.

    When -
        Running create_connection function.

    Then -
        The connection_id should be returned.
    """

    requests_mock.post(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.post(BASE_URL + '/plugin/products/threat-response/api/v1/conns/connect',
                       content=b'remote:hostname:123:')

    args = {'ip': '1.1.1.1',
            'client_id': '123',
            'hostname': 'hostname'}
    human_readable, outputs, _ = TaniumThreatResponseV2.create_connection(MOCK_CLIENT, args)
    assert 'Initiated connection request to ' in human_readable
    assert outputs.get('Tanium.Connection(val.id === obj.id)', {}).get('id') == 'remote:hostname:123:'


def test_delete_connection(requests_mock):
    """
    Given - connection_id to delete

    When -
        Running delete_connection function.

    Then -
        The connection should be deleted without errors.
    """

    requests_mock.post(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.delete(BASE_URL + '/plugin/products/threat-response/api/v1/conns/delete/remote:host:123:', json={})

    args = {'connection_id': 'remote:host:123:'}
    human_readable, outputs, _ = TaniumThreatResponseV2.delete_connection(MOCK_CLIENT, args)
    assert 'Connection `remote:host:123:` deleted successfully.' in human_readable
    assert outputs == {}


def test_close_connection(requests_mock):
    """
    Given - connection_id to close

    When -
        Running close_connection function.

    Then -
        The connection should be closed without errors.
    """

    requests_mock.post(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.delete(BASE_URL + '/plugin/products/threat-response/api/v1/conns/close/remote:host:123:', json={})

    args = {'connection_id': 'remote:host:123:'}
    human_readable, outputs, _ = TaniumThreatResponseV2.close_connection(MOCK_CLIENT, args)
    assert 'Connection `remote:host:123:` closed successfully.' in human_readable
    assert outputs == {}


def test_get_events_by_connection(requests_mock):
    """
    Given -connection_id and type of events to return in this connection.

    When -
        Running get_events_by_connection function.

    Then -
        The list of events in connection should be returned.
    """

    api_raw_response = util_load_json('test_data/get_events_by_connection.json')
    requests_mock.post(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.get(
        BASE_URL + '/plugin/products/threat-response/api/v1/conns/remote:hostname:123:/views/process/events',
        json=api_raw_response)

    args = {'limit': '2',
            'offset': '0',
            'connection_id': 'remote:hostname:123:',
            'type': 'process'}
    human_readable, outputs, _ = TaniumThreatResponseV2.get_events_by_connection(MOCK_CLIENT, args)
    assert 'Events for remote:hostname:123:' in human_readable
    assert outputs.get('TaniumEvent(val.id === obj.id)', [{}])[0].get('pid') == 1


def test_get_labels(requests_mock):
    """
    Given - limit 2 labels.

    When -
        Running get_labels function.

    Then -
        two labels should be returned.
    """

    api_raw_response = util_load_json('test_data/get_labels.json')
    requests_mock.post(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.get(BASE_URL + '/plugin/products/detect3/api/v1/labels/',
                      json=api_raw_response)
    requests_mock.get(BASE_URL + '/plugin/products/threat-response/api/v1/labels/',
                      json={'data': api_raw_response})

    args = {'limit': '2', 'offset': '0'}
    human_readable, outputs, _ = TaniumThreatResponseV2.get_labels(MOCK_CLIENT, args)
    assert 'Labels' in human_readable
    assert outputs.get('Tanium.Label(val.id === obj.id)', [{}])[0].get('id') == 1
    assert len(outputs.get('Tanium.Label(val.id === obj.id)')) == 2


def test_get_label(requests_mock):
    """
    Given - label id to get.

    When -
        Running get_label function.

    Then -
        The label info should be returned.
    """

    api_raw_response = util_load_json('test_data/get_label.json')
    requests_mock.post(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.get(BASE_URL + '/plugin/products/detect3/api/v1/labels/1',
                      json=api_raw_response)
    requests_mock.get(BASE_URL + '/plugin/products/threat-response/api/v1/labels/1',
                      json={'data': api_raw_response})

    args = {'label_id': 1}
    human_readable, outputs, _ = TaniumThreatResponseV2.get_label(MOCK_CLIENT, args)
    assert 'Label information' in human_readable
    assert outputs.get('Tanium.Label(val.id && val.id === obj.id)', {}).get('id') == 1


def test_get_events_by_process(requests_mock):
    """
    Given - connection id, process id anf type of events to get.

    When -
        Running get_events_by_process function.

    Then -
        Two pocess events related to connection id and ptid 1 should be returned.
    """

    api_raw_response = util_load_json('test_data/get_events_by_process.json')
    requests_mock.post(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.get(
        BASE_URL + '/plugin/products/threat-response/api/v1/conns/remote:host:123:/processevents/1/process?limit=2&offset=0',
        json=api_raw_response)

    args = {'connection_id': 'remote:host:123:',
            'limit': '2',
            'offset': '0',
            'ptid': '1',
            'type': 'Process'}
    human_readable, outputs, _ = TaniumThreatResponseV2.get_events_by_process(MOCK_CLIENT, args)
    assert 'Events for process 1' in human_readable
    assert outputs.get('Tanium.ProcessEvent(val.id && val.id === obj.id)', [{}])[0].get('id') == '1'


def test_get_process_info(requests_mock):
    """
    Given - connection id and ptid to get its info.

    When -
        Running get_process_info function.

    Then -
        The process info should be returned.
    """

    api_raw_response = util_load_json('test_data/get_process_info.json')
    requests_mock.post(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.get(BASE_URL + '/plugin/products/threat-response/api/v1/conns/remote:host:123:/processtrees/1',
                      json=api_raw_response)

    args = {'connection_id': 'remote:host:123:',
            'ptid': '1'}
    human_readable, outputs, _ = TaniumThreatResponseV2.get_process_info(MOCK_CLIENT, args)
    assert 'Process information for process with PTID 1' in human_readable
    assert outputs.get('Tanium.ProcessInfo(val.id === obj.id)', [{}])[0].get('id') == "1"


def test_get_process_children(requests_mock):
    """
    Given - connection id and ptid to get its children.

    When -
        Running get_process_children function.

    Then -
        The process children should be returned.
    """

    api_raw_response = util_load_json('test_data/get_process_children.json')
    requests_mock.post(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.get(BASE_URL + '/plugin/products/threat-response/api/v1/conns/remote:host:123:/processtrees/1',
                      json=api_raw_response)

    args = {'connection_id': 'remote:host:123:',
            'ptid': '1'}
    human_readable, outputs, _ = TaniumThreatResponseV2.get_process_children(MOCK_CLIENT, args)
    assert 'Children for process with PTID 1' in human_readable
    assert outputs.get('Tanium.ProcessChildren(val.id === obj.id)', [{}])[0].get('id') == "2"


def test_get_parent_process(requests_mock):
    """
    Given - connection id and ptid to get its parent.

    When -
        Running get_parent_process function.

    Then -
        The process parent should be returned.
    """

    api_raw_response = util_load_json('test_data/get_parent_process.json')
    requests_mock.post(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.get(BASE_URL + '/plugin/products/threat-response/api/v1/conns/remote:host:123:/processtrees/2',
                      json=api_raw_response)

    args = {'connection_id': 'remote:host:123:',
            'ptid': '2'}
    human_readable, outputs, _ = TaniumThreatResponseV2.get_parent_process(MOCK_CLIENT, args)
    assert 'Parent process for process with PTID 2' in human_readable
    assert outputs.get('Tanium.ProcessParent(val.id === obj.id)', [{}])[0].get('id') == "1"


def test_get_process_tree(requests_mock):
    """
    Given - connection id and ptid to get its process tree.

    When -
        Running get_process_tree function.

    Then -
        The process tree should be returned.
    """

    api_raw_response = util_load_json('test_data/get_process_tree.json')
    requests_mock.post(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.get(BASE_URL + '/plugin/products/threat-response/api/v1/conns/remote:host:123:/processtrees/2',
                      json=api_raw_response)

    args = {'connection_id': 'remote:host:123:',
            'ptid': '2'}
    human_readable, outputs, _ = TaniumThreatResponseV2.get_process_tree(MOCK_CLIENT, args)
    assert 'Process information for process with PTID 2' in human_readable
    assert outputs.get('Tanium.ProcessTree(val.id && val.id === obj.id)', [{}])[0].get('id') == "1"


def test_list_evidence(requests_mock):
    """
    Given - limit and offset for evidenced to get

    When -
        Running list_evidence function.

    Then -
        Two evidences should be returned.
    """

    api_raw_response = util_load_json('test_data/list_evidence.json')
    requests_mock.post(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.get(BASE_URL + '/plugin/products/threat-response/api/v1/evidence',
                      json=api_raw_response)

    args = {'limit': '2',
            'offset': '0'}
    human_readable, outputs, _ = TaniumThreatResponseV2.list_evidence(MOCK_CLIENT, args)
    assert 'Evidence list' in human_readable
    assert outputs.get('Tanium.Evidence(val.uuid && val.uuid === obj.uuid)', [{}])[0].get('uuid') == '123abc'
    assert len(outputs.get('Tanium.Evidence(val.uuid && val.uuid === obj.uuid)')) == 2


@pytest.mark.parametrize(
    'command_args, expected_output_len', FILTER_EVIDENCE_LIST_ARGS
)
def test_filter_list_evidence(requests_mock, command_args, expected_output_len):
    """
    Given -
        offset, limit, hash/hostname as filter arguments for 'get_file_downloads_function'

    When -
        Running 'get_file_downloads' function

    Then -
        'get_file_downloads' function will filter and return response in the same length as expected_output_len.
    """
    api_raw_response = util_load_json('test_data/filter_list_evidence.json')
    requests_mock.post(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.get(BASE_URL + '/plugin/products/threat-response/api/v1/evidence',
                      json=api_raw_response)

    _, outputs, _ = TaniumThreatResponseV2.list_evidence(MOCK_CLIENT, command_args)
    response = outputs.get('Tanium.Evidence(val.uuid && val.uuid === obj.uuid)', {})
    assert (len(
        response) == expected_output_len), f'Actual length: {len(response)}, Expected length: {expected_output_len}'


def test_event_evidence_get_properties(requests_mock):
    """
    Given - event_evidence_get_properties command.

    When -
        Running event_evidence_get_properties function.

    Then -
        The properties list should be returned should be returned.
    """

    api_raw_response = util_load_json('test_data/event_evidence_get_properties.json')
    requests_mock.post(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.get(BASE_URL + '/plugin/products/threat-response/api/v1/event-evidence/properties',
                      json=api_raw_response)

    args = {}
    human_readable, outputs, _ = TaniumThreatResponseV2.event_evidence_get_properties(MOCK_CLIENT, args)
    assert 'Evidence Properties' in human_readable
    assert outputs.get('Tanium.EvidenceProperties(val.value === obj.value)', [{}])[0].get('type') == 'ProcessId'


def test_get_evidence_by_id(requests_mock):
    """
    Given - evidence id to get its info.

    When -
        Running get_evidence_by_id function.

    Then -
        The evidence with given id should be returned.
    """

    api_raw_response = util_load_json('test_data/get_evidence_by_id.json')
    requests_mock.post(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.get(BASE_URL + '/plugin/products/threat-response/api/v1/event-evidence/1',
                      json=api_raw_response)

    args = {'evidence_id': '1'}
    human_readable, outputs, _ = TaniumThreatResponseV2.get_evidence_by_id(MOCK_CLIENT, args)
    assert 'Evidence information' in human_readable
    assert outputs.get('Tanium.Evidence(val.uuid && val.uuid === obj.uuid)', {}).get('uuid') == '1'


def test_create_evidence(requests_mock):
    """
    Given - hostname, connection_id and ptid to create event evidence with this data.

    When -
        Running create_evidence function.

    Then -
        Human readable should be returned.
    """
    api_raw_response = util_load_json('test_data/create_evidence.json')
    requests_mock.post(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.get(BASE_URL + '/plugin/products/threat-response/api/v1/conns/remote:host:123:/views/process/events',
                      json=api_raw_response)
    requests_mock.post(BASE_URL + '/plugin/products/threat-response/api/v1/event-evidence',
                       json={})

    args = {'connection_id': 'remote:host:123:',
            'hostname': 'host',
            'ptid': '1'}
    human_readable, _, _ = TaniumThreatResponseV2.create_evidence(MOCK_CLIENT, args)
    assert 'Evidence have been created.' in human_readable


def test_delete_evidence(requests_mock):
    """
    Given - evidence_ids to delete

    When -
        Running delete_evidence? function.

    Then -
        The evidence ids should be deleted.
    """

    requests_mock.post(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.delete(BASE_URL + '/plugin/products/threat-response/api/v1/event-evidence',
                         json={})

    args = {'evidence_ids': '1,2,3'}
    human_readable, _, _ = TaniumThreatResponseV2.delete_evidence(MOCK_CLIENT, args)
    assert 'Evidence 1,2,3 has been deleted successfully.' in human_readable


def test_get_file_downloads(requests_mock):
    """
    Given - get_file_downloads command

    When -
        Running get_file_downloads function.

    Then -
        The file dowloads list should be returned.
    """

    api_raw_response = util_load_json('test_data/get_file_downloads.json')
    requests_mock.post(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.get(BASE_URL + '/plugin/products/threat-response/api/v1/filedownload',
                      json=api_raw_response)

    args = {'limit': '2'}
    human_readable, outputs, _ = TaniumThreatResponseV2.get_file_downloads(MOCK_CLIENT, args)
    assert 'File downloads' in human_readable
    assert outputs.get('Tanium.FileDownload(val.uuid === obj.uuid)', [{}])[0].get('uuid') == '1'
    assert outputs.get('Tanium.FileDownload(val.uuid === obj.uuid)', [{}])[0].get('evidenceType') == 'file'


@pytest.mark.parametrize(
    'command_args, expected_output_len', FILTER_FILE_DOWNLOADS_ARGS
)
def test_filter_get_file_downloads(requests_mock, command_args, expected_output_len):
    """
    Given -
        offset, limit, hash/hostname as filter arguments for 'get_file_downloads_function'

    When -
        Running 'get_file_downloads' function

    Then -
        'get_file_downloads' function will filter and return response in the same length as expected_output_len.
    """
    api_raw_response = util_load_json('test_data/filter_get_file_downloads.json')
    requests_mock.post(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.get(BASE_URL + '/plugin/products/threat-response/api/v1/filedownload',
                      json=api_raw_response)

    _, outputs, _ = TaniumThreatResponseV2.get_file_downloads(MOCK_CLIENT, command_args)
    response = outputs.get('Tanium.FileDownload(val.uuid === obj.uuid)', {})
    assert len(response) == expected_output_len, f"Expected length: {expected_output_len}, actual: {len(response)}"


def test_get_file_download_info(requests_mock):
    """
    Given - file id to get its info

    When -
        Running get_file_download_info function.

    Then -
        The file download info should be returned.
    """

    api_raw_response = util_load_json('test_data/get_file_download_info.json')
    requests_mock.post(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.get(BASE_URL + '/plugin/products/threat-response/api/v1/filedownload/1',
                      json=api_raw_response)

    args = {'file_id': '1'}
    human_readable, outputs, _ = TaniumThreatResponseV2.get_file_download_info(MOCK_CLIENT, args)
    assert 'File download' in human_readable
    assert outputs.get('Tanium.FileDownload(val.uuid === obj.uuid)', {}).get('uuid') == '1'


def test_request_file_download(requests_mock):
    """
    Given - path, connection id to request file download from there.

    When -
        Running request_file_download function.

    Then -
        The Task info should be returned.
    """

    api_raw_response = util_load_json('test_data/request_file_download.json')
    requests_mock.post(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.post(BASE_URL + '/plugin/products/threat-response/api/v1/conns/remote:host:123:/file',
                       json=api_raw_response)

    args = {'connection_id': 'remote:host:123:', 'path': 'C:\\file.txt'}
    human_readable, outputs, _ = TaniumThreatResponseV2.request_file_download(MOCK_CLIENT, args)
    assert 'Task id: 1' in human_readable
    assert outputs.get('Tanium.FileDownloadTask(val.taskId === obj.taskId && val.connection === obj.connection)',
                       {}).get('taskId') == 1
    assert outputs.get('Tanium.FileDownloadTask(val.taskId === obj.taskId && val.connection === obj.connection)',
                       {}).get('connection') == 'remote:host:123:'


def test_delete_file_download(requests_mock):
    """
    Given - file id to delete

    When -
        Running delete_file_download function.

    Then -
        The file download should be deleted.
    """

    requests_mock.post(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.delete(BASE_URL + '/plugin/products/threat-response/api/v1/filedownload/1',
                         json={})

    args = {'file_id': '1'}
    human_readable, outputs, _ = TaniumThreatResponseV2.delete_file_download(MOCK_CLIENT, args)
    assert 'Delete request of file with ID 1 has been sent successfully' in human_readable


def test_list_files_in_dir(requests_mock):
    """
    Given - path in connection to get its files.

    When -
        Running list_files_in_dir function.

    Then -
        The list of files in path should be returned.
    """

    api_raw_response = util_load_json('test_data/list_files_in_dir.json')
    requests_mock.post(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.get(
        BASE_URL + '/plugin/products/threat-response/api/v1/conns/remote:host:123:/file/list/C%3A%5CDir%5C',
        json=api_raw_response)

    args = {'connection_id': 'remote:host:123:',
            'path': 'C:\\Dir\\',
            'limit': '2', 'offset': '0'}
    human_readable, outputs, _ = TaniumThreatResponseV2.list_files_in_dir(MOCK_CLIENT, args)
    assert 'Files in directory' in human_readable
    assert outputs.get('Tanium.File(val.name === obj.name && val.connectionId === obj.connectionId)', [{}])[0].get(
        'name') == 'file1.exe'
    assert outputs.get('Tanium.File(val.name === obj.name && val.connectionId === obj.connectionId)', [{}])[0].get(
        'connectionId') == 'remote:host:123:'


def test_get_file_info(requests_mock):
    """
    Given -

    When -
        Running get_file_info function.

    Then -
        The file info should be returned.
    """

    api_raw_response = util_load_json('test_data/get_file_info.json')
    requests_mock.post(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.get(
        BASE_URL + '/plugin/products/threat-response/api/v1/conns/remote:host:123:/file/info/C%3A%5Cfile1.txt',
        json=api_raw_response)

    args = {'path': "C:\\file1.txt",
            'connection_id': "remote:host:123:"}
    human_readable, outputs, _ = TaniumThreatResponseV2.get_file_info(MOCK_CLIENT, args)
    assert 'Information for file' in human_readable
    assert outputs.get('Tanium.File(val.path === obj.path && val.connectionId === obj.connectionId)', {}).get(
        'connectionId') == 'remote:host:123:'
    assert outputs.get('Tanium.File(val.path === obj.path && val.connectionId === obj.connectionId)', {}).get(
        'path') == "C:\\file1.txt"


def test_delete_file_from_endpoint(requests_mock):
    """
    Given - connection id and path of file to delete.

    When -
        Running delete_file_from_endpoint function.

    Then -
        The file should be deleted.
    """

    requests_mock.post(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.delete(
        BASE_URL + '/plugin/products/threat-response/api/v1/conns/remote:host:123:/file/delete/C%3A%5Cfile1.txt',
        json={})

    args = {'path': "C:\\file1.txt",
            'connection_id': "remote:host:123:"}
    human_readable, outputs, _ = TaniumThreatResponseV2.delete_file_from_endpoint(MOCK_CLIENT, args)
    assert 'Delete request of file C:\\file1.txt' in human_readable


def test_get_task_by_id(requests_mock):
    """
    Given - task id to get its status and info

    When -
        Running get_task_by_id function.

    Then -
        The task info should be returned.
    """

    api_raw_response = util_load_json('test_data/get_task_by_id.json')
    requests_mock.post(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.get(BASE_URL + '/plugin/products/threat-response/api/v1/tasks/1',
                      json=api_raw_response)

    args = {'task_id': '1'}
    human_readable, outputs, _ = TaniumThreatResponseV2.get_task_by_id(MOCK_CLIENT, args)
    assert 'Task information' in human_readable
    assert outputs.get('Tanium.Task(val.id === obj.id)', {}).get('id') == 1


def test_get_system_status(requests_mock):
    """
    Given - tanium system

    When -
        Running get_system_status function.

    Then -
        The connected computers should be returned.
    """

    api_raw_response = util_load_json('test_data/get_system_status.json')
    requests_mock.post(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.get(BASE_URL + '/api/v2/system_status',
                      json=api_raw_response)

    args = {'limit': 2, 'offset': 0}
    human_readable, outputs, _ = TaniumThreatResponseV2.get_system_status(MOCK_CLIENT, args)
    assert 'Reporting clients' in human_readable
    assert outputs.get('Tanium.SystemStatus(val.clientId === obj.clientId)', {})[0].get('clientId') == 1


@pytest.mark.parametrize(
    'command_args, expected_output_len', FILTER_GET_SYSTEM_STATUS_ARGS
)
def test_filter_get_system_status(
        requests_mock, command_args, expected_output_len
):
    """
    Given -
        offset, limit, status/hostname/ip_server/ip_client/port as filter arguments for 'get_system_status' function

    When -
        Running 'get_system_status' function

    Then -
        'get_system_status' function will filter and return response in the same length as expected_output_len.
    """
    api_raw_response = util_load_json(
        'test_data/filter_get_system_status.json'
    )

    requests_mock.get(
        BASE_URL + '/api/v2/session/login',
        json={'data': {'session': 'session-id'}},
    )
    requests_mock.get(
        BASE_URL + '/api/v2/system_status', json=api_raw_response
    )

    _, outputs, _ = TaniumThreatResponseV2.get_system_status(
        MOCK_CLIENT, command_args
    )
    response = outputs.get(
        'Tanium.SystemStatus(val.clientId === obj.clientId)', {}
    )
    assert (len(
        response) == expected_output_len), f'Actual length: {len(response)}, Expected length: {expected_output_len}'


def test_fetch_all_incidents(requests_mock):
    """
        Given
            fetch incidents command running for the first time.
        When
            mock the Client's http_request.
        Then
            validate fetch incidents command using the Client gets all 2 relevant incidents
    """

    test_incidents = util_load_json('test_data/fetch_incidents.json')
    requests_mock.post(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.get(BASE_URL + '/plugin/products/detect3/api/v1/alerts?'
                                 '&state=unresolved&sort=-createdAt&limit=500&offset=0&labelName=some_label',
                      json=test_incidents)
    requests_mock.get(BASE_URL + '/plugin/products/threat-response/api/v1/alerts?'
                                 '&state=unresolved&sort=-createdAt&limit=500&offset=0&labelName=some_label',
                      json={'data': test_incidents})
    requests_mock.get(BASE_URL + '/plugin/products/detect3/api/v1/alerts?'
                                 '&state=unresolved&sort=-createdAt&limit=500&offset=500',
                      json=[])
    requests_mock.get(BASE_URL + '/plugin/products/threat-response/api/v1/alerts?'
                                 'state=unresolved&sort=-createdAt&limit=500&offset=500', json=[])
    requests_mock.get(BASE_URL + '/plugin/products/detect3/api/v1/intels/11', json={'name': 'test'})
    requests_mock.get(BASE_URL + '/plugin/products/threat-response/api/v1/intels/11', json={'data': {'name': 'test'}})
    requests_mock.get(BASE_URL + '/plugin/products/detect3/api/v1/intels/11/labels', json=[{'name': 'test'}])
    requests_mock.get(BASE_URL + '/plugin/products/threat-response/api/v1/intels/11/labels',
                      json={'data': [{'name': 'test'}]})

    alerts_states_to_retrieve = 'unresolved'
    last_run = {}
    fetch_time = '10 years'
    max_fetch = 2
    filter_label_name = 'some_label'

    incidents, next_run = TaniumThreatResponseV2.fetch_incidents(
        MOCK_CLIENT,
        alerts_states_to_retrieve,
        filter_label_name,
        last_run,
        fetch_time,
        max_fetch
    )

    assert len(incidents) == 2
    assert incidents[0].get(
        'name') == 'hostname found test'
    assert incidents[0].get(
        'occurred') == "2021-09-26T14:01:31.000Z"
    assert next_run.get('id') == "2"
    assert next_run.get('time') == datetime.strftime(parse("2021-09-26T14:02:59.000Z"),
                                                     TaniumThreatResponseV2.DATE_FORMAT)


def test_fetch_new_incidents(requests_mock):
    """
        Given
            fetch incidents command running for the first time.
        When
            mock the Client's http_request.
        Then
            validate fetch incidents command using the Client gets new 2 relevant incidents
    """

    test_incidents = util_load_json('test_data/fetch_incidents_new.json')
    requests_mock.post(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.get(BASE_URL + '/plugin/products/detect3/api/v1/alerts?'
                                 '&state=unresolved&sort=-createdAt&limit=500&offset=0',
                      json=test_incidents)
    requests_mock.get(BASE_URL + '/plugin/products/threat-response/api/v1/alerts?'
                                 'state=unresolved&sort=-createdAt&limit=500&offset=0',
                      json={'data': test_incidents})
    requests_mock.get(BASE_URL + '/plugin/products/detect3/api/v1/alerts?'
                                 '&state=unresolved&sort=-createdAt&limit=500&offset=500',
                      json=[])
    requests_mock.get(BASE_URL + '/plugin/products/threat-response/api/v1/alerts?'
                                 'state=unresolved&sort=-createdAt&limit=500&offset=500',
                      json=[])
    requests_mock.get(BASE_URL + '/plugin/products/detect3/api/v1/intels/11', json={'name': 'test'})
    requests_mock.get(BASE_URL + '/plugin/products/threat-response/api/v1/intels/11', json={'data': {'name': 'test'}})
    requests_mock.get(BASE_URL + '/plugin/products/detect3/api/v1/intels/11/labels', json=[{'name': 'test'}])
    requests_mock.get(BASE_URL + '/plugin/products/threat-response/api/v1/intels/11/labels',
                      json={'data': [{'name': 'test'}]})

    alerts_states_to_retrieve = 'unresolved'
    last_run = {'time': '2021-09-26T14:02:59.000000Z', 'id': '2'}
    fetch_time = '3 days'
    max_fetch = 2
    filter_label_name = ''

    incidents, next_run = TaniumThreatResponseV2.fetch_incidents(
        MOCK_CLIENT,
        alerts_states_to_retrieve,
        filter_label_name,
        last_run,
        fetch_time,
        max_fetch
    )

    assert len(incidents) == 2
    assert incidents[0].get(
        'name') == 'hostname found test'
    assert incidents[0].get(
        'occurred') == "2021-09-26T14:01:31.000Z"
    assert next_run.get('id') == "4"
    assert next_run.get('time') == datetime.strftime(parse("2021-09-26T14:04:59.000Z"),
                                                     TaniumThreatResponseV2.DATE_FORMAT)


def test_get_response_actions(requests_mock):
    """
    Given - Nothing

    When -
        Running get_response_actions function.

    Then -
        The response actions should be returned.
    """

    api_raw_response = {
        "data": [
            {
                "id": 10,
                "type": "downloadFile",
                "status": "COMPLETED",
                "computerName": "id1",
                "userId": 1,
                "userName": "test",
                "options": {
                    "filePath": "C:\\Program Files (x86)\\log1.txt"
                },
                "results": {
                    "taskIds": [
                        34
                    ],
                    "actionIds": [],
                    "fileName": "test.zip"
                },
                "expirationTime": "2021-11-17T14:05:12.003Z",
                "createdAt": "2021-11-10T14:06:19.571Z",
                "updatedAt": "2021-11-10T14:06:26.249Z"
            }]
    }
    requests_mock.post(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.get(BASE_URL + '/plugin/products/threat-response/api/v1/response-actions',
                      json=api_raw_response)

    args = {'limit': 2, 'offset': 0, 'partial_computer_name': '1', 'status': 'test'}
    human_readable, outputs, _ = TaniumThreatResponseV2.get_response_actions(MOCK_CLIENT, args)
    assert 'Response Actions' in human_readable
    assert outputs.get('Tanium.ResponseActions(val.id === obj.id)', {})['data'][0].get('id') == 10


def test_response_action_gather_snapshot(requests_mock):
    """
    Given - Nothing

    When -
        Running get_response_actions function.

    Then -
        The response actions should be returned.
    """

    api_raw_response = {
        "data": {
            "type": "gatherSnapshot",
            "computerName": "1",
            "options": {},
            "status": "QUEUED",
            "userId": 1,
            "userName": "administrator",
            "results": {},
            "expirationTime": "2023-05-18T16:56:16.502Z",
            "createdAt": "2023-05-11T16:56:16.503Z",
            "updatedAt": "2023-05-11T16:56:16.503Z",
            "id": 11
        }
    }
    requests_mock.post(BASE_URL + '/api/v2/session/login', json={'data': {'session': 'session-id'}})
    requests_mock.post(BASE_URL + '/plugin/products/threat-response/api/v1/response-actions',
                       json=api_raw_response)

    args = {'computer_name': 1}
    human_readable, outputs, _ = TaniumThreatResponseV2.response_action_gather_snapshot(MOCK_CLIENT, args)
    assert 'Response Actions' in human_readable
    assert outputs.get('Tanium.ResponseActions(val.id === obj.id)', {})['data'].get('id') == 11
    assert outputs.get('Tanium.ResponseActions(val.id === obj.id)', {})['data'].get('type') == 'gatherSnapshot'
