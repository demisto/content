import json
import pytest
from LogRhythmRestV2 import Client
import demistomock as demisto

BASE_URL = 'http://testurl.com/'
CLIENT = Client(BASE_URL, True, True, headers={}, auth=None)

ALARMS_LIST = {'alarmsSearchDetails': [{'alarmId': 2, 'alarmStatus': 1, 'dateInserted': '2021-08-23T15:19:00'},
               {'alarmId': 1, 'alarmStatus': 1, 'dateInserted': '2021-03-23T15:19:00'}]}

ALARMS_LIST_BY_ID = {'alarmDetails': {'alarmId': 1, 'alarmStatus': 1, 'dateInserted': '2021-08-23T15:19:00'}}

CASES_LIST = [{'id': '525569EF-CA80-4901-BA8A-95D80851BACA'}, {'id': '75081347-EB56-4AEA-A6F9-A6EB6662F48E'}]

HOSTS_LIST = [{'id': 1, 'name': 'host1'}, {'id': 2, 'name': 'host2'}, {'id': 3, 'name': 'host3'}]

CASE_EVIDENCES_LIST = [{'number': 1}, {'number': 2}]

ENTITIES_LIST = [{'id': 1}, {'id': 2}, {'id': 3}]

GENERATE_QUERY_TEST_DATA = [(23, 4, 'host1', {"filterType": 23, "valueType": 4, "value": {"value": "host1",
                                                                                          "matchType": 2}}),
                            (136, 2, '2', {"filterType": 136, "valueType": 2, "value": 2}),
                            (17, 5, '127.0.0.1', {"filterType": 17, "valueType": 5, "value": '127.0.0.1'})]

FILE_EVIDENCE_REQUEST_BODY = '-----------------------------\n' \
                             'Content-Disposition: form-data; name="file"; filename="test.txt"\n' \
                             'Content-Type: text/plain\n\n' \
                             'This is a test file.\n' \
                             '-----------------------------\n' \
                             'Content-Disposition: form-data; name="note"\n\n' \
                             '-------------------------------'

SEARCH_QUERY_REQUEST_DATA = {"maxMsgsToQuery": 60, "logCacheSize": 10000, "queryTimeout": 60, "queryRawLog": True,
                             "queryEventManager": False,
                             "dateCriteria": {"useInsertedDate": False, "lastIntervalValue": 4, "lastIntervalUnit": 4},
                             "queryLogSources": [],
                             "queryFilter":
                                 {"msgFilterType": 2, "isSavedFilter": False, "filterGroup":
                                     {"filterItemType": 1, "fieldOperator": 1, "filterMode": 1,
                                      "filterGroupOperator": 0, "filterItems": [{"filterItemType": 0,
                                                                                 "fieldOperator": 1, "filterMode": 1,
                                                                                 "values":
                                                                                     [{"filterType": 9, "valueType": 2,
                                                                                       "value": 1000633}]},
                                                                                {"filterItemType": 0,
                                                                                 "fieldOperator": 1, "filterMode": 1,
                                                                                 "values": [{"filterType": 23,
                                                                                             "valueType": 4, "value":
                                                                                                 {"value": "host1",
                                                                                                  "matchType": 2}}]},
                                                                                {"filterItemType": 0,
                                                                                 "fieldOperator": 1,
                                                                                 "filterMode": 1, "values":
                                                                                     [{"filterType": 17, "valueType": 5,
                                                                                       "value": "127.0.0.1"}]}]}}}


def test_alarms_list_request_filter_by_alarm_id(requests_mock):
    """
    Given:
    - List of alarms.

    When:
    - Running alarms_list_request with alarm_id filter.

    Then:
    - Validate that result contains only one alarm with the correct ID.
    """
    requests_mock.get(f'{BASE_URL}lr-alarm-api/alarms/1', json=ALARMS_LIST_BY_ID)
    res, _ = CLIENT.alarms_list_request(alarm_id='1')
    assert len(res) == 1
    assert res[0]['alarmId'] == 1


def test_alarms_list_request_filter_by_created_after(requests_mock):
    """
    Given:
    - List of alarms.

    When:
    - Running alarms_list_request with created_after filter.

    Then:
    - Validate that result filtered the alarms after 20.4.2021.
    """
    requests_mock.get(f'{BASE_URL}lr-alarm-api/alarms/', json=ALARMS_LIST)
    res, _ = CLIENT.alarms_list_request(created_after='2021-04-20')
    assert len(res) == 1
    assert res[0]['alarmId'] == 2
    assert res[0]['dateInserted'] == '2021-08-23T15:19:00'


def test_cases_list_request_filter_by_case_id(requests_mock):
    """
    Given:
    - List of cases.

    When:
    - Running cases_list_request with case_id filter.

    Then:
    - Validate that result contains only one case with the correct ID.
    """
    requests_mock.get(f'{BASE_URL}lr-case-api/cases', json=CASES_LIST)
    res = CLIENT.cases_list_request(case_id='75081347-EB56-4AEA-A6F9-A6EB6662F48E')
    assert res
    assert res['id'] == '75081347-EB56-4AEA-A6F9-A6EB6662F48E'


def test_case_evidence_list_request_filter_by_evidence_number(requests_mock):
    """
    Given:
    - List of evidences.

    When:
    - Running case_evidence_list_request with case_id filter.

    Then:
    - Validate that result contains only one evidence with the correct ID.
    """
    case_id = '75081347-EB56-4AEA-A6F9-A6EB6662F48E'
    requests_mock.get(f'{BASE_URL}lr-case-api/cases/{case_id}/evidence', json=CASE_EVIDENCES_LIST)
    res = CLIENT.case_evidence_list_request(case_id, '1', None, None)
    assert res
    assert res['number'] == 1


def test_case_file_evidence_add_request(requests_mock, mocker):
    """
    Given:
    - txt file as evidence.

    When:
    - Running case_file_evidence_add_request.

    Then:
    - Validate that file request body created as expected.
    """
    case_id = '75081347-EB56-4AEA-A6F9-A6EB6662F48E'
    requests_mock.post(f'{BASE_URL}lr-case-api/cases/{case_id}/evidence/file', json={})
    mocker.patch.object(demisto, 'getFilePath', return_value={
                        'path': 'test_data/test.txt',
                        'name': 'test.txt'})
    CLIENT.case_file_evidence_add_request(case_id, '23@32')
    assert requests_mock.last_request.text == FILE_EVIDENCE_REQUEST_BODY


def test_entities_list_request_filter_by_entity_id(requests_mock):
    """
    Given:
    - List of entities.

    When:
    - Running entities_list_request with entity_id filter.

    Then:
    - Validate that result contains only one entity with the correct ID.
    """
    requests_mock.get(f'{BASE_URL}lr-admin-api/entities', json=ENTITIES_LIST)
    res = CLIENT.entities_list_request('1', None, None, None)
    assert res
    assert res['id'] == 1


def test_hosts_list_request_filter_by_endpoint_id_list(requests_mock):
    """
    Given:
    - List of hosts.

    When:
    - Running hosts_list_request with endpoint_id_list filter.

    Then:
    - Validate that result contains 2 hosts with the correct IDs.
    """
    requests_mock.get(f'{BASE_URL}lr-admin-api/hosts', json=HOSTS_LIST)
    res = CLIENT.hosts_list_request(endpoint_id_list=['2', '3'])
    assert len(res) == 2
    assert res[0]['id'] == 2
    assert res[1]['id'] == 3


def test_hosts_list_request_filter_by_endpoint_hostname_list(requests_mock):
    """
    Given:
    - List of hosts.

    When:
    - Running hosts_list_request with endpoint_hostname_list filter.

    Then:
    - Validate that result contains 2 hosts with the correct host names.
    """
    requests_mock.get(f'{BASE_URL}lr-admin-api/hosts', json=HOSTS_LIST)
    res = CLIENT.hosts_list_request(endpoint_hostname_list=['host1', 'host2'])
    assert len(res) == 2
    assert res[0]['name'] == 'host1'
    assert res[1]['name'] == 'host2'


def test_execute_search_query_request(requests_mock):
    """
    Given:
    - Client object.

    When:
    - Running execute_search_query_request filter by number_of_days, source_type, host_name and ipaddress.

    Then:
    - Validate that search-task request body created as expected.
    """
    requests_mock.post(f'{BASE_URL}lr-search-api/actions/search-task', json={})
    CLIENT.execute_search_query_request('4', 'API_-_Box_Event', 'host1', None, None, None, None, None, None, None, None,
                                        '127.0.0.1', '60', '60', None)

    assert requests_mock.last_request.text == json.dumps(SEARCH_QUERY_REQUEST_DATA)


@pytest.mark.parametrize("filter_type,value_type,value,expected", GENERATE_QUERY_TEST_DATA)
def test_generate_query_item(filter_type, value_type, value, expected):
    """
    Given:
    - filter_type, value_type and value for generate query item.

    When:
    - Running generate_query_item.

    Then:
    - Validate that query item created as expected.
    """
    query_item = CLIENT.generate_query_item(filter_type, value_type, value)
    assert query_item['values'][0] == expected


def test_add_host_request(requests_mock):
    """
    Given:
    - Entity ID, entity name and hostname for creating a new host.

    When:
    - Running add_host_request.

    Then:
    - Validate that add host request body created as expected.
    """
    requests_mock.post(f'{BASE_URL}lr-admin-api/hosts', json={})
    CLIENT.add_host_request('1', 'entity', 'host1', None, None, None, None, None, None, None, None, None, None)
    assert requests_mock.last_request.text == '{"id": -1, "entity": {"name": "entity", "id": 1}, "name": "host1"}'


def test_alarm_update_request(requests_mock):
    """
    Given:
    - Alarm status and alarm ID to update.

    When:
    - Running alarm_update_request.

    Then:
    - Validate that update alarm request body created as expected.
    """
    requests_mock.patch(f'{BASE_URL}lr-alarm-api/alarms/1', json={})
    CLIENT.alarm_update_request(alarm_id='1', alarm_status='New', rbp='')
    assert requests_mock.last_request.text == '{"alarmStatus": "New"}'


def test_alarm_add_comment_request(requests_mock):
    """
    Given:
    - Alarm comment and alarm ID.

    When:
    - Running alarm_add_comment_request.

    Then:
    - Validate that add alarm comment request body created as expected.
    """
    requests_mock.post(f'{BASE_URL}lr-alarm-api/alarms/1/comment', json={})
    CLIENT.alarm_add_comment_request(alarm_id='1', alarm_comment='hi')
    assert requests_mock.last_request.text == '{"alarmComment": "hi"}'


def test_alarm_history_list_request(requests_mock):
    """
    Given:
    - Alarm ID, person ID, date updated, history type, offset and count to filter alarm history.

    When:
    - Running alarm_history_list_request.

    Then:
    - Validate that get alarm history request query created as expected.
    """
    requests_mock.get(f'{BASE_URL}lr-alarm-api/alarms/1/history', json={})
    CLIENT.alarm_history_list_request('1', '2', '2020-04-20', 'comment', '0', '0')
    assert requests_mock.last_request.query == 'personid=2&dateupdated=2020-04-20&type=comment&offset=0&count=0'


def test_case_create_request(requests_mock):
    """
    Given:
    - Case name, priority and external Id to create a case.

    When:
    - Running case_create_request.

    Then:
    - Validate that create case request body created as expected.
    """
    requests_mock.post(f'{BASE_URL}lr-case-api/cases', json={})
    CLIENT.case_create_request(name='case name', priority='5', external_id='9900', due_date='', summary='')
    assert requests_mock.last_request.text == '{"name": "case name", "priority": 5, "externalId": "9900"}'


def test_case_update_request(requests_mock):
    """
    Given:
    - Priority, case summary and case ID to update.

    When:
    - Running case_update_request.

    Then:
    - Validate that case update request body created as expected.
    """
    requests_mock.put(f'{BASE_URL}lr-case-api/cases/1', json={})
    CLIENT.case_update_request('1', '', '5', '', '', 'summary', '', '')
    assert requests_mock.last_request.text == '{"summary": "summary", "priority": 5}'


def test_case_status_change_request(requests_mock):
    """
    Given:
    - Case status and case ID to update.

    When:
    - Running case_status_change_request.

    Then:
    - Validate that case update status request body created as expected.
    """
    requests_mock.put(f'{BASE_URL}lr-case-api/cases/1/actions/changeStatus/', json={})
    CLIENT.case_status_change_request(case_id='1', status='Mitigated')
    assert requests_mock.last_request.text == '{"statusNumber": 4}'


def test_case_evidence_list_request(requests_mock):
    """
    Given:
    - Case ID, evidence type and evidence status to filter.

    When:
    - Running case_evidence_list_request.

    Then:
    - Validate that case evidence list request query created as expected.
    """
    requests_mock.get(f'{BASE_URL}lr-case-api/cases/1/evidence', json={})
    CLIENT.case_evidence_list_request('1', '', 'alarm', 'pending')
    assert requests_mock.last_request.query == 'type=alarm&status=pending'
