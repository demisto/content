import json

import pytest

from CommonServerPython import arg_to_datetime


def test_dedup_elements():
    from CohesityHeliosEventCollector import adjust_and_dedup_elements, ALERT_TIME_FIELD, AUDIT_LOGS_TIME_FIELD
    """
    Case 1: all elements appear in the existing ID list.
    We expect the result list to have no elements at all and that the final list length was not changed.
    """
    new_elements = [{'id': '1', 'latestTimestampUsecs': '1'}, {'id': '2', 'latestTimestampUsecs': '2'},
                    {'id': '3', 'latestTimestampUsecs': '3'}]
    existing_element_ids = ['1', '2', '3']
    deduped_elements = adjust_and_dedup_elements(new_elements=new_elements, existing_element_ids=existing_element_ids,
                                                 time_field_name='')
    assert deduped_elements == []
    assert len(new_elements) == 3

    """
    Case 2: all elements appear in the existing ID list
    We expect the result list to have no elements at all and that the final list length was not changed.
    """
    new_elements = [{'id': '2', 'latestTimestampUsecs': '2'}, {'id': '3', 'latestTimestampUsecs': '3'}]
    existing_element_ids = ['1', '2', '3']
    deduped_elements = adjust_and_dedup_elements(new_elements=new_elements, existing_element_ids=existing_element_ids,
                                                 time_field_name='')
    assert deduped_elements == []
    assert len(new_elements) == 2

    """
    Case 3: the first element appear in the existing ID list.
    We expect the result list to have the other two elements and that the final list length was not changed.
    """
    new_elements = [{'id': '1', 'latestTimestampUsecs': '1'}, {'id': '2', 'latestTimestampUsecs': '2'},
                    {'id': '3', 'latestTimestampUsecs': '3'}]
    existing_element_ids = ['1']
    deduped_elements = adjust_and_dedup_elements(new_elements=new_elements, existing_element_ids=existing_element_ids,
                                                 time_field_name=ALERT_TIME_FIELD)
    assert deduped_elements == [{'id': '2', 'latestTimestampUsecs': '2', '_time': '2'},
                                {'id': '3', 'latestTimestampUsecs': '3', '_time': '3'}]
    assert len(new_elements) == 3

    """
    Case 4: The existing ID list is empty.
    We expect the result list to have all elements and that the final list length was not changed.
    """
    new_elements = [{'id': '1', 'timestampUsecs': '1'}, {'id': '2', 'timestampUsecs': '2'},
                    {'id': '3', 'timestampUsecs': '3'}]
    existing_element_ids = []
    deduped_elements = adjust_and_dedup_elements(new_elements=new_elements, existing_element_ids=existing_element_ids,
                                                 time_field_name=AUDIT_LOGS_TIME_FIELD)
    assert deduped_elements == [{'id': '1', 'timestampUsecs': '1', '_time': '1'},
                                {'id': '2', 'timestampUsecs': '2', '_time': '2'},
                                {'id': '3', 'timestampUsecs': '3', '_time': '3'}]
    assert len(new_elements) == 3

    """
    Case 5: The list of elements is empty.
    We expect the result list to have no elements at all and that the final list length was not changed.
    """
    new_elements = []
    existing_element_ids = ['1', '2', '3']
    deduped_elements = adjust_and_dedup_elements(new_elements=new_elements, existing_element_ids=existing_element_ids,
                                                 time_field_name='')
    assert deduped_elements == []
    assert len(new_elements) == 0


def test_get_earliest_event_ids_with_the_same_time():
    from CohesityHeliosEventCollector import get_earliest_event_ids_with_the_same_time, ALERT_TIME_FIELD, AUDIT_LOGS_TIME_FIELD

    time_field = ALERT_TIME_FIELD
    """
    Case 1: list of Alert events where there is only one event that has the earliest timestamp
    Ensure only the ID of the earliest Alert is returned
    """
    events = [
        {'latestTimestampUsecs': '3', 'id': 'c'},
        {'latestTimestampUsecs': '2', 'id': 'b'},
        {'latestTimestampUsecs': '1', 'id': 'a'}
    ]
    earliest_event_fetched_ids = get_earliest_event_ids_with_the_same_time(events=events, time_field=time_field)
    assert earliest_event_fetched_ids == ['a']

    """
    Case 2: list of Alert events where there are two "earliest" events
    Ensure the ID of the TWO earliest Alerts is returned
    """
    events = [
        {'latestTimestampUsecs': '3', 'id': 'd'},
        {'latestTimestampUsecs': '2', 'id': 'c'},
        {'latestTimestampUsecs': '1', 'id': 'b'},
        {'latestTimestampUsecs': '1', 'id': 'a'}
    ]
    earliest_event_fetched_ids = get_earliest_event_ids_with_the_same_time(events=events, time_field=time_field)
    assert earliest_event_fetched_ids == ['a', 'b']

    time_field = AUDIT_LOGS_TIME_FIELD
    """
    Case 3: list of Audit Log events where there is only one event that has the earliest timestamp
    Ensure only the ID of the earliest event is returned
    """
    events = [
        {'timestampUsecs': '3', 'id': 'c'},
        {'timestampUsecs': '2', 'id': 'b'},
        {'timestampUsecs': '1', 'id': 'a'}
    ]
    earliest_event_fetched_ids = get_earliest_event_ids_with_the_same_time(events=events, time_field=time_field)
    assert earliest_event_fetched_ids == ['a']

    """
    Case 4: list of Audit Log events where there are two "earliest" events
    Ensure the ID of the TWO earliest Audit logs is returned
    """
    events = [
        {'timestampUsecs': '3', 'id': 'd'},
        {'timestampUsecs': '2', 'id': 'c'},
        {'timestampUsecs': '1', 'id': 'b'},
        {'timestampUsecs': '1', 'id': 'a'}
    ]
    earliest_event_fetched_ids = get_earliest_event_ids_with_the_same_time(events=events, time_field=time_field)
    assert earliest_event_fetched_ids == ['a', 'b']


def test_hash_fields_to_create_id():
    """
    Given: Dummy audit log event with the relevant fields
    """
    from CohesityHeliosEventCollector import hash_fields_to_create_id
    event = {
        'details': 'dummy_details',
        'username': 'dummy_username',
        'domain': 'dummy_domain',
        'sourceType': 'dummy_sourceType',
        'entityName': 'dummy_entityName',
        'entityType': 'dummy_entityType',
        'action': 'dummy_action',
        'timestampUsecs': 'dummy_timestampUsecs',
        'ip': 'dummy_ip',
        'isImpersonation': 'dummy_isImpersonation',
        'tenantId': 'dummy_tenantId',
        'originalTenantId': 'dummy_originalTenantId',
        'serviceContext': 'dummy_serviceContext'
    }
    _id = hash_fields_to_create_id(event)
    assert _id == '8bb89cb674035796b755e9e1db5022dc750e904f520eb290d18e134b12656bf2'


class TestFetchEventsCommand:
    base_url = 'https://test.com'
    audit_logs_endpoint = 'mcm/audit-logs'
    alerts_endpoint = 'mcm/alerts'
    mock_time = '2024-01-01 10:00:00'
    mock_fixed_time_unix = int(arg_to_datetime(mock_time).timestamp() * 1000000)

    # Fetch should test 3 case:
    # 1: There are fewer events than page_size on first request
    # 2: There are more than page_size events but there are less than max_fetch events
    # 3: There are more than max_fetch events
    @staticmethod
    def load_response(event_type) -> dict:
        from CohesityHeliosEventCollector import EventType
        filename = 'test_data/CohesityHeliosEventCollector-AuditLogList.json' if event_type == EventType.audit_log else \
            'test_data/CohesityHeliosEventCollector-AlertList.json'
        with open(filename) as f:
            return json.loads(f.read())

    @pytest.fixture()
    def audit_logs_mock_res(self):
        import CohesityHeliosEventCollector
        return self.load_response(CohesityHeliosEventCollector.EventType.audit_log)

    @pytest.fixture()
    def alerts_mock_res(self):
        import CohesityHeliosEventCollector
        return self.load_response(CohesityHeliosEventCollector.EventType.alert)

    def test_fetch_events_command_case_1(self, requests_mock, mocker, audit_logs_mock_res, alerts_mock_res):
        # audit_logs_mock = requests_mock.get(audit_logs_matcher, json=audit_logs_mock_res)
        # audit_logs_matcher = re.compile(f'{self.base_url}/{self.audit_logs_endpoint}?.*')

        from CohesityHeliosEventCollector import Client, fetch_events_command

        # mockers
        mocker.patch("CohesityHeliosEventCollector.arg_to_datetime", return_value=arg_to_datetime(self.mock_time))
        requests_mock.get(f'{self.base_url}/{self.audit_logs_endpoint}?'
                          f'startTimeUsecs={self.mock_fixed_time_unix}&'
                          f'endTimeUsecs={self.mock_fixed_time_unix}&'
                          f'count=10000',
                          json=audit_logs_mock_res[0])
        requests_mock.get(f'{self.base_url}/{self.alerts_endpoint}?'
                          f'startDateUsecs={self.mock_fixed_time_unix}&'
                          f'endDateUsecs={self.mock_fixed_time_unix}&',
                          json=alerts_mock_res[0])

        client = Client(base_url=self.base_url)
        events, last_run = fetch_events_command(client=client, last_run={}, max_fetch=1000)

        assert len(events) == 4
        assert last_run['audit_cache']['next_start_timestamp'] == 170691857331523
        assert not last_run['audit_cache']['ids_for_dedup']
        assert not last_run['audit_cache']['latest_event_fetched_timestamp']
        assert last_run['alert_cache']['next_start_timestamp'] == 1708175775539274
        assert not last_run['alert_cache']['ids_for_dedup']
        assert not last_run['audit_cache']['latest_event_fetched_timestamp']

    def test_fetch_events_command_case_2(self, requests_mock, mocker, audit_logs_mock_res, alerts_mock_res):
        import CohesityHeliosEventCollector
        from CohesityHeliosEventCollector import Client, fetch_events_command

        mocker.patch.object(CohesityHeliosEventCollector, 'PAGE_SIZE', 2)
        mocker.patch("CohesityHeliosEventCollector.arg_to_datetime", return_value=arg_to_datetime(self.mock_time))

        audit_logs_expected_end_time = audit_logs_mock_res[0].get('auditLogs')[1].get('timestampUsecs')
        audit_logs_call_1 = requests_mock.get(f'{self.base_url}/{self.audit_logs_endpoint}',
                                              [{'json': audit_logs_mock_res[0]}, {'json': audit_logs_mock_res[2]}])

        # audit_logs_call_1 = requests_mock.get(
        #     f'{self.base_url}/{self.audit_logs_endpoint}?'
        #     f'startTimeUsecs={self.mock_fixed_time_unix}&'
        #     f'endTimeUsecs={self.mock_fixed_time_unix}&'
        #     f'count=10000',
        #     json=audit_logs_mock_res[0])
        # audit_logs_call_2 = requests_mock.get(
        #     f'{self.base_url}/{self.audit_logs_endpoint}?'
        #     f'startTimeUsecs={self.mock_fixed_time_unix}&'
        #     f'endTimeUsecs={audit_logs_expected_end_time}&'
        #     f'count=10000',
        #     json=audit_logs_mock_res[2])

        alerts_expected_end_time = alerts_mock_res[0].get('alertsList')[1].get('latestTimestampUsecs')
        alerts_call_1 = requests_mock.get(f'{self.base_url}/{self.alerts_endpoint}',
                                          [{'json': alerts_mock_res[0]}, {'json': alerts_mock_res[2]}])

        # alerts_call_1 = requests_mock.get(
        #     f'{self.base_url}/{self.alerts_endpoint}',
        #     f'{self.base_url}/{self.alerts_endpoint}?'
        #     f'startDateUsecs={self.mock_fixed_time_unix}&'
        #     f'endDateUsecs={self.mock_fixed_time_unix}&',
        #     json=alerts_mock_res[0])
        # alerts_call_2 = requests_mock.get(
        #     f'{self.base_url}/{self.alerts_endpoint}?'
        #     f'startDateUsecs={self.mock_fixed_time_unix}&'
        #     f'endDateUsecs={alerts_expected_end_time}&',
        #     json=alerts_mock_res[2])

        client = Client(base_url=self.base_url)
        events, last_run = fetch_events_command(client=client, last_run={}, max_fetch=1000)
        assert len(events) == 6
        assert last_run['audit_cache']['next_start_timestamp'] == 170691857331523
        assert not last_run['audit_cache']['ids_for_dedup']
        assert not last_run['audit_cache']['latest_event_fetched_timestamp']
        assert last_run['alert_cache']['next_start_timestamp'] == 1708175775539274
        assert not last_run['alert_cache']['ids_for_dedup']
        assert not last_run['audit_cache']['latest_event_fetched_timestamp']
        # assert audit_logs_call_1.call_count == audit_logs_call_2.call_count == alerts_call_1.call_count == \
        #        alerts_call_2.call_count == 1
