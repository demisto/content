import json

import pytest

from CommonServerPython import arg_to_datetime


def test_dedup_elements():
    from CohesityHeliosEventCollector import adjust_and_dedup_elements, ALERT_TIME_FIELD, AUDIT_LOGS_TIME_FIELD
    """
    Case 1:
    Given a list of 3 elements where all IDs appear in the ID list.
    We expect the result list to have no elements at all and that the final list length was not changed.
    """
    new_elements = [{'id': '1', 'latestTimestampUsecs': 1704096000000000},
                    {'id': '2', 'latestTimestampUsecs': 1704182400000000},
                    {'id': '3', 'latestTimestampUsecs': 1704268800000000}]
    existing_element_ids = ['1', '2', '3']
    deduped_elements = adjust_and_dedup_elements(new_elements=new_elements, existing_element_ids=existing_element_ids,
                                                 time_field_name='')
    assert deduped_elements == []
    assert len(new_elements) == 3

    """
    Case 2:
    Given a list of 2 elements where all elements appear in the existing ID list
    We expect the result list to have no elements at all and that the final list length was not changed.
    """
    new_elements = [{'id': '2', 'latestTimestampUsecs': 1704182400000000},
                    {'id': '3', 'latestTimestampUsecs': 1704268800000000}]
    existing_element_ids = ['1', '2', '3']
    deduped_elements = adjust_and_dedup_elements(new_elements=new_elements, existing_element_ids=existing_element_ids,
                                                 time_field_name='')
    assert deduped_elements == []
    assert len(new_elements) == 2

    """
    Case 3:
    Given a list of 3 elements where the first element appear in the existing ID list.
    We expect the result list to have the other two elements and that the final list length was not changed.
    """
    new_elements = [{'id': '1', 'latestTimestampUsecs': 1704096000000000},
                    {'id': '2', 'latestTimestampUsecs': 1704182400000000},
                    {'id': '3', 'latestTimestampUsecs': 1704268800000000}]
    existing_element_ids = ['1']
    deduped_elements = adjust_and_dedup_elements(new_elements=new_elements, existing_element_ids=existing_element_ids,
                                                 time_field_name=ALERT_TIME_FIELD)
    assert deduped_elements == [{'id': '2', 'latestTimestampUsecs': 1704182400000000, '_time': '2024-01-02T08:00:00.000Z'},
                                {'id': '3', 'latestTimestampUsecs': 1704268800000000, '_time': '2024-01-03T08:00:00.000Z'}]
    assert len(new_elements) == 3

    """
    Case 4:
    Given a list of 3 elements while the existing ID list is empty.
    We expect the result list to have all elements and that the final list length was not changed.
    """
    new_elements = [{'id': '1', 'timestampUsecs': 1704096000000000}, {'id': '2', 'timestampUsecs': 1704182400000000},
                    {'id': '3', 'timestampUsecs': 1704268800000000}]
    existing_element_ids = []
    deduped_elements = adjust_and_dedup_elements(new_elements=new_elements, existing_element_ids=existing_element_ids,
                                                 time_field_name=AUDIT_LOGS_TIME_FIELD)
    assert deduped_elements == [{'id': '1', 'timestampUsecs': 1704096000000000, '_time': '2024-01-01T08:00:00.000Z'},
                                {'id': '2', 'timestampUsecs': 1704182400000000, '_time': '2024-01-02T08:00:00.000Z'},
                                {'id': '3', 'timestampUsecs': 1704268800000000, '_time': '2024-01-03T08:00:00.000Z'}]
    assert len(new_elements) == 3

    """
    Case 5:
    Given an empty list elements.
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
    Case 1:
    Given a list of Alert events where there is only one event that has the earliest timestamp
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
    Case 2:
    Given a list of Alert events where there are two "earliest" events
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
    Case 3:
    Given a list of Audit Log events where there is only one event that has the earliest timestamp
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
    Case 4:
    Given a list of Audit Log events where there are two "earliest" events
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
    Given dummy audit log event with the relevant fields
    Ensure the id is created correctly
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
    """
    Class to test the different Fetch events flow.
    Fetch events has test 3 case:
    1: There are fewer events than page_size on first request
    2: There are more than page_size events but there are less than max_fetch events
    3: There are more than max_fetch events
    """
    base_url = 'https://test.com'
    audit_logs_endpoint = 'mcm/audit-logs'
    alerts_endpoint = 'mcm/alerts'
    mock_time = '2024-01-01 10:00:00'
    mock_fixed_time_unix = int(arg_to_datetime(mock_time).timestamp() * 1000000)

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
        """
        Case 1 is when where are fewer events (4) than page_size (10,000) on the first request.

        We expect:
            - Each event type API call to be called once
            - To have only 4 events returned
            - Audit logs next start time for the next fetch to be set to the latest pulled event timestamp plus 1
                (170691857331523)
            - No list of ids_for_dedup and no latest_event_fetched_timestamp for audit logs
            - Alerts next start time for the next fetch to be set to the latest pulled event timestamp plus 1 (1708175775539274)
            - No list of ids_for_dedup and no latest_event_fetched_timestamp for alerts
        """
        from CohesityHeliosEventCollector import Client, fetch_events_command

        # mockers
        mocker.patch("CohesityHeliosEventCollector.arg_to_datetime", return_value=arg_to_datetime(self.mock_time))
        audit_logs_call = requests_mock.get(f'{self.base_url}/{self.audit_logs_endpoint}', json=audit_logs_mock_res[0])
        alerts_call = requests_mock.get(f'{self.base_url}/{self.alerts_endpoint}', json=alerts_mock_res[0])

        client = Client(base_url=self.base_url)
        events, last_run = fetch_events_command(client=client, last_run={}, max_fetch=1000)

        assert audit_logs_call.call_count == alerts_call.call_count == 1
        assert len(events) == 4
        assert last_run['audit_cache']['next_start_timestamp'] == 170691857331523
        assert not last_run['audit_cache']['ids_for_dedup']
        assert not last_run['audit_cache']['latest_event_fetched_timestamp']
        assert last_run['alert_cache']['next_start_timestamp'] == 1708175775539274
        assert not last_run['alert_cache']['ids_for_dedup']
        assert not last_run['audit_cache']['latest_event_fetched_timestamp']

    def test_fetch_events_command_case_2(self, requests_mock, mocker, audit_logs_mock_res, alerts_mock_res):
        """
        Case 2 is when there are more events (3) from each type than the page_size (2), but there are not more than max_fetch
        (1000).

        We expect:
            - Each event type API call to be called twice
            - That the endtimeusecs in the 2dn API call for audit logs will be the same as the time of the earliest event fetched
                timestamp
            - That the enddateusecs in the 2dn API call for alerts will be the same as the time of the earliest event fetched
                timestamp
            - To have 6 events returned
            - Audit logs next start time for the next fetch to be set to the latest pulled event timestamp plus 1
                (170691857331523)
            - No list of ids_for_dedup and no latest_event_fetched_timestamp for audit logs
            - Alerts next start time for the next fetch to be set to the latest pulled event timestamp plus 1 (1708175775539274)
            - No list of ids_for_dedup and no latest_event_fetched_timestamp for alerts
        """
        import CohesityHeliosEventCollector
        from CohesityHeliosEventCollector import Client, fetch_events_command

        # mockers
        mocker.patch.object(CohesityHeliosEventCollector, 'PAGE_SIZE', 2)
        mocker.patch("CohesityHeliosEventCollector.arg_to_datetime", return_value=arg_to_datetime(self.mock_time))
        audit_logs_call = requests_mock.get(f'{self.base_url}/{self.audit_logs_endpoint}',
                                            [{'json': audit_logs_mock_res[0]}, {'json': audit_logs_mock_res[2]}])
        alerts_call = requests_mock.get(f'{self.base_url}/{self.alerts_endpoint}',
                                        [{'json': alerts_mock_res[0]}, {'json': alerts_mock_res[2]}])

        audit_logs_expected_end_time = audit_logs_mock_res[0].get('auditLogs')[1].get('timestampUsecs')
        alerts_expected_end_time = alerts_mock_res[0].get('alertsList')[1].get('latestTimestampUsecs')
        client = Client(base_url=self.base_url)
        events, last_run = fetch_events_command(client=client, last_run={}, max_fetch=1000)

        assert audit_logs_call.call_count == alerts_call.call_count == 2
        assert audit_logs_call.request_history[1].qs['endtimeusecs'][0] == str(audit_logs_expected_end_time)
        assert alerts_call.request_history[1].qs['enddateusecs'][0] == str(alerts_expected_end_time)
        assert len(events) == 6
        assert last_run['audit_cache']['next_start_timestamp'] == 170691857331523
        assert not last_run['audit_cache']['ids_for_dedup']
        assert not last_run['audit_cache']['latest_event_fetched_timestamp']
        assert last_run['alert_cache']['next_start_timestamp'] == 1708175775539274
        assert not last_run['alert_cache']['ids_for_dedup']
        assert not last_run['alert_cache']['latest_event_fetched_timestamp']

    def test_fetch_events_command_case_3(self, requests_mock, mocker, audit_logs_mock_res, alerts_mock_res):
        """
        Case 3 is when there are more events than max_fetch events.

        We expect:
            - Each event type API call to be called twice
            - That the endtimeusecs in the 2dn API call for audit logs will be the same as the time of the earliest event fetched
                timestamp
            - That the enddateusecs in the 2dn API call for alerts will be the same as the time of the earliest event fetched
                timestamp
            - To have 8 events returned
            - Audit logs next start time for the next fetch to be set to the same initial start time
            - ids_for_dedup in the audit_log cache has the ID of the earliest audit log event
            - latest_event_fetched_timestamp in the audit_log cache holds the latest audit log event timestamp plus 1 sec
            - Alerts next start time for the next fetch to be set to the same initial start time
            - No list of ids_for_dedup and no latest_event_fetched_timestamp for alerts
            - ids_for_dedup in the alerts cache has the ID of the earliest alert event
            - latest_event_fetched_timestamp in the alerts cache holds the latest alert event timestamp plus 1 sec
        """
        import CohesityHeliosEventCollector
        from CohesityHeliosEventCollector import Client, fetch_events_command

        # mockers
        mocker.patch.object(CohesityHeliosEventCollector, 'PAGE_SIZE', 2)
        mocker.patch("CohesityHeliosEventCollector.arg_to_datetime", return_value=arg_to_datetime(self.mock_time))
        audit_logs_call = requests_mock.get(f'{self.base_url}/{self.audit_logs_endpoint}',
                                            [{'json': audit_logs_mock_res[0]},
                                             {'json': audit_logs_mock_res[1]}])
        alerts_call = requests_mock.get(f'{self.base_url}/{self.alerts_endpoint}',
                                        [{'json': alerts_mock_res[0]},
                                         {'json': alerts_mock_res[1]}])

        audit_logs_expected_end_time = audit_logs_mock_res[0].get('auditLogs')[1].get('timestampUsecs')
        alerts_expected_end_time = alerts_mock_res[0].get('alertsList')[1].get('latestTimestampUsecs')

        client = Client(base_url=self.base_url)
        events, last_run = fetch_events_command(client=client, last_run={}, max_fetch=3)

        assert audit_logs_call.call_count == alerts_call.call_count == 2
        assert audit_logs_call.request_history[1].qs['endtimeusecs'][0] == str(audit_logs_expected_end_time)
        assert alerts_call.request_history[1].qs['enddateusecs'][0] == str(alerts_expected_end_time)
        assert len(events) == 8
        assert last_run['audit_cache']['next_start_timestamp'] == self.mock_fixed_time_unix
        assert last_run['audit_cache']['ids_for_dedup'] == ['4b2c6b16b2d288ed617ec28f5aca574bd8fb5670c696b726f483057ccc8aff16']
        assert last_run['audit_cache']['latest_event_fetched_timestamp'] == 170691857331523
        assert last_run['alert_cache']['next_start_timestamp'] == self.mock_fixed_time_unix
        assert last_run['alert_cache']['ids_for_dedup'] == ['66770']
        assert last_run['alert_cache']['latest_event_fetched_timestamp'] == 1708175775539274
