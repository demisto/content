import requests_mock
from freezegun import freeze_time
import demistomock as demisto
from SymantecCloudSOCEventCollector import Client
import pytest
import json


''' HELPER FUNCTIONS '''


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


response_data = util_load_json('./test_data/test_data_dedup_by_id.json')
response_pagination_incident = util_load_json('./test_data/test_data_pagination_incident.json')
response_pagination_investigate = util_load_json('./test_data/test_data_pagination_investigate.json')


def get_mocked_url(app: str, subtype: str,
                   created_timestamp: str = None, limit: int = None):
    if limit:
        if created_timestamp:
            return f'{mocked_client._base_url}?app={app}&subtype={subtype}&limit={limit}&created_timestamp={created_timestamp}'
        return f'{mocked_client._base_url}?app={app}&subtype={subtype}&limit={limit}'
    return f'{mocked_client._base_url}?app={app}&subtype={subtype}'


def mock_set_last_run(last_run):
    return last_run


def get_client() -> Client:
    return Client(
        base_url='http://some_mock_url.com',
        verify=False,
        proxy=None,
        headers={
            'Authorization': 'Basic encoded_credentials',
            'X-Elastica-Dbname-Resolved': 'True',
        },
    )


mocked_client = get_client()
test_params = {
    "credentials": {
        "password": "api_token",
    },
    "insecure": True,
    "proxy": False,
    "server_url": "server_url",
    "first_fetch": "3 days",
    "max_fetch": "1"
}


def test_get_events_command():
    """
        Given:
            - The SymantecCloudSOC Client.
        When:
            - Calling to symantec-get-events command.
        Then:
            - Verify human-readable outputs.
    """
    from SymantecCloudSOCEventCollector import get_events_command
    with requests_mock.Mocker() as request_mocker:
        investigate_mocker = request_mocker.get(
            url=get_mocked_url(app="investigate", subtype="all",
                                   created_timestamp="2023-01-01T23%3A23%3A59",
                                   limit=1000),
            status_code=200, json=response_data["Investigate_logs"])
        detect_incidents_mocker = request_mocker.get(
            url=get_mocked_url(app="Detect", subtype="incidents",
                               created_timestamp="2023-01-01T23%3A23%3A59",
                               limit=1000),
            status_code=200, json=response_data["Incident_logs"])
        event_list, command_results = get_events_command(mocked_client, '2023-01-01T23:23:59', '2023-01-01T23:23:59', {}, 3)
        assert investigate_mocker.called
        assert investigate_mocker.called_once
        assert detect_incidents_mocker.called
        assert detect_incidents_mocker.called_once
        assert event_list == response_data["all_events"]
        assert command_results.readable_output == response_data["readable_output_collector"]


@freeze_time("2022-01-01 00:00:00 UTC")
def test_test_module():
    """
        Given:
            - The SymantecCloudSOC Client.
        When:
            - Calling to test-module command.
        Then:
            - Ensure that three API calls are executed and each call is execute only once.
    """
    from SymantecCloudSOCEventCollector import test_module
    with requests_mock.Mocker() as request_mocker:
        investigate_mocker = request_mocker.get(
            url=get_mocked_url(app="Investigate", subtype="all",
                               created_timestamp="2022-01-01T00%3A00%3A00Z", limit=1),
            status_code=200, json={})
        detect_incidents_mocker = request_mocker.get(
            url=get_mocked_url(app="detect", subtype="incidents", limit=1),
            status_code=200, json={})
        test_module(mocked_client)
    assert investigate_mocker.called
    assert investigate_mocker.called_once
    assert detect_incidents_mocker.called
    assert detect_incidents_mocker.called_once


@pytest.mark.parametrize('event, log_type ,expected_event', [
    ({"_id": "_id1", "incident_start_time": "2023-01-02T23:23:59"},
     "Incident_logs",
     {'_id': '_id1', '_time': '2023-01-02T23:23:59',
      'incident_start_time': '2023-01-02T23:23:59',
      'type': 'Detect incident'}),
    ({"_id": "_id1", "created_timestamp": "2023-01-02T23:23:59"},
     "Investigate_logs",
     {'_id': '_id1', '_time': '2023-01-02T23:23:59',
      'created_timestamp': '2023-01-02T23:23:59',
      'type': 'Investigate'})])
def test_add_fields_to_event(event, log_type, expected_event):
    """
        Given:
            - An event dict and log_type.
        When:
            - executing add_fields_to_event function.
        Then:
            - Ensure that the fields _time and type are added.
    """
    from SymantecCloudSOCEventCollector import add_fields_to_event
    add_fields_to_event(event, log_type)
    assert event == expected_event


dedup_by_id_test_case: list = [
    ({'last_run': '2024-01-02T23:23:59'}, [], "Investigate_logs", 100,
     0, "2023-01-02T23:23:59", {'last_run': '2024-01-02T23:23:59'}, []),
    ({'last_run': '2023-01-02T23:23:59'}, [], "Investigate_logs", 100,
     0, "2022-01-02T23:23:59", {'last_run': '2023-01-02T23:23:59'}, []),
    ({'last_run': '2023-01-02T23:23:59'},
     [{"_id": "_id1", "incident_start_time": "2023-01-02T23:23:59"}], "Incident_logs",
     100, 100, "2022-01-02T23:23:59", {'last_run': '2023-01-02T23:23:59', 'Incident_logs-ids': []}, []),
    ({'last_run': '2023-01-02T23:23:59'},
     [{"_id": "_id1", "incident_start_time": "2023-01-02T23:23:59"}], "Incident_logs",
     100, 99, "2022-01-02T23:23:59", {'last_run': '2023-01-02T23:23:59', 'Incident_logs-ids': ["_id1"]},
     [{'_id': '_id1', '_time': '2023-01-02T23:23:59', 'incident_start_time': '2023-01-02T23:23:59', 'type': 'Detect incident'}]),
    ({'last_run': '2023-01-02T22:23:59'},
     [{"_id": "_id1", "incident_start_time": "2023-01-02T23:23:59"},
      {"_id": "_id2", "incident_start_time": "2023-01-02T23:23:59"}],
     "Incident_logs", 100, 99, "2022-01-02T22:22:59", {'last_run': '2023-01-02T23:23:59', 'Incident_logs-ids': ["_id1"]},
     [{'_id': '_id1', '_time': '2023-01-02T23:23:59', 'incident_start_time': '2023-01-02T23:23:59', 'type': 'Detect incident'}]),
    ({'last_run': '2023-01-02T22:22:59'},
     [{"_id": "_id1", "incident_start_time": "2023-01-02T22:22:59"},
      {"_id": "_id2", "incident_start_time": "2023-01-02T23:23:59"}],
     "Incident_logs", 100, 98, "2022-01-02T23:23:59", {'last_run': '2023-01-02T23:23:59', 'Incident_logs-ids': ["_id2"]},
     [{'_id': '_id1', '_time': '2023-01-02T22:22:59', 'incident_start_time': '2023-01-02T22:22:59', 'type': 'Detect incident'},
      {'_id': '_id2', '_time': '2023-01-02T23:23:59', 'incident_start_time': '2023-01-02T23:23:59', 'type': 'Detect incident'}]),
    ({'last_run': '2023-01-02T23:22:59'},
     [{"_id": "_id1", "incident_start_time": "2023-01-02T23:23:59"},
      {"_id": "_id2", "incident_start_time": "2023-01-02T23:23:59"}],
     "Incident_logs", 100, 98, "2022-01-02T23:23:59",
     {'last_run': '2023-01-02T23:23:59', 'Incident_logs-ids': ["_id1", "_id2"]},
     [{'_id': '_id1', '_time': '2023-01-02T23:23:59', 'incident_start_time': '2023-01-02T23:23:59', 'type': 'Detect incident'},
      {'_id': '_id2', '_time': '2023-01-02T23:23:59', 'incident_start_time': '2023-01-02T23:23:59', 'type': 'Detect incident'}]),
    ({'last_run': '2023-01-02T23:22:59', 'Incident_logs-ids': ["_id1", "_id2"]},
     [{"_id": "_id1", "incident_start_time": "2023-01-02T23:22:59"},
      {"_id": "_id2", "incident_start_time": "2023-01-02T23:22:59"}],
     "Incident_logs", 100, 98, "2022-01-02T23:23:59",
     {'last_run': '2023-01-02T23:22:59', 'Incident_logs-ids': ["_id1", "_id2"]}, []),
    ({'last_run': '2023-01-02T23:22:59', 'Incident_logs-ids': ["_id1"]},
     [{"_id": "_id1", "incident_start_time": "2023-01-02T23:22:59"},
      {"_id": "_id2", "incident_start_time": "2023-01-02T23:22:59"}],
     "Incident_logs", 100, 98, "2022-01-02T23:23:59", {'last_run': '2023-01-02T23:22:59', 'Incident_logs-ids': ["_id1", "_id2"]},
     [{'_id': '_id2', '_time': '2023-01-02T23:22:59', 'incident_start_time': '2023-01-02T23:22:59', 'type': 'Detect incident'}]),
]


@pytest.mark.parametrize('last_run_for_log_type, log_events, log_type, max_fetch, '
                         'number_of_events, last_fetch, expected_last_run,'
                         'expected_event_list', dedup_by_id_test_case)
def test_dedup_by_id_with_last_run(last_run_for_log_type, log_events, log_type,
                                   max_fetch, number_of_events, last_fetch,
                                   expected_last_run, expected_event_list):
    """
        Given:
            - A last_run dict, a list of logs, type of the log, max fetch and number of events.
        When:
            - executing dedup_by_id function.
        Then:
            - Ensure that the last_run object is correct and verify content of the event_list.
    """
    from SymantecCloudSOCEventCollector import dedup_by_id
    list_of_events, last_run_for_log_type = dedup_by_id(last_run_for_log_type, log_events, log_type,
                                                        max_fetch, number_of_events, last_fetch)
    assert expected_last_run == last_run_for_log_type
    assert list_of_events == expected_event_list


dedup_by_id_test_case_without_last_run: list = [
    ({}, [], "Investigate_logs", 100, 0, "2023-01-02T23:23:59", {'last_run': '2023-01-02T23:23:59'}, []),
    ({}, [], "Incident_logs", 100, 100, "2023-01-02T23:23:59", {'last_run': '2023-01-02T23:23:59'}, []),
    ({}, [{"_id": "_id1", "incident_start_time": "2023-01-02T23:23:59"},
          {"_id": "_id2", "incident_start_time": "2023-01-02T23:23:59"}],
        "Incident_logs", 100, 0, "2023-01-02T23:23:59",
     {'last_run': '2023-01-02T23:23:59', 'Incident_logs-ids': ['_id1', '_id2']},
     [{'_id': '_id1', '_time': '2023-01-02T23:23:59',
       'incident_start_time': '2023-01-02T23:23:59', 'type': 'Detect incident'},
      {'_id': '_id2', '_time': '2023-01-02T23:23:59',
       'incident_start_time': '2023-01-02T23:23:59', 'type': 'Detect incident'}]),
    ({}, [{"_id": "_id1", "incident_start_time": "2023-01-03T23:23:59"},
          {"_id": "_id2", "incident_start_time": "2023-01-04T23:23:59"}],
     "Incident_logs", 100, 0, "2023-01-02T23:23:59",
     {'last_run': '2023-01-04T23:23:59', 'Incident_logs-ids': ['_id1', '_id2']},
     [{'_id': '_id1', '_time': '2023-01-03T23:23:59',
       'incident_start_time': '2023-01-03T23:23:59', 'type': 'Detect incident'},
      {'_id': '_id2', '_time': '2023-01-04T23:23:59',
       'incident_start_time': '2023-01-04T23:23:59', 'type': 'Detect incident'}])]


@pytest.mark.parametrize('last_run_for_log_type, log_events, log_type, max_fetch, '
                         'number_of_events, last_fetch, expected_last_run,'
                         'expected_event_list', dedup_by_id_test_case_without_last_run)
def test_dedup_by_id_without_last_run(last_run_for_log_type, log_events, log_type,
                                      max_fetch, number_of_events, last_fetch,
                                      expected_last_run, expected_event_list):
    """
        Given:
            - A empty last_run dict, a list of logs, type of the log, max fetch and number of events.
        When:
            - executing dedup_by_id function.
        Then:
            - Ensure that the last_run object is correct and verify content of the event_list.
    """
    from SymantecCloudSOCEventCollector import dedup_by_id
    list_of_events, last_run_for_log_type = dedup_by_id(last_run_for_log_type, log_events, log_type,
                                                        max_fetch, number_of_events, last_fetch)
    assert expected_last_run == last_run_for_log_type
    assert list_of_events == expected_event_list


get_first_fetch_time_params = [({'first_fetch': "7 months"}, "2022-06-01T23:23:59", "2022-07-05T23:23:59"),
                               ({'first_fetch': "5 months"}, "2022-08-01T23:23:59", "2022-08-01T23:23:59")]


@freeze_time("2023-01-01T23:23:59")
@pytest.mark.parametrize('first_fetch_from_params,'
                         ', expected_fetch_Incident, expected_fetch_investigation', get_first_fetch_time_params)
def test_get_first_fetch_time(first_fetch_from_params, expected_fetch_Incident, expected_fetch_investigation):
    """
        Given:
            - first fetch time from integration parameters.
            - Case 1: The first fetch time is longer then 6 months.
            - Case 2: The first fetch time is shorter then 6 months.
        When:
            - executing get_first_fetch_time function.
        Then:
            - Validate that the fetch_incident and the fetch_investigation are as expected.
    """
    from SymantecCloudSOCEventCollector import get_first_fetch_time
    fetch_incident, fetch_investigation = get_first_fetch_time(first_fetch_from_params)
    assert fetch_incident == expected_fetch_Incident
    assert fetch_investigation == expected_fetch_investigation


def test_create_client_with_authorization():
    """
        Given:
            - base_url, verify_certificate, proxy, key_id, key_secret
        When:
            - executing create_client_with_authorization function.
        Then:
            - Ensure that the client created with the correct header and base url.
    """
    from SymantecCloudSOCEventCollector import create_client_with_authorization
    client_results = create_client_with_authorization("http://some_mock_url.com", True,
                                                      False, key_id="key_id", key_secret="key_secret")

    assert client_results._base_url == "http://some_mock_url.com"
    assert client_results._headers == {'Authorization': 'Basic a2V5X2lkOmtleV9zZWNyZXQ=',
                                       'X-Elastica-Dbname-Resolved': 'True'}


get_all_events_for_log_type_test_case_with_pagination: list = [
    (26, "Incident_logs", {}, "2021-06-01T00:00:00", "2021-06-01T00:00:00",
     response_pagination_incident["expected_event_list"][:26],
     {'Incident_logs-ids': response_pagination_incident["expected_ids_list"][:26], 'last_run': '2021-06-01T00:00:00'}),
    (40, "Investigate_logs", {}, "2021-06-01T00:00:00", "2021-06-01T00:00:00",
     response_pagination_investigate["expected_event_list"][:40],
     {'Investigate_logs-ids': response_pagination_investigate["expected_ids_list"][32:40], 'last_run': '2021-06-30T23:08:59'}),
]


@pytest.mark.parametrize('max_fetch, log_type, last_run,'
                         'first_fetch_time, first_fetch_time_investigate,'
                         'expected_all_events_list, expected_last_run',
                         get_all_events_for_log_type_test_case_with_pagination)
def test_get_all_events_for_log_type_with_pagination(max_fetch, log_type, last_run,
                                                     first_fetch_time, first_fetch_time_investigate,
                                                     expected_all_events_list, expected_last_run):
    """
        Given:
            - max_fetch, log_type, last_run, first_fetch_time,
              first_fetch_time_investigate
            - Case 1: All the fetched events with the same creation date.
            - Case 2: The fetched events with different creation date.
        When:
            - executing get_all_events_for_log_type function.
        Then:
            - Ensure that the pagination mechanism works as expected.
            - Validate that the last_run and the events_list are as expected.
    """
    from SymantecCloudSOCEventCollector import get_all_events_for_log_type
    with requests_mock.Mocker() as request_mocker:
        investigate_mocker = request_mocker.get(
            url=get_mocked_url(app="Investigate", subtype="all",
                               created_timestamp="2022-06-21T00%3A00%3A00Z", limit=1000),
            status_code=200, json=response_pagination_investigate["page_1_response"])
        detect_incidents_mocker = request_mocker.get(
            url=get_mocked_url(app="detect", subtype="incidents", limit=1000),
            status_code=200, json=response_pagination_incident["page_1_response"])
        investigate_mocker = request_mocker.get(
            url=get_mocked_url(app="Investigate", subtype="all", limit=1000),
            status_code=200, json=response_pagination_investigate["page_1_response"])
        detect_incidents_mocker_page = request_mocker.get(
            url="http://some_mock_url.com/incident",
            status_code=200, json=response_pagination_incident["page_2_response"])
        detect_investigate_mocker_page = request_mocker.get(
            url="http://some_mock_url.com/investigate",
            status_code=200, json=response_pagination_investigate["page_2_response"])

        all_events_list, last_run_for_log_type = get_all_events_for_log_type(mocked_client, max_fetch, log_type, last_run,
                                                                             first_fetch_time, first_fetch_time_investigate)
    if log_type == "Investigate_logs":
        assert investigate_mocker.called
        assert investigate_mocker.called_once
        assert detect_investigate_mocker_page.called
        assert detect_investigate_mocker_page.called_once
    else:
        assert detect_incidents_mocker_page.called
        assert detect_incidents_mocker_page.called_once
        assert detect_incidents_mocker.called
        assert detect_incidents_mocker.called_once
    assert len(all_events_list) == max_fetch
    assert all_events_list == expected_all_events_list
    assert last_run_for_log_type == expected_last_run


get_all_events_for_log_type_test_case_without_pagination: list = [
    (3, "Investigate_logs", {}, "2021-06-01T00:00:00", "2021-06-01T00:00:00",
     response_pagination_investigate["expected_event_list"][0:3], {
     'Investigate_logs-ids': response_pagination_investigate["expected_ids_list"][0:3], 'last_run': '2021-06-01T00:00:00'}),
]


@pytest.mark.parametrize('max_fetch, log_type, last_run,'
                         'first_fetch_time, first_fetch_time_investigate,'
                         'expected_all_events_list, expected_last_run',
                         get_all_events_for_log_type_test_case_without_pagination)
def test_get_all_events_for_log_type_without_pagination(max_fetch, log_type, last_run,
                                                        first_fetch_time, first_fetch_time_investigate,
                                                        expected_all_events_list, expected_last_run):
    """
        Given:
            - max_fetch, log_type, last_run, first_fetch_time,
              first_fetch_time_investigate
        When:
            - executing get_all_events_for_log_type function.
        Then:
            - Validate that the last_run and the events_list are as expected.
    """
    from SymantecCloudSOCEventCollector import get_all_events_for_log_type
    with requests_mock.Mocker() as request_mocker:
        investigate_mocker = request_mocker.get(
            url=get_mocked_url(app="Investigate", subtype="all",
                               created_timestamp="2022-01-01T00%3A00%3A00Z", limit=1000),
            status_code=200, json=response_pagination_investigate["page_1_response"])
        investigate_mocker = request_mocker.get(
            url=get_mocked_url(app="Investigate", subtype="all", limit=1000),
            status_code=200, json=response_pagination_investigate["page_1_response"])
        all_events_list, last_run_for_log_type = get_all_events_for_log_type(mocked_client, max_fetch, log_type, last_run,
                                                                             first_fetch_time, first_fetch_time_investigate)
    assert investigate_mocker.called
    assert investigate_mocker.called_once
    assert all_events_list == expected_all_events_list
    assert last_run_for_log_type == expected_last_run


test_main_params: list = [
    (3, {}, "2021-06-01T00:00:00", "2021-06-01T00:00:00",
     {'Investigate_logs': {
      'Investigate_logs-ids': response_pagination_investigate["expected_ids_list"][0:3], 'last_run': '2021-06-01T00:00:00'},
      'Incident_logs': {
      'Incident_logs-ids': response_pagination_incident["expected_ids_list"][0:3], 'last_run': '2021-06-01T00:00:00'}},
     [{'_id': 'id0', 'created_timestamp': '2021-06-01T00:00:00', '_time': '2021-06-01T00:00:00', 'type': 'Investigate'},
      {'_id': 'id1', 'created_timestamp': '2021-06-01T00:00:00', '_time': '2021-06-01T00:00:00', 'type': 'Investigate'},
      {'_id': 'id2', 'created_timestamp': '2021-06-01T00:00:00', '_time': '2021-06-01T00:00:00', 'type': 'Investigate'},
      {'_id': 'id0', 'incident_start_time': '2021-06-01T00:00:00', '_time': '2021-06-01T00:00:00', 'type': 'Detect incident'},
      {'_id': 'id1', 'incident_start_time': '2021-06-01T00:00:00', '_time': '2021-06-01T00:00:00', 'type': 'Detect incident'},
      {'_id': 'id2', 'incident_start_time': '2021-06-01T00:00:00', '_time': '2021-06-01T00:00:00', 'type': 'Detect incident'}
      ])
]


@freeze_time("2023-01-01T23:23:59")
@pytest.mark.parametrize('max_fetch, last_run, first_fetch_time, first_fetch_time_investigate,'
                         'expected_last_run, expected_events', test_main_params)
def test_fetch_events_command(mocker, max_fetch, last_run, first_fetch_time, first_fetch_time_investigate,
                              expected_last_run, expected_events):
    """
        Given:
            - max_fetch, log_type, last_run, first_fetch_time,
              first_fetch_time_investigate
        When:
            - executing fetch_events_command function.
        Then:
            - Validate that the last_run and the events are as expected.
    """
    from SymantecCloudSOCEventCollector import fetch_events_command
    mocker.patch.object(demisto, 'command', return_value='fetch-events')
    mocker.patch.object(demisto, 'params', return_value=test_params)
    with requests_mock.Mocker() as request_mocker:
        investigate_mocker = request_mocker.get(
            url=get_mocked_url(app="Investigate", subtype="all",
                               created_timestamp="2022-01-01T00%3A00%3A00Z", limit=1000),
            status_code=200, json=response_pagination_investigate["page_1_response"])
        detect_incidents_mocker = request_mocker.get(
            url=get_mocked_url(app="detect", subtype="incidents",
                               created_timestamp="2021-06-01T00%3A00%3A00", limit=1000),
            status_code=200, json=response_pagination_incident["page_1_response"])
        investigate_mocker = request_mocker.get(
            url=get_mocked_url(app="Investigate", subtype="all", limit=1000),
            status_code=200, json=response_pagination_investigate["page_1_response"])
        request_mocker.get(
            url="http://some_mock_url.com/incident",
            status_code=200, json=response_pagination_incident["page_2_response"])
        request_mocker.get(
            url="http://some_mock_url.com/investigate",
            status_code=200, json=response_pagination_investigate["page_2_response"])
        next_run, events = fetch_events_command(mocked_client, max_fetch, last_run,
                                                first_fetch_time, first_fetch_time_investigate)
    assert next_run == expected_last_run
    assert events == expected_events
    assert investigate_mocker.called
    assert investigate_mocker.called_once
    assert detect_incidents_mocker.called
    assert detect_incidents_mocker.called_once


def test_get_date_timestamp():
    """
        Given:
            - date string in both format with and without 'Z'
        When:
            - call get_date_timestamp
        Then:
            - Validate that the return date are as expected.
    """
    from SymantecCloudSOCEventCollector import get_date_timestamp

    assert get_date_timestamp('2024-06-02T07:39:08Z') == get_date_timestamp('2024-06-02T07:39:08')
