import requests_mock
from freezegun import freeze_time
import demistomock as demisto
from SymantecCloudSOC import Client
import pytest
from test_data.use_cases import response_data, response_pagination_incident, response_pagination_investigate
from test_data.use_cases import dedup_by_id_test_case, get_first_fetch_time_params
from test_data.use_cases import get_all_events_for_log_type_test_case, test_main_params


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
    from SymantecCloudSOC import get_events_command
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


def get_mocked_url(app: str, subtype: str,
                   created_timestamp: str = None, limit: int = None):
    if limit:
        if created_timestamp:
            return f'{mocked_client._base_url}?app={app}&subtype={subtype}&limit={limit}&created_timestamp={created_timestamp}'
        return f'{mocked_client._base_url}?app={app}&subtype={subtype}&limit={limit}'
    return f'{mocked_client._base_url}?app={app}&subtype={subtype}'


def mock_set_last_run(last_run):
    return last_run


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
    from SymantecCloudSOC import test_module
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


@pytest.mark.parametrize('event,log_type ,expected_event',
                         [({"_id": "_id1", "incident_start_time": "2023-01-02T23:23:59"},
                           "Incident_logs", {'_id': '_id1', '_time': '2023-01-02T23:23:59',
                                             'incident_start_time': '2023-01-02T23:23:59',
                                             'type': 'Detect incident'}),
                          ({"_id": "_id1", "created_timestamp": "2023-01-02T23:23:59"}, "Investigate_logs",
                           {'_id': '_id1',
                            '_time': '2023-01-02T23:23:59',
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
    from SymantecCloudSOC import add_fields_to_event
    add_fields_to_event(event, log_type)
    assert event == expected_event


@pytest.mark.parametrize('last_run_for_log_type, log_events, log_type, max_fetch, '
                         'number_of_events, last_fetch, expected_last_run,'
                         'expected_event_list', dedup_by_id_test_case)
def test_dedup_by_id(last_run_for_log_type, log_events, log_type,
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
    from SymantecCloudSOC import dedup_by_id
    list_of_events, last_run_for_log_type = dedup_by_id(last_run_for_log_type, log_events, log_type,
                                                        max_fetch, number_of_events, last_fetch)
    assert expected_last_run == last_run_for_log_type
    assert list_of_events == expected_event_list


@freeze_time("2023-01-01T23:23:59")
@pytest.mark.parametrize('first_fetch_from_params,'
                         ', expected_fetch_Incident, expected_fetch_investigation', get_first_fetch_time_params)
def test_get_first_fetch_time(first_fetch_from_params, expected_fetch_Incident, expected_fetch_investigation):
    from SymantecCloudSOC import get_first_fetch_time
    fetch_Incident, fetch_investigation = get_first_fetch_time(first_fetch_from_params)
    assert fetch_Incident == expected_fetch_Incident
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
    from SymantecCloudSOC import create_client_with_authorization
    client_results = create_client_with_authorization("http://some_mock_url.com", True,
                                                      False, key_id="key_id", key_secret="key_secret")

    assert client_results._base_url == "http://some_mock_url.com"
    assert client_results._headers == {'Authorization': 'Basic a2V5X2lkOmtleV9zZWNyZXQ=',
                                       'X-Elastica-Dbname-Resolved': 'True'}


@pytest.mark.parametrize('max_fetch, log_type, last_run,'
                         'first_fetch_time, first_fetch_time_investigate,'
                         'expected_all_events_list, expected_last_run',
                         get_all_events_for_log_type_test_case)
def test_get_all_events_for_log_type(max_fetch, log_type, last_run,
                                     first_fetch_time, first_fetch_time_investigate,
                                     expected_all_events_list, expected_last_run):
    from SymantecCloudSOC import get_all_events_for_log_type
    with requests_mock.Mocker() as request_mocker:
        investigate_mocker = request_mocker.get(
            url=get_mocked_url(app="Investigate", subtype="all",
                               created_timestamp="2022-01-01T00%3A00%3A00Z", limit=1000),
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
    detect_incidents_mocker.called
    detect_incidents_mocker.called_once
    investigate_mocker.called
    investigate_mocker.called_once
    if max_fetch > 1000:
        detect_incidents_mocker_page.called
        detect_incidents_mocker_page.called_once
        detect_investigate_mocker_page.called
        detect_investigate_mocker_page.called_once
    assert all_events_list == expected_all_events_list
    assert last_run_for_log_type == expected_last_run


@freeze_time("2023-01-01T23:23:59")
@pytest.mark.parametrize('max_fetch, last_run, first_fetch_time, first_fetch_time_investigate,'
                         'expected_last_run, expected_events', test_main_params)
def test_fetch_events_command(mocker, max_fetch, last_run, first_fetch_time, first_fetch_time_investigate,
                              expected_last_run, expected_events):
    from SymantecCloudSOC import fetch_events_command
    mocker.patch.object(demisto, 'command', return_value='fetch-events')
    mocker.patch.object(demisto, 'params', return_value=test_params)
    with requests_mock.Mocker() as request_mocker:
        investigate_mocker = request_mocker.get(
            url=get_mocked_url(app="Investigate", subtype="all",
                               created_timestamp="2022-01-01T00%3A00%3A00Z", limit=1000),
            status_code=200, json=response_pagination_investigate["page_1_response"])
        detect_incidents_mocker = request_mocker.get(
            url=get_mocked_url(app="detect", subtype="incidents", limit=1000),
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
