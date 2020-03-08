import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import pytest
from datetime import datetime, timedelta
from unittest.mock import mock_open

''' MOCK DATA AND RESPONSES '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%S'

START_SUBSCRIPTION_RESPONSE = {
    "contentType": "Audit.AzureActiveDirectory",
    "status": "enabled",
    "webhook": None
}

LIST_SUBSCRIPTIONS_RESPONSE_MULTIPLE_SUBSCRIPTIONS = [
    {
        "contentType": "Audit.AzureActiveDirectory",
        "status": "enabled",
        "webhook": None
    },
    {
        "contentType": "audit.general",
        "status": "enabled",
        "webhook": None
    }
]

LIST_SUBSCRIPTIONS_RESPONSE_SINGLE_SUBSCRIPTION = [
    {
        "contentType": "audit.general",
        "status": "enabled",
        "webhook": None
    }
]

LIST_SUBSCRIPTIONS_RESPONSE_NO_SUBSCRIPTIONS = []

LIST_CONTENT_AUDIT_GENERAL_RESPONSE = [
    {
        "contentUri": "https://manage.office.com/api/v1.0/test1",
        "contentId": "test1",
        "contentType": "audit.general",
        "contentCreated": "2020-02-27T01:00:18.139Z",
        "contentExpiration": "2020-03-04T07:56:39.063Z"
    },
    {
        "contentUri": "https://manage.office.com/api/v1.0/test2",
        "contentId": "test2",
        "contentType": "audit.general",
        "contentCreated": "2020-02-27T01:00:18.139Z",
        "contentExpiration": "2020-03-04T07:56:39.063Z"
    },
    {
        "contentUri": "https://manage.office.com/api/v1.0/test3",
        "contentId": "test3",
        "contentType": "audit.general",
        "contentCreated": "2020-02-27T01:00:18.139Z",
        "contentExpiration": "2020-03-04T07:56:39.063Z"
    }
]

LIST_CONTENT_AZUREACTIVE_RESPONSE = [
    {
        "contentUri": "https://manage.office.com/api/v1.0/test4",
        "contentId": "test4",
        "contentType": "Audit.AzureActiveDirectory",
        "contentCreated": "2020-02-27T01:00:18.139Z",
        "contentExpiration": "2020-03-04T07:56:39.063Z"
    },
    {
        "contentUri": "https://manage.office.com/api/v1.0/test5",
        "contentId": "test5",
        "contentType": "Audit.AzureActiveDirectory",
        "contentCreated": "2020-02-27T01:00:18.139Z",
        "contentExpiration": "2020-03-04T07:56:39.063Z"
    },
    {
        "contentUri": "https://manage.office.com/api/v1.0/test6",
        "contentId": "test6",
        "contentType": "Audit.AzureActiveDirectory",
        "contentCreated": "2020-02-27T01:00:18.139Z",
        "contentExpiration": "2020-03-04T07:56:39.063Z"
    }
]

LIST_CONTENT_RESPONSE_NO_DATA = []

GET_BLOB_DATA_RESPONSE_FOR_AUDIT_GENERAL = [
    {
        "CreationTime": "2020-02-27T00:57:40",
        "Id": "1234",
        "Operation": "Test",
        "OrganizationId": "Test1234",
        "RecordType": 25,
        "UserKey": "key1234",
        "UserType": 5,
        "Version": 1234,
        "Workload": "MicrosoftTeams",
        "UserId": "Application",
        "CommunicationType": "Team",
        "Members": [
            {
                "DisplayName": "test",
                "Role": 1,
                "UPN": "test@test.onmicrosoft.com"
            }
        ],
        "TeamGuid": "testGuid",
        "ItemName": "TestTeam",
        "TeamName": "TestTeam"
    }
]

GET_BLOB_DATA_RESPONSE_FOR_AUDIT_ACTIVEDIRECTORY = [
    {
        "CreationTime": "2020-02-27T00:57:40",
        "Id": "5678",
        "Operation": "Test",
        "OrganizationId": "Test1234",
        "RecordType": 25,
        "UserKey": "key1234",
        "UserType": 5,
        "Version": 1234,
        "Workload": "MicrosoftTeams",
        "UserId": "Application",
        "CommunicationType": "Team",
        "Members": [
            {
                "DisplayName": "test",
                "Role": 1,
                "UPN": "test@test.onmicrosoft.com"
            }
        ],
        "TeamGuid": "testGuid",
        "ItemName": "TestTeam",
        "TeamName": "TestTeam"
    }
]

TIME_ONE_MINUTE_AGO_DATETIME = datetime.now() - timedelta(minutes=1)
TIME_ONE_MINUTE_AGO_DATETIME = datetime.strftime(TIME_ONE_MINUTE_AGO_DATETIME, DATE_FORMAT)


CONTENT_RECORD_CREATED_ONE_MINUTE_AGO = [
    {
        "CreationTime": TIME_ONE_MINUTE_AGO_DATETIME,
        "Id": "5678",
        "Operation": "Test",
        "OrganizationId": "Test1234",
        "RecordType": 25,
        "UserKey": "key1234",
        "UserType": 5,
        "Version": 1234,
        "Workload": "MicrosoftTeams",
        "UserId": "Application",
        "CommunicationType": "Team",
        "Members": [
            {
                "DisplayName": "test",
                "Role": 1,
                "UPN": "test@test.onmicrosoft.com"
            }
        ],
        "TeamGuid": "testGuid",
        "ItemName": "TestTeam",
        "TeamName": "TestTeam"
    }
]

CONTENT_RECORD_CREATED_ONE_MINUTE_AGO = [
    {
        "CreationTime": TIME_ONE_MINUTE_AGO_DATETIME,
        "Id": "5678",
        "Operation": "Test",
        "OrganizationId": "Test1234",
        "RecordType": 25,
        "UserKey": "key1234",
        "UserType": 5,
        "Version": 1234,
        "Workload": "MicrosoftTeams",
        "UserId": "Application",
        "CommunicationType": "Team",
        "Members": [
            {
                "DisplayName": "test",
                "Role": 1,
                "UPN": "test@test.onmicrosoft.com"
            }
        ],
        "TeamGuid": "testGuid",
        "ItemName": "TestTeam",
        "TeamName": "TestTeam"
    }
]




GET_ACCESS_TOKEN_RESPONSE = {
    "token_type": "Bearer",
    "scope": "ActivityFeed.Read ActivityFeed.ReadDlp ActivityReports.Read ServiceHealth.Read ThreatIntelligence.Read",
    "expires_in": "3599",
    "ext_expires_in": "3599",
    "expires_on": "1582793586",
    "not_before": "1582789686",
    "resource": "https://manage.office.com",
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0aWQiOiIxMjM0NTY3ODkwIiwiZXhwIjoxNTgyNzkzNTg2fQ.-p8gaG2vG90SHCvrDSratgPv-Bfti4iF2YTZ9AvIeJY",
    "refresh_token": "refresh"
}


TIME_6_HOURS_AGO = datetime.now() - timedelta(hours=6)
TIME_6_HOURS_AGO_STRING = datetime.strftime(TIME_6_HOURS_AGO, DATE_FORMAT)
TEST_FETCH_FIRST_RUN = ({},720,12,0)
TEST_FETCH_FIRST_RUN_WITH_DELTA_OVER_24_HOURS = ({},2880,48,24)
TEST_FETCH_NOT_FIRST_RUN = ({'last_fetch': TIME_6_HOURS_AGO_STRING}, 2880,6,0)
FETCH_TIMES_TEST_DATA = [
    TEST_FETCH_FIRST_RUN,
    TEST_FETCH_FIRST_RUN_WITH_DELTA_OVER_24_HOURS,
    TEST_FETCH_NOT_FIRST_RUN
]

DATE_YESTERDAY_IN_EPOCH = int((datetime.now() - datetime(1970, 1, 1)).total_seconds()) - 24 * 60 * 60
DATE_TOMORROW_IN_EPOCH = int((datetime.now() - datetime(1970, 1, 1)).total_seconds()) + 24 * 60 * 60
FIRST_RUN = {}
EXPIRED_TOKEN = {
    'expires_on': str(DATE_YESTERDAY_IN_EPOCH),
    'refresh_token': 'refresh',
    'access_token': 'access'
}
ACTIVE_TOKEN = {
    'expires_on': str(DATE_TOMORROW_IN_EPOCH),
    'refresh_token': 'refresh',
    'access_token': 'access'
}

''' HELPER FUNCTIONS '''


def is_time_in_expected_delta(actual_time, expected_time_delta):
    expected_time = datetime.now() - timedelta(hours=expected_time_delta)
    one_minute_before_expected_time = expected_time - timedelta(minutes=1)
    return one_minute_before_expected_time <= actual_time <= expected_time


def http_return_data(method, url_suffix, full_url, headers, json_data):
    return json_data


def create_client():
    from MicrosoftManagement import Client
    base_url = 'https://manage.office.com/api/v1.0/'
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)

    client = Client(base_url, username='', password='', headers='', verify=verify_certificate, proxy=proxy)

    return client




''' TESTS '''


@pytest.mark.parametrize('integration_context, output', [(FIRST_RUN, "auth_code"), (EXPIRED_TOKEN, "refresh_token"),
                                                         (ACTIVE_TOKEN, "refresh_token")])
def test_get_access_token_request_data(mocker, integration_context, output):
    from MicrosoftManagement import Client
    mocker.patch.object(demisto, 'params', return_value={})
    data_for_request = Client.build_access_token_request_data(integration_context)

    if output == 'auth_code':
        assert 'grant_type' in data_for_request and data_for_request['grant_type'] == 'authorization_code'
        assert 'code' in data_for_request and 'refresh_token' not in data_for_request
    else:
        assert 'grant_type' in data_for_request and data_for_request['grant_type'] == 'refresh_token'
        assert 'refresh_token' in data_for_request and 'code' not in data_for_request


def test_integration_context_update_after_token_request(mocker):
    from MicrosoftManagement import Client
    new_context = Client.create_new_integration_context(GET_ACCESS_TOKEN_RESPONSE)
    assert 'refresh_token' in new_context and new_context['refresh_token'] == "refresh"
    assert 'access_token' in new_context and new_context['access_token'] == "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0aWQiOiIxMjM0NTY3ODkwIiwiZXhwIjoxNTgyNzkzNTg2fQ.-p8gaG2vG90SHCvrDSratgPv-Bfti4iF2YTZ9AvIeJY"
    assert 'expires_on' in new_context and new_context['expires_on'] == "1582793586"


def test_get_access_token_data(requests_mock):
    from MicrosoftManagement import Client
    client = create_client()
    requests_mock.post('https://login.windows.net/common/oauth2/token', json=GET_ACCESS_TOKEN_RESPONSE)
    access_token_jwt, token_data = client.get_access_token_data()
    assert access_token_jwt == "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0aWQiOiIxMjM0NTY3ODkwIiwiZXhwIjoxNTgyNzkzNTg2fQ.-p8gaG2vG90SHCvrDSratgPv-Bfti4iF2YTZ9AvIeJY"
    data = {
        "tid": "1234567890",
        "exp": 1582793586
    }
    assert token_data == data


@pytest.mark.parametrize('last_run, first_fetch_delta, expected_start_time_in_hours_from_now, expected_end_time_in_hours_from_now', FETCH_TIMES_TEST_DATA)
def test_fetch_times_range(last_run, first_fetch_delta, expected_start_time_in_hours_from_now, expected_end_time_in_hours_from_now):
    from MicrosoftManagement import get_fetch_start_and_end_time
    fetch_start_time_str, fetch_end_time_str = get_fetch_start_and_end_time(last_run, first_fetch_delta)

    end_time_datetime = datetime.strptime(fetch_end_time_str, DATE_FORMAT)
    assert is_time_in_expected_delta(end_time_datetime, expected_end_time_in_hours_from_now)

    start_time_datetime = datetime.strptime(fetch_start_time_str, DATE_FORMAT)
    assert is_time_in_expected_delta(start_time_datetime, expected_start_time_in_hours_from_now)


TEST_NO_SUBSCRIPTIONS_SPECIFIED = ({}, ["audit.general", "Audit.AzureActiveDirectory"])
TEST_SUBSCRIPTIONS_SPECIFIED = ({"content_types_to_fetch": ["audit.general"]}, ["audit.general"])

@pytest.mark.parametrize('demisto_params, expected_output', [TEST_NO_SUBSCRIPTIONS_SPECIFIED, TEST_SUBSCRIPTIONS_SPECIFIED])
def test_get_content_types_to_fetch(mocker, requests_mock, demisto_params, expected_output):
    from MicrosoftManagement import Client, get_content_types_to_fetch
    client = create_client()
    set_requests_mock(client, requests_mock)
    mocker.patch.object(demisto, 'params', return_value=demisto_params)

    assert set(get_content_types_to_fetch(client)) == set(expected_output)


GET_CONTENT_RECORDS_TEST_DATA = [
    (['audit.general'], LIST_CONTENT_AUDIT_GENERAL_RESPONSE),
    (['audit.AzureActiveDirectory'], LIST_CONTENT_AZUREACTIVE_RESPONSE),
    (['audit.AzureActiveDirectory', 'audit.general'], LIST_CONTENT_AZUREACTIVE_RESPONSE + LIST_CONTENT_AUDIT_GENERAL_RESPONSE)
]
@pytest.mark.parametrize('content_types, expected_results', GET_CONTENT_RECORDS_TEST_DATA)
def test_get_all_content_records_of_specified_types(requests_mock, content_types, expected_results):
    from MicrosoftManagement import Client, get_all_content_records_of_specified_types
    client = create_client()
    set_requests_mock(client, requests_mock)
    assert get_all_content_records_of_specified_types(client, content_types, None, None)


def test_content_records_to_incidents_records_creation():
    from MicrosoftManagement import content_records_to_incidents
    time_now_string = datetime.strftime(datetime.now(), DATE_FORMAT)
    incidents, latest_creation_time = content_records_to_incidents(GET_BLOB_DATA_RESPONSE_FOR_AUDIT_GENERAL,TIME_6_HOURS_AGO_STRING, time_now_string)
    single_incident = incidents[0]
    assert 'name' in single_incident and single_incident['name'] == "1234"
    assert 'occurred' in single_incident and single_incident['occurred'] == '2020-02-27T00:57:40'


@pytest.mark.parametrize()
def test_content_records_to_incidents_last_run():
    from MicrosoftManagement import content_records_to_incidents
    time_now_string = datetime.strftime(datetime.now(), DATE_FORMAT)
    _, latest_creation_time = content_records_to_incidents(GET_BLOB_DATA_RESPONSE_FOR_AUDIT_GENERAL,
                                                           TIME_6_HOURS_AGO_STRING, time_now_string)

























































































def mock_get_access_token(requests_mock, access_token_resp):
    requests_mock.post('https://login.windows.net/common/oauth2/token', json=access_token_resp)


def mock_start_subscription(requests_mock, client,  start_subscription_resp):
    start_subscription_endpoint = 'https://manage.office.com/api/v1.0/{}/activity/feed/subscriptions/start'.format(client.tenant_id)
    requests_mock.post(start_subscription_endpoint, json=start_subscription_resp)


def mock_stop_subscription(requests_mock, client):
    stop_subscription_endpoint = 'https://manage.office.com/api/v1.0/{}/activity/feed/subscriptions/stop'.format(client.tenant_id)
    requests_mock.post(stop_subscription_endpoint, json={})


def mock_list_subscriptions(requests_mock, client, list_subscriptions_resp):
    list_subscriptions_endpoint = 'https://manage.office.com/api/v1.0/{}/activity/feed/subscriptions/list'.format(
        client.tenant_id)
    requests_mock.get(list_subscriptions_endpoint, json=list_subscriptions_resp)


def mock_list_content(requests_mock):
    list_audit_general_content_endpoint = "https://manage.office.com/api/v1.0/None/activity/feed/subscriptions/content?contentType=audit.general"
    requests_mock.get(list_audit_general_content_endpoint, json=LIST_CONTENT_AUDIT_GENERAL_RESPONSE)
    list_audit_general_content_endpoint = "https://manage.office.com/api/v1.0/None/activity/feed/subscriptions/content?contentType=audit.AzureActiveDirectory"
    requests_mock.get(list_audit_general_content_endpoint, json=LIST_CONTENT_AZUREACTIVE_RESPONSE)


def mock_get_blob_data(requests_mock):
    test_blob_uri = "https://manage.office.com/api/v1.0/test{}"
    for i in range(1, 7):
        current_endpoint = test_blob_uri.format(i)
        if i < 4:
            # It is part of the audit.general test data
            requests_mock.get(current_endpoint, json=GET_BLOB_DATA_RESPONSE_FOR_AUDIT_GENERAL)
        else:
            requests_mock.get(current_endpoint, json=GET_BLOB_DATA_RESPONSE_FOR_AUDIT_ACTIVEDIRECTORY)


def set_requests_mock(client, requests_mock, access_token_resp=GET_ACCESS_TOKEN_RESPONSE,
                      start_subscription_resp=START_SUBSCRIPTION_RESPONSE,
                      list_subscriptions_resp=LIST_SUBSCRIPTIONS_RESPONSE_MULTIPLE_SUBSCRIPTIONS):
    mock_get_access_token(requests_mock, access_token_resp)
    mock_start_subscription(requests_mock, client, start_subscription_resp)
    mock_stop_subscription(requests_mock, client)
    mock_list_subscriptions(requests_mock, client, list_subscriptions_resp)
    mock_list_content(requests_mock)
    mock_get_blob_data(requests_mock)







