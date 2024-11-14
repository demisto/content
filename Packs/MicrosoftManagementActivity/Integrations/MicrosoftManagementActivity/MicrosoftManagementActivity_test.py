from CommonServerPython import *
import pytest
from datetime import datetime, timedelta
from freezegun import freeze_time

''' MOCK DATA AND RESPONSES '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%S'

TIME_ONE_MINUTE_AGO_DATETIME = datetime.now() - timedelta(minutes=1)
TIME_ONE_MINUTE_AGO_STRING = datetime.strftime(TIME_ONE_MINUTE_AGO_DATETIME, DATE_FORMAT)

TIME_ONE_HOUR_AGO = datetime.now() - timedelta(hours=1)
TIME_ONE_HOUR_AGO_STRING = datetime.strftime(TIME_ONE_HOUR_AGO, DATE_FORMAT)

TIME_6_HOURS_AGO = datetime.now() - timedelta(hours=6)
TIME_6_HOURS_AGO_STRING = datetime.strftime(TIME_6_HOURS_AGO, DATE_FORMAT)

TIME_12_HOURS_AGO = datetime.now() - timedelta(hours=12)
TIME_12_HOURS_AGO_STRING = datetime.strftime(TIME_12_HOURS_AGO, DATE_FORMAT)

TIME_24_HOURS_AGO = datetime.now() - timedelta(hours=24)
TIME_24_HOURS_AGO_STRING = datetime.strftime(TIME_24_HOURS_AGO, DATE_FORMAT)

TIME_48_HOURS_AGO = datetime.now() - timedelta(hours=48)
TIME_48_HOURS_AGO_STRING = datetime.strftime(TIME_48_HOURS_AGO, DATE_FORMAT)

TEST_FETCH_FIRST_RUN = ({}, TIME_12_HOURS_AGO, 720, 710)
TEST_FETCH_FIRST_RUN_WITH_DELTA_OVER_24_HOURS = ({}, TIME_48_HOURS_AGO, 2880, 2870)
TEST_FETCH_NOT_FIRST_RUN = ({'last_fetch': TIME_6_HOURS_AGO_STRING}, 48, 360, 350)
FETCH_TIMES_TEST_DATA = [
    TEST_FETCH_FIRST_RUN,
    TEST_FETCH_FIRST_RUN_WITH_DELTA_OVER_24_HOURS,
    TEST_FETCH_NOT_FIRST_RUN
]

DATE_YESTERDAY_IN_EPOCH = int((datetime.now() - datetime(1970, 1, 1)).total_seconds()) - 24 * 60 * 60
DATE_TOMORROW_IN_EPOCH = int((datetime.now() - datetime(1970, 1, 1)).total_seconds()) + 24 * 60 * 60

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
        "contentCreated": TIME_6_HOURS_AGO_STRING,
    },
    {
        "contentUri": "https://manage.office.com/api/v1.0/test2",
        "contentId": "test2",
        "contentType": "audit.general",
        "contentCreated": TIME_6_HOURS_AGO_STRING,
    },
    {
        "contentUri": "https://manage.office.com/api/v1.0/test3",
        "contentId": "test3",
        "contentType": "audit.general",
        "contentCreated": TIME_6_HOURS_AGO_STRING,
    }
]

LIST_CONTENT_AUDIT_GENERAL_RESPONSE_CONTENT_RECORDS_RESPONSE = [
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
    },
    {
        "CreationTime": "2020-02-27T00:57:40",
        "Id": "567",
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
    },
    {
        "CreationTime": "2020-02-27T00:57:40",
        "Id": "89",
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

LIST_CONTENT_AZUREACTIVE_RESPONSE = [
    {
        "contentUri": "https://manage.office.com/api/v1.0/test4",
        "contentId": "test4",
        "contentType": "Audit.AzureActiveDirectory",
        "contentCreated": TIME_6_HOURS_AGO_STRING,
    },
    {
        "contentUri": "https://manage.office.com/api/v1.0/test5",
        "contentId": "test5",
        "contentType": "Audit.AzureActiveDirectory",
        "contentCreated": TIME_6_HOURS_AGO_STRING,
    },
    {
        "contentUri": "https://manage.office.com/api/v1.0/test6",
        "contentId": "test6",
        "contentType": "Audit.AzureActiveDirectory",
        "contentCreated": TIME_6_HOURS_AGO_STRING,
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
GET_BLOB_DATA_RESPONSE_FOR_AUDIT_GENERAL_SECOND_RESPONSE = [
    {
        "CreationTime": "2020-02-27T00:57:40",
        "Id": "567",
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

GET_BLOB_DATA_RESPONSE_FOR_AUDIT_GENERAL_THIRD_RESPONSE = [
    {
        "CreationTime": "2020-02-27T00:57:40",
        "Id": "89",
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


CONTENT_RECORD_CREATED_ONE_HOUR_AGO = [
    {
        "CreationTime": TIME_ONE_HOUR_AGO_STRING,
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

CONTENT_RECORD_CREATED_48_HOURS_AGO = [
    {
        "CreationTime": TIME_48_HOURS_AGO_STRING,
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

CONTENT_RECORDS_CREATED_1_AND_6_HOURS_AGO = [
    {
        "CreationTime": TIME_ONE_HOUR_AGO_STRING,
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
    },
    {
        "CreationTime": TIME_6_HOURS_AGO_STRING,
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

GET_CONTENT_RECORDS_TEST_DATA = [
    (['audit.general'], LIST_CONTENT_AUDIT_GENERAL_RESPONSE),
    (['audit.AzureActiveDirectory'], LIST_CONTENT_AZUREACTIVE_RESPONSE),
    (['audit.AzureActiveDirectory', 'audit.general'], LIST_CONTENT_AZUREACTIVE_RESPONSE
     + LIST_CONTENT_AUDIT_GENERAL_RESPONSE)]

TEST_LAST_RUN_UPDATE_DATA = [
    ([], datetime.strftime(datetime.now(), DATE_FORMAT)),
    (CONTENT_RECORD_CREATED_48_HOURS_AGO, datetime.strftime(datetime.now(), DATE_FORMAT)),
    (CONTENT_RECORD_CREATED_ONE_HOUR_AGO, TIME_ONE_HOUR_AGO_STRING),
    (CONTENT_RECORDS_CREATED_1_AND_6_HOURS_AGO, TIME_ONE_HOUR_AGO_STRING)
]

GET_ACCESS_TOKEN_RESPONSE = {
    "token_type": "Bearer",
    "scope": "ActivityFeed.Read ActivityFeed.ReadDlp ActivityReports.Read ServiceHealth.Read ThreatIntelligence.Read",
    "expires_in": "3599",
    "ext_expires_in": "3599",
    "expires_on": "1582793586",
    "not_before": "1582789686",
    "resource": "https://manage.office.com",
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                    "eyJ0aWQiOiIxMjM0NTY3ODkwIiwiZXhwIjoxNTgyN"
                    "zkzNTg2fQ.-p8gaG2vG90SHCvrDSratgPv-Bfti4iF2YTZ9AvIeJY",
    "refresh_token": "refresh"
}

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
    expected_time = datetime.now() - timedelta(minutes=expected_time_delta)
    one_minute_before_expected_time = expected_time - timedelta(minutes=1)
    return one_minute_before_expected_time <= actual_time <= expected_time


def are_dates_approximately_equal(date_a, date_b):
    date_a_datetime = datetime.strptime(date_a, DATE_FORMAT)
    date_b_datetime = datetime.strptime(date_b, DATE_FORMAT)

    one_minute_before_date_a = date_a_datetime - timedelta(minutes=1)
    one_minute_before_date_b = date_b_datetime - timedelta(minutes=1)

    date_a_is_almost_date_b = one_minute_before_date_b <= date_a_datetime <= date_b_datetime
    date_b_is_almost_date_a = one_minute_before_date_a <= date_b_datetime <= date_a_datetime

    return date_a_is_almost_date_b or date_b_is_almost_date_a


def http_return_data(method, url_suffix, full_url, headers, json_data):
    return json_data


def create_client(timeout: int = 15):
    from MicrosoftManagementActivity import Client
    base_url = 'https://manage.office.com/api/v1.0/'
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)

    client = Client(base_url, verify=verify_certificate, proxy=proxy, self_deployed=True, auth_and_token_url="test",
                    refresh_token="test", enc_key="test", auth_code="test", tenant_id="test", redirect_uri="",
                    timeout=timeout)

    return client


''' TESTS '''


@pytest.mark.parametrize('last_run, first_fetch_delta, expected_start_time_'
                         'in_hours_from_now, expected_end_time_in_hours_from_now', FETCH_TIMES_TEST_DATA)
def test_fetch_times_range(last_run, first_fetch_delta, expected_start_time_in_hours_from_now,
                           expected_end_time_in_hours_from_now):
    from MicrosoftManagementActivity import get_fetch_start_and_end_time
    fetch_start_time_str, fetch_end_time_str = get_fetch_start_and_end_time(last_run, first_fetch_delta)

    end_time_datetime = datetime.strptime(fetch_end_time_str, DATE_FORMAT)
    assert is_time_in_expected_delta(end_time_datetime, expected_end_time_in_hours_from_now)

    start_time_datetime = datetime.strptime(fetch_start_time_str, DATE_FORMAT)
    assert is_time_in_expected_delta(start_time_datetime, expected_start_time_in_hours_from_now)


TEST_NO_SUBSCRIPTIONS_SPECIFIED = ({}, ["audit.general", "Audit.AzureActiveDirectory"])
TEST_SUBSCRIPTIONS_SPECIFIED = ({"content_types_to_fetch": ["audit.general"]}, ["audit.general"])


@pytest.mark.parametrize('demisto_params, expected_output', [TEST_NO_SUBSCRIPTIONS_SPECIFIED,
                                                             TEST_SUBSCRIPTIONS_SPECIFIED])
def test_get_content_types_to_fetch(mocker, requests_mock, demisto_params, expected_output):
    from MicrosoftManagementActivity import get_content_types_to_fetch
    client = create_client()
    set_requests_mock(client, requests_mock)
    mocker.patch.object(demisto, 'params', return_value=demisto_params)

    assert set(get_content_types_to_fetch(client)) == set(expected_output)


def test_content_records_to_incidents_records_creation():
    from MicrosoftManagementActivity import content_records_to_incidents
    time_now_string = datetime.strftime(datetime.now(), DATE_FORMAT)
    incidents, latest_creation_time = content_records_to_incidents(GET_BLOB_DATA_RESPONSE_FOR_AUDIT_GENERAL,
                                                                   TIME_6_HOURS_AGO_STRING, time_now_string)
    single_incident = incidents[0]
    assert 'name' in single_incident
    assert single_incident['name'] == 'Microsoft Management Activity: 1234'
    assert 'occurred' in single_incident
    assert single_incident['occurred'] == '2020-02-27T00:57:40Z'


@pytest.mark.parametrize('content_records, expected_last_run', TEST_LAST_RUN_UPDATE_DATA)
def test_content_records_to_incidents_last_run(content_records, expected_last_run):
    from MicrosoftManagementActivity import content_records_to_incidents
    time_now_string = datetime.strftime(datetime.now(), DATE_FORMAT)
    end_time = time_now_string

    time_24_hours_ago = datetime.now() - timedelta(hours=24)
    time_24_hours_ago_string = datetime.strftime(time_24_hours_ago, DATE_FORMAT)
    start_time = time_24_hours_ago_string

    _, last_run = content_records_to_incidents(content_records, start_time, end_time)
    assert are_dates_approximately_equal(last_run, expected_last_run)


def test_fetch_incidents_flow(mocker, requests_mock):
    from MicrosoftManagementActivity import fetch_incidents
    client = create_client()
    set_requests_mock(client, requests_mock)
    demisto_params = {
        "content_types_to_fetch": "audit.general"
    }
    mocker.patch.object(demisto, 'params', return_value=demisto_params)
    last_run = {}
    first_fetch_delta = TIME_24_HOURS_AGO

    next_run, incidents = fetch_incidents(client, last_run, first_fetch_delta)
    incident_names = [incident["name"] for incident in incidents]
    assert incident_names == [
        "Microsoft Management Activity: 1234",
        "Microsoft Management Activity: 1234",
        "Microsoft Management Activity: 1234"
    ]


@pytest.mark.parametrize("command", [("start"), ("stop")])
def test_start_and_stop_subscription(requests_mock, command, ):
    from MicrosoftManagementActivity import start_or_stop_subscription_command
    args = {
        'content_type': 'audit.general'
    }
    client = create_client()
    set_requests_mock(client, requests_mock)
    start_or_stop_subscription_command(client, args, command)

    # This test does not assert anything, it only tests if the command matches the mocked endpoints.


def test_list_subscriptions(requests_mock, ):
    from MicrosoftManagementActivity import list_subscriptions_command
    client = create_client()
    set_requests_mock(client, requests_mock)
    list_subscriptions_command(client)

    # This test does not assert anything, it only tests if the command matches the mocked endpoints.


def test_get_all_content_type_records(requests_mock):
    from MicrosoftManagementActivity import get_all_content_type_records
    client = create_client()
    mock_list_content(requests_mock)

    first_audit_general_blob_uri = "https://manage.office.com/api/v1.0/test1"
    second_audit_general_blob_uri = "https://manage.office.com/api/v1.0/test2"
    third_audit_general_blob_uri = "https://manage.office.com/api/v1.0/test3"

    requests_mock.get(first_audit_general_blob_uri, json=GET_BLOB_DATA_RESPONSE_FOR_AUDIT_GENERAL)
    requests_mock.get(second_audit_general_blob_uri, json=GET_BLOB_DATA_RESPONSE_FOR_AUDIT_GENERAL_SECOND_RESPONSE)
    requests_mock.get(third_audit_general_blob_uri, json=GET_BLOB_DATA_RESPONSE_FOR_AUDIT_GENERAL_THIRD_RESPONSE)

    content_records = get_all_content_type_records(client, "audit.general", TIME_24_HOURS_AGO, TIME_ONE_MINUTE_AGO_STRING)
    content_record_ids = [record['Id'] for record in content_records]
    assert set(content_record_ids) == {"1234", "567", "89"}


def mock_get_access_token(requests_mock, access_token_resp):
    requests_mock.post('https://login.windows.net/common/oauth2/token', json=access_token_resp)


def mock_start_subscription(requests_mock, client, start_subscription_resp):
    start_subscription_endpoint = 'https://manage.office.com/api/v1.0/{}/activity/feed/subscriptions/' \
                                  'start'.format(client.tenant_id)
    requests_mock.post(start_subscription_endpoint, json=start_subscription_resp)


def mock_stop_subscription(requests_mock, client):
    stop_subscription_endpoint = 'https://manage.office.com/api/v1.0/{}/activity/feed/subscriptions/' \
                                 'stop'.format(client.tenant_id)
    requests_mock.post(stop_subscription_endpoint, json={})


def mock_list_subscriptions(requests_mock, client, list_subscriptions_resp):
    list_subscriptions_endpoint = 'https://manage.office.com/api/v1.0/{}/activity/feed/subscriptions/list'.format(
        client.tenant_id)
    requests_mock.get(list_subscriptions_endpoint, json=list_subscriptions_resp)


def mock_list_content(requests_mock):
    list_audit_general_content_endpoint = "https://manage.office.com/api/v1.0/test/activity/feed/subscriptions" \
                                          "/content?contentType=audit.general"
    requests_mock.get(list_audit_general_content_endpoint, json=LIST_CONTENT_AUDIT_GENERAL_RESPONSE)
    list_audit_general_content_endpoint = "https://manage.office.com/api/v1.0/test/activity/feed/subscriptions" \
                                          "/content?contentType=audit.AzureActiveDirectory"
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


@pytest.mark.parametrize('args_timeout,param_timeout,expected_timeout', ((0, 0, 15),
                                                                         (None, None, 15),
                                                                         (1, None, 1),
                                                                         (1, 0, 1),
                                                                         (None, 2, 2),
                                                                         (0, 2, 2),
                                                                         (3, 0, 3),
                                                                         (3, 4, 3)))
def test_timeout(args_timeout, param_timeout, expected_timeout):
    """
    Given
            args and params, both of which may contain `timeout`
    When
            running get_timeout
    Then
            validate the output of get_timeout matches the logic, based on availability:
             use arg, then param, then default.
             Validate the Client and its MSClient get the expected value
    """
    from MicrosoftManagementActivity import calculate_timeout_value
    timeout = calculate_timeout_value(params={'timeout': param_timeout}, args={'timeout': args_timeout})
    assert timeout == expected_timeout
    client = create_client(timeout=timeout)
    assert client.timeout == expected_timeout
    assert client.ms_client.timeout == expected_timeout


@pytest.mark.parametrize(argnames='client_id', argvalues=['test_client_id', None])
def test_test_module_command_with_managed_identities(mocker, requests_mock, client_id):
    """
        Given:
            - Managed Identities client id for authentication.
        When:
            - Calling test_module.
        Then:
            - Ensure the output are as expected.
    """
    from MicrosoftManagementActivity import main, MANAGED_IDENTITIES_TOKEN_URL, Resources, jwt
    import MicrosoftManagementActivity
    import demistomock as demisto

    mock_token = {'access_token': 'test_token', 'expires_in': '86400'}
    get_mock = requests_mock.get(MANAGED_IDENTITIES_TOKEN_URL, json=mock_token)
    client = create_client()

    params = {
        'managed_identities_client_id': {'password': client_id},
        'use_managed_identities': 'True',
    }
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'command', return_value='test-module')
    mocker.patch.object(jwt, 'decode', return_value={'tid': 'test'})
    mocker.patch.object(MicrosoftManagementActivity, 'return_results')
    mocker.patch('MicrosoftApiModule.get_integration_context', return_value={})

    list_subscriptions_endpoint = 'https://manage.office.com/api/v1.0/{}/activity/feed/subscriptions/list'.format(
        client.tenant_id)
    requests_mock.get(list_subscriptions_endpoint, json=LIST_SUBSCRIPTIONS_RESPONSE_NO_SUBSCRIPTIONS)

    main()

    assert 'ok' in MicrosoftManagementActivity.return_results.call_args[0][0]
    qs = get_mock.last_request.qs
    assert qs['resource'] == [Resources.manage_office]
    assert client_id and qs['client_id'] == [client_id] or 'client_id' not in qs


def test_generate_login_url(mocker):
    """
    Given:
        - Self-deployed are true and auth code are the auth flow
    When:
        - Calling function ms-management-activity-generate-login-url
    Then:
        - Ensure the generated url are as expected.
    """
    # prepare
    import demistomock as demisto
    from MicrosoftManagementActivity import main
    import MicrosoftManagementActivity

    redirect_uri = 'redirect_uri'
    tenant_id = 'tenant_id'
    client_id = 'client_id'
    mocked_params = {
        'redirect_uri': redirect_uri,
        'auth_type': 'Authorization Code',
        'self_deployed': 'True',
        'refresh_token': tenant_id,
        'auth_id': client_id,
        'enc_key': 'client_secret',
    }
    mocker.patch.object(demisto, 'params', return_value=mocked_params)
    mocker.patch.object(demisto, 'command', return_value='ms-management-activity-generate-login-url')
    mocker.patch.object(MicrosoftManagementActivity, 'return_results')

    # call
    main()

    # assert
    expected_url = f'[login URL](https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize?' \
                   'response_type=code&scope=offline_access%20https://management.azure.com/.default' \
                   f'&client_id={client_id}&redirect_uri={redirect_uri})'
    res = MicrosoftManagementActivity.return_results.call_args[0][0].readable_output
    assert expected_url in res


@freeze_time('2023-08-09')
def test_fetch_start_time(mocker):
    """
    Given:
        - frozen time set to '2023-08-09'.
    When:
        - calling 'get_fetch_start_and_end_time' with 'last_run' containing 'last_fetch' as '2023-04-02T14:22:49'
         (more than 7 days ago)
    Then:
        - Ensure the 'fetch_start_time_str' is as expected - 7 days ago from the frozen time.
    """
    from MicrosoftManagementActivity import get_fetch_start_and_end_time

    last_run = {'last_fetch': '2023-04-02T14:22:49'}

    mocker.patch('dateparser.parse', return_value=datetime.strptime('2023-08-02T14:22:49', DATE_FORMAT))

    first_fetch_datetime = None
    fetch_start_time_str, fetch_end_time_str = get_fetch_start_and_end_time(last_run, first_fetch_datetime)

    assert fetch_start_time_str == '2023-08-02T14:22:49'
    assert fetch_end_time_str == '2023-08-02T14:32:49'
