import json

import pytest
from incydr import Client as incydrClient
from Code42 import (
    create_client,
    Code42Client,
    Code42LegalHoldMatterNotFoundError,
    Code42InvalidLegalHoldMembershipError,
    alert_get_command,
    alert_update_state_command,
    user_create_command,
    user_block_command,
    user_unblock_command,
    user_deactivate_command,
    user_reactivate_command,
    update_user_risk_profile,
    get_user_risk_profile,
    legal_hold_add_user_command,
    legal_hold_remove_user_command,
    list_watchlists_command,
    list_watchlists_included_users,
    add_user_to_watchlist_command,
    remove_user_from_watchlist_command,
    download_file_command,
    download_file_by_xfc_id_command,
    fetch_incidents,
    Code42AlertNotFoundError,
    Code42UserNotFoundError,
    Code42UnsupportedHashError,
    Code42MissingSearchArgumentsError,
    Code42FileDownloadError,
    file_events_search_command,
    file_events_to_table_command,
    run_command,
)
from _incydr_sdk.file_events.models.response import FileEventsPage
from _incydr_sdk.sessions.models.response import Session
from _incydr_sdk.actors.models import Actor
from _incydr_sdk.alert_rules.models.response import RuleDetails
from _incydr_sdk.users.models import User
from _incydr_sdk.watchlists.models.responses import WatchlistsPage
from _incydr_sdk.watchlists.models.responses import WatchlistActor
from _incydr_sdk.legal_hold.models import AddCustodianResponse, MattersPage
from incydr import EventQuery
from requests import Response, HTTPError
import time

MOCK_API_URL = "https://api.us.code42.com"

MOCK_AUTH = ("123", "123")

MOCK_FETCH_TIME = "24 hours"


MOCK_CODE42_EVENT_CONTEXT = [
    {
        "ApplicationTabURL": "example.com",
        "DevicePrivateIPAddress": ["255.255.255.255", "127.0.0.1"],
        "DeviceUsername": "test@example.com",
        "EndpointID": "935873453596901068",
        "EventID": "0_1d71796f-af5b-4231-9d8e-df6434da4663_935873453596901068_956171635867906205_5",
        "EventTimestamp": "2020-05-28T12:46:39.838Z",
        "EventType": "READ_BY_APP",
        "Exposure": ["ApplicationRead"],
        "FileCategory": "IMAGE",
        "FileCreated": "2020-05-28T12:43:34.902Z",
        "FileHostname": "HOSTNAME",
        "FileMD5": "9cea266b4e07974df1982ae3b9de92ce",
        "FileModified": "2020-05-28T12:43:35.105Z",
        "FileName": "company_secrets.txt",
        "FileOwner": "Test",
        "FilePath": "C:/Users/QA/Downloads/",
        "FileSHA256": "34d0c9fc9c907ec374cf7e8ca1ff8a172e36eccee687f0a9b69dd169debb81e1",
        "FileSize": 265122,
        "ProcessName": "chrome.exe",
        "ProcessOwner": "QA",
        "Source": "Endpoint",
        "WindowTitle": ["Jira"],
    },
    {
        "ApplicationTabURL": "example.com/test",
        "DevicePrivateIPAddress": ["127.0.0.1"],
        "DeviceUsername": "test@example.com",
        "EndpointID": "935873453596901068",
        "EventID": "0_1d71796f-af5b-4231-9d8e-df6434da4663_935873453596901068_956171635867906205_5",
        "EventTimestamp": "2020-05-28T12:46:39.838Z",
        "EventType": "READ_BY_APP",
        "Exposure": ["ApplicationRead"],
        "FileCategory": "IMAGE",
        "FileCreated": "2020-05-28T12:43:34.902Z",
        "FileHostname": "TEST'S MAC",
        "FileMD5": "9cea266b4e07974df1982ae3b9de92ce",
        "FileModified": "2020-05-28T12:43:35.105Z",
        "FileName": "data.jpg",
        "FileOwner": "QA",
        "FilePath": "C:/Users/QA/Downloads/",
        "FileSHA256": "34d0c9fc9c907ec374cf7e8ca1ff8a172e36eccee687f0a9b69dd169debb81e1",
        "FileSize": 265122,
        "ProcessName": "chrome.exe",
        "ProcessOwner": "QA",
        "Source": "Endpoint",
        "WindowTitle": ["Jira"],
    },
    {
        "ApplicationTabURL": "example.com/foo",
        "DevicePrivateIPAddress": ["0:0:0:0:0:0:0:1", "127.0.0.1"],
        "DeviceUsername": "test@example.com",
        "EndpointID": "935873453596901068",
        "EventID": "0_1d71796f-af5b-4231-9d8e-df6434da4663_935873453596901068_956171635867906205_5",
        "EventTimestamp": "2020-05-28T12:46:39.838Z",
        "EventType": "READ_BY_APP",
        "Exposure": ["ApplicationRead"],
        "FileCategory": "IMAGE",
        "FileCreated": "2020-05-28T12:43:34.902Z",
        "FileHostname": "Test's Windows",
        "FileMD5": "9cea266b4e07974df1982ae3b9de92ce",
        "FileModified": "2020-05-28T12:43:35.105Z",
        "FileName": "confidential.pdf",
        "FileOwner": "Mock",
        "FilePath": "C:/Users/QA/Downloads/",
        "FileSHA256": "34d0c9fc9c907ec374cf7e8ca1ff8a172e36eccee687f0a9b69dd169debb81e1",
        "FileSize": 265122,
        "ProcessName": "chrome.exe",
        "ProcessOwner": "QA",
        "Source": "Endpoint",
        "WindowTitle": ["Jira"],
    },
]

MOCK_FILE_CONTEXT = [
    {
        "Hostname": "HOSTNAME",
        "MD5": "9cea266b4e07974df1982ae3b9de92ce",
        "Name": "company_secrets.txt",
        "Path": "C:/Users/QA/Downloads/",
        "SHA256": "34d0c9fc9c907ec374cf7e8ca1ff8a172e36eccee687f0a9b69dd169debb81e1",
        "Size": 265122,
    },
    {
        "Hostname": "TEST'S MAC",
        "MD5": "9cea266b4e07974df1982ae3b9de92ce",
        "Name": "data.jpg",
        "Path": "C:/Users/QA/Downloads/",
        "SHA256": "34d0c9fc9c907ec374cf7e8ca1ff8a172e36eccee687f0a9b69dd169debb81e1",
        "Size": 265122,
    },
    {
        "Hostname": "Test's Windows",
        "MD5": "9cea266b4e07974df1982ae3b9de92ce",
        "Name": "confidential.pdf",
        "Path": "C:/Users/QA/Downloads/",
        "SHA256": "34d0c9fc9c907ec374cf7e8ca1ff8a172e36eccee687f0a9b69dd169debb81e1",
        "Size": 265122,
    },
]

with open("test_data/alert_response.json") as f:
    MOCK_ALERTS_RESPONSE = f.read()

with open("test_data/alert_aggregate_response.json") as f:
    MOCK_ALERT_AGGREGATE_RESPONSE = f.read()

with open("test_data/alert_details_response.json") as f:
    MOCK_ALERT_DETAILS_RESPONSE = f.read()


MOCK_V2_FILE_EVENTS_RESPONSE = FileEventsPage.parse_file("test_data/v2_file_event_response.json")

MOCK_SESSION_RESPONSE = Session.parse_file("test_data/session_response.json")

MOCK_SESSION_RESPONSE_2 = Session.parse_file("test_data/session_response_2.json")

MOCK_SESSION_RESPONSE_3 = Session.parse_file("test_data/session_response_3.json")

MOCK_ACTOR_RESPONSE = Actor.parse_file("test_data/actor_response.json")

MOCK_RULE_RESPONSE = RuleDetails.parse_file("test_data/rule_response.json")

MOCK_USER_RISK_PROFILE_RESPONSE = Actor.parse_file("test_data/risk_profile_response.json")

MOCK_CODE42_ALERT_CONTEXT = [
    {
        "ID": "sessionid-abc-1",
        "Name": "document file(s) shared via link from corporate Box",
        "Description": "example rule name",
        "Occurred": "2024-09-11T19:26:00.680000+00:00",
        "Severity": "MODERATE",
        "State": "OPEN",
        "Username": "someactor@domain.com",
    },
    {
        "ID": "18ac641d-7d9c-4d37-a48f-c89396c07d03",
        "Name": "High-Risk Employee Alert",
        "Description": "Cortex XSOAR is 2cool.",
        "Occurred": "2019-10-02T17:02:24.2071980Z",
        "Severity": "MODERATE",
        "State": "OPEN",
        "Type": "FED_CLOUD_SHARE_PERMISSIONS",
        "Username": "user2@example.com",
    },
    {
        "ID": "3137ff1b-b824-42e4-a476-22bccdd8ddb8",
        "Name": "Custom Alert 1",
        "Description": "Cortex XSOAR is 3cool.",
        "Occurred": "2019-10-02T17:03:28.2885720Z",
        "Severity": "LOW",
        "State": "OPEN",
        "Type": "FED_ENDPOINT_EXFILTRATION",
        "Username": "user3@example.com",
    },
]

MOCK_WATCHLISTS_RESPONSE = WatchlistsPage.parse_raw("""
{
    "watchlists": [
        {
            "listType": "DEPARTING_EMPLOYEE",
            "watchlistId": "b55978d5-2d50-494d-bec9-678867f3830c",
            "tenantId": "1d71796f-af5b-4231-9d8e-df6434da4663",
            "stats": {
                "includedUsersCount": 3
            }
        },
        {
            "listType": "SUSPICIOUS_SYSTEM_ACTIVITY",
            "watchlistId": "2870bd73-ce1f-4704-a7f7-a8d11b19908e",
            "tenantId": "1d71796f-af5b-4231-9d8e-df6434da4663",
            "stats": {
                "includedUsersCount": 11
            }
        },
        {
            "listType": "FLIGHT_RISK",
            "watchlistId": "d2abb9f2-8c27-4f95-b7e2-252f191a4a1d",
            "tenantId": "1d71796f-af5b-4231-9d8e-df6434da4663",
            "stats": {
                "includedUsersCount": 4
            }
        },
        {
            "listType": "PERFORMANCE_CONCERNS",
            "watchlistId": "a21b2bbb-ed16-42eb-9983-32076ba417c0",
            "tenantId": "1d71796f-af5b-4231-9d8e-df6434da4663",
            "stats": {
                "includedUsersCount": 3
            }
        },
        {
            "listType": "CONTRACT_EMPLOYEE",
            "watchlistId": "c9557acf-4141-4162-b767-c129d3e668d4",
            "tenantId": "1d71796f-af5b-4231-9d8e-df6434da4663",
            "stats": {
                "includedUsersCount": 2
            }
        },
        {
            "listType": "HIGH_IMPACT_EMPLOYEE",
            "watchlistId": "313c388e-4c63-4071-a6fc-d6270e04c350",
            "tenantId": "1d71796f-af5b-4231-9d8e-df6434da4663",
            "stats": {
                "includedUsersCount": 4
            }
        },
        {
            "listType": "ELEVATED_ACCESS_PRIVILEGES",
            "watchlistId": "b49c938f-8f13-45e4-be17-fa88eca616ec",
            "tenantId": "1d71796f-af5b-4231-9d8e-df6434da4663",
            "stats": {
                "includedUsersCount": 3
            }
        },
        {
            "listType": "POOR_SECURITY_PRACTICES",
            "watchlistId": "534fa6a4-4b4c-4712-9b37-2f81c652c140",
            "tenantId": "1d71796f-af5b-4231-9d8e-df6434da4663",
            "stats": {
                "includedUsersCount": 2
            }
        },
        {
            "listType": "NEW_EMPLOYEE",
            "watchlistId": "5a39abda-c672-418a-82a0-54485bd59b7b",
            "tenantId": "1d71796f-af5b-4231-9d8e-df6434da4663",
            "stats": {}
        }
    ],
    "totalCount": 9
}""")

MOCK_WATCHLISTS_INCLUDED_USERS_RESPONSE = [
    WatchlistActor.parse_obj(
        {"actorId": "921286907298179098", "actorname": "user_a@example.com", "addedTime": "2022-02-26T18:41:45.766005"}
    ),
    WatchlistActor.parse_obj(
        {"actorId": "990572034162882387", "actorname": "user_b@example.com", "addedTime": "2022-03-31T20:41:47.2985"}
    ),
    WatchlistActor.parse_obj(
        {"actorId": "987210998131391466", "actorname": "user_c@example.com", "addedTime": "2022-03-31T14:43:48.059325"}
    ),
]


MOCK_ADD_TO_MATTER_RESPONSE = AddCustodianResponse.parse_raw("""{
    "membershipActive":true,
    "membershipCreationDate":"2015-05-16T15:07:44.820-05:00",
    "matter":{
      "matterId":"645576513911664484",
      "name":"Patent Lawsuit"
    },
    "custodian":{
      "user_id":"123412341234123412",
      "username":"user1@example.com",
      "email":"user1@example.com"
    }
}""")

MOCK_GET_ALL_MATTERS_RESPONSE = MattersPage.parse_raw("""
{
    "matters":[
      {
        "matterId":"645576513911664484",
        "name":"Patent Lawsuit",
        "description":"Lawsuit from Acme Inc demanding we license their software patents.",
        "notes":"Engineering is still reviewing what, if any, of our components are actually infringing.",
        "active":true,
        "creationDate":"2015-05-16T15:07:44.820-05:00",
        "lastModified":"2015-05-16T15:07:44.820-05:00",
        "policyId":"23456753135798456",
        "creator":{
          "userId":"123412341234123412",
          "username":"user1@example.com"
          },
        "creatorPrincipal": {
          "type": "user",
          "principalId": "123412341234123412",
          "displayName": "user1@example.com"
        }
      }
    ]
}
""")


_TEST_USER_ID = "123412341234123412"  # value found in GET_USER_RESPONSE
_TEST_USERNAME = "user1@example.com"
_TEST_ORG_NAME = "TestCortexOrg"


@pytest.fixture
def incydr_sdk_mock(mocker):
    incydr_mock = mocker.MagicMock(spec=incydrClient)
    return incydr_mock


@pytest.fixture
def incydr_sessions_mock(incydr_sdk_mock, mocker):
    return create_sessions_mock(incydr_sdk_mock, mocker)


@pytest.fixture
def incydr_file_events_mock(incydr_sdk_mock, mocker):
    return create_file_events_mock(incydr_sdk_mock, mocker)


@pytest.fixture
def incydr_users_mock(incydr_sdk_mock, mocker):
    user = User()
    user.user_id = 123456
    incydr_sdk_mock.users.v1.get_user.return_value = user
    incydr_sdk_mock.users.v1.deactivate.return_value = ""
    incydr_sdk_mock.users.v1.activate.return_value = ""
    return incydr_sdk_mock


@pytest.fixture
def code42_user_risk_profile_mock(incydr_sdk_mock, mocker):
    risk_profile_response = MOCK_USER_RISK_PROFILE_RESPONSE
    incydr_sdk_mock.actors.v1.get_actor_by_name.return_value = risk_profile_response
    incydr_sdk_mock.actors.v1.get_actor_by_id.return_value = risk_profile_response
    incydr_sdk_mock.actors.v1.update_actor.return_value = risk_profile_response
    return incydr_sdk_mock


def create_sessions_mock(incydr_sdk_mock, mocker):
    incydr_sdk_mock.sessions.v1.get_session_details.return_value = MOCK_SESSION_RESPONSE
    incydr_sdk_mock.actors.v1.get_actor_by_id.return_value = MOCK_ACTOR_RESPONSE
    incydr_sdk_mock.alert_rules.v2.get_rule.return_value = MOCK_RULE_RESPONSE
    incydr_sdk_mock.sessions.v1.get_session_events.return_value = MOCK_V2_FILE_EVENTS_RESPONSE
    incydr_sdk_mock.sessions.v1.iter_all.return_value = iter(
        [MOCK_SESSION_RESPONSE, MOCK_SESSION_RESPONSE_2, MOCK_SESSION_RESPONSE_3]
    )
    return incydr_sdk_mock


def create_file_events_mock(incydr_sdk_mock, mocker):
    incydr_sdk_mock.file_events.v2.search.return_value = MOCK_V2_FILE_EVENTS_RESPONSE
    return incydr_sdk_mock


@pytest.fixture
def incydr_watchlists_mock(incydr_sdk_mock, mocker):
    incydr_sdk_mock.watchlists.v2.iter_all.return_value = list_to_generator(MOCK_WATCHLISTS_RESPONSE.watchlists)
    return incydr_sdk_mock


@pytest.fixture
def incydr_watchlists_included_users_mock(incydr_sdk_mock, mocker):
    incydr_sdk_mock.watchlists.v2.iter_all_members.return_value = list_to_generator(MOCK_WATCHLISTS_INCLUDED_USERS_RESPONSE)
    return incydr_sdk_mock


@pytest.fixture
def incydr_legal_hold_mock(incydr_sdk_mock, mocker):
    incydr_sdk_mock.users.v1.get_user.return_value = User(userId=_TEST_USER_ID)
    incydr_sdk_mock.legal_hold.v1.get_matters_page.return_value = MOCK_GET_ALL_MATTERS_RESPONSE
    incydr_sdk_mock.legal_hold.v1.add_custodian.return_value = MOCK_ADD_TO_MATTER_RESPONSE
    incydr_sdk_mock.legal_hold.v1.remove_custodian.return_value = ""
    return incydr_sdk_mock


def list_to_generator(list):
    yield from list


def create_mock_requests_response(mocker, response_text):
    response_mock = mocker.MagicMock(spec=Response)
    response_mock.text = response_text
    response_mock.status_code = 200
    response_mock._content_consumed = False
    return response_mock


def _create_incydr_client(sdk):
    return Code42Client(incydr_sdk=sdk, auth=MOCK_AUTH, api_url=MOCK_API_URL, verify=False, proxy=False)


"""TESTS"""


def test_run_command_returns_results(mocker):
    mock_returner = mocker.patch("Code42.return_results")

    def test_command():
        return ["result"]

    run_command(test_command)
    mock_returner.assert_called_once_with("result")


def test_run_command_returns_error(mocker):
    mock_returner = mocker.patch("Code42.return_error")

    def test_command():
        raise Exception

    run_command(test_command)

    mock_returner.assert_called_once()


def test_run_command_forces_array(mocker):
    mock_returner = mocker.patch("Code42.return_results")

    def test_command():
        return "result"

    run_command(test_command)
    mock_returner.assert_called_once_with("result")


def test_client_lazily_inits_sdk(mocker, incydr_sdk_mock):
    sdk_factory_mock = mocker.patch("incydr.Client")
    response_json_mock = """{"total": 1, "users": [{"username": "Test"}]}"""
    incydr_sdk_mock.users.v1.get.return_value = create_mock_requests_response(mocker, response_json_mock)
    sdk_factory_mock.return_value = incydr_sdk_mock

    # test that sdk does not init during ctor
    client = Code42Client(auth=MOCK_AUTH, api_url=MOCK_API_URL, verify=False, proxy=False)
    assert client._incydr_sdk is None

    # test that sdk init from first method call
    client.get_user("Test")
    assert client._incydr_sdk is not None


def test_client_raises_helpful_error_when_not_given_an_api_client_id(mocker, incydr_sdk_mock):
    mock_demisto = mocker.patch("Code42.demisto")
    mock_demisto.params.return_value = {"credentials": {"identifier": "test@example.com"}}
    with pytest.raises(Exception) as err:
        create_client()

    assert "Got invalid API Client ID" in str(err)


def test_create_client_passes_credential_from_demisto(mocker, incydr_sdk_mock):
    mock_Code42Client = mocker.patch("Code42.Code42Client")
    mock_demisto = mocker.patch("Code42.demisto")
    mock_demisto.params.return_value = {
        "credentials": {"identifier": "key-12345", "password": "1234"},
        "api_url": "https://api.us.code42.com",
        "insecure": False,
        "proxy": False,
    }

    create_client()
    mock_Code42Client.assert_called_once()
    mock_Code42Client.assert_called_with(
        api_url="https://api.us.code42.com",
        auth=("key-12345", "1234"),
        verify=True,
        proxy=False,
    )


def test_client_when_no_alert_found_returns(mocker, incydr_sdk_mock):
    mock_response = mocker.MagicMock(spec=Response)
    mock_response.status_code = 404
    incydr_sdk_mock.sessions.v1.get_session_details.side_effect = HTTPError(response=mock_response)
    client = _create_incydr_client(incydr_sdk_mock)
    with pytest.raises(Code42AlertNotFoundError):
        client.get_alert_details("mock-id")


def test_client_when_no_user_found_raises_user_not_found(mocker, incydr_sdk_mock):
    incydr_sdk_mock.users.v1.get_user.side_effect = ValueError
    client = _create_incydr_client(incydr_sdk_mock)
    with pytest.raises(Code42UserNotFoundError):
        client.get_user("test@example.com")


def test_client_add_to_matter_when_no_legal_hold_matter_found_raises_matter_not_found(incydr_sdk_mock, mocker):
    incydr_sdk_mock.users.v1.get_user.return_value = User(userId="asdf")
    incydr_sdk_mock.legal_hold.v1.get_matters_page.return_value = MattersPage(matters=[])
    client = _create_incydr_client(incydr_sdk_mock)
    with pytest.raises(Code42LegalHoldMatterNotFoundError):
        client.add_user_to_legal_hold_matter("TESTUSERNAME", "TESTMATTERNAME")


def test_client_add_to_matter_when_no_user_found_raises_user_not_found(mocker, incydr_sdk_mock):
    incydr_sdk_mock.users.v1.get_user.side_effect = ValueError
    client = _create_incydr_client(incydr_sdk_mock)
    with pytest.raises(Code42UserNotFoundError):
        client.add_user_to_legal_hold_matter("TESTUSERNAME", "TESTMATTERNAME")


def test_client_remove_from_matter_when_no_legal_hold_matter_found_raises_exception(incydr_sdk_mock, mocker):
    incydr_sdk_mock.users.v1.get_user.return_value = User(userId="asdf")
    incydr_sdk_mock.legal_hold.v1.get_matters_page.return_value = MattersPage(matters=[])
    client = _create_incydr_client(incydr_sdk_mock)
    with pytest.raises(Code42LegalHoldMatterNotFoundError):
        client.remove_user_from_legal_hold_matter("TESTUSERNAME", "TESTMATTERNAME")


def test_client_remove_from_matter_when_no_user_found_raises_user_not_found(mocker, incydr_sdk_mock):
    incydr_sdk_mock.users.v1.get_user.side_effect = ValueError
    client = _create_incydr_client(incydr_sdk_mock)
    with pytest.raises(Code42UserNotFoundError):
        client.remove_user_from_legal_hold_matter("TESTUSERNAME", "TESTMATTERNAME")


def test_client_remove_from_matter_when_no_membership_raises_invalid_legal_hold_membership(incydr_sdk_mock, mocker):
    incydr_sdk_mock.users.v1.get_user.return_value = User(userId="asdf")
    incydr_sdk_mock.legal_hold.v1.get_matters_page.return_value = MOCK_GET_ALL_MATTERS_RESPONSE
    incydr_sdk_mock.legal_hold.v1.remove_custodian.side_effect = HTTPError()
    client = _create_incydr_client(incydr_sdk_mock)
    with pytest.raises(Code42InvalidLegalHoldMembershipError):
        client.remove_user_from_legal_hold_matter("TESTUSERNAME", "TESTMATTERNAME")


def test_alert_get_command(incydr_sessions_mock):
    client = _create_incydr_client(incydr_sessions_mock)
    cmd_res = alert_get_command(client, {"id": "sessionid-abc-1"})
    assert cmd_res.raw_response["sessionId"] == "sessionid-abc-1"
    assert cmd_res.outputs == [MOCK_CODE42_ALERT_CONTEXT[0]]
    assert cmd_res.outputs_prefix == "Code42.SecurityAlert"
    assert cmd_res.outputs_key_field == "ID"


def test_alert_get_command_when_no_alert_found(mocker, incydr_sdk_mock):
    mock_response = mocker.MagicMock(spec=Response)
    mock_response.status_code = 404
    incydr_sdk_mock.sessions.v1.get_session_details.side_effect = HTTPError(response=mock_response)
    client = _create_incydr_client(incydr_sdk_mock)
    cmd_res = alert_get_command(client, {"id": "mock-id"})
    assert cmd_res.readable_output == "No results found"


def test_alert_update_state_command(incydr_sessions_mock):
    client = _create_incydr_client(incydr_sessions_mock)
    cmd_res = alert_update_state_command(client, {"id": "rule-id-abc-1", "state": "OPEN"})
    assert cmd_res.raw_response["sessionId"] == "sessionid-abc-1"
    assert cmd_res.outputs == [MOCK_CODE42_ALERT_CONTEXT[0]]
    assert cmd_res.outputs_prefix == "Code42.SecurityAlert"
    assert cmd_res.outputs_key_field == "ID"


def test_alert_resolve_command(incydr_sessions_mock):
    client = _create_incydr_client(incydr_sessions_mock)
    cmd_res = alert_update_state_command(client, {"id": "rule-id-abc-123"})
    assert cmd_res.raw_response["sessionId"] == "sessionid-abc-1"
    assert cmd_res.outputs == [MOCK_CODE42_ALERT_CONTEXT[0]]
    assert cmd_res.outputs_prefix == "Code42.SecurityAlert"
    assert cmd_res.outputs_key_field == "ID"


def test_legalhold_add_user_command(incydr_legal_hold_mock):
    client = _create_incydr_client(incydr_legal_hold_mock)
    cmd_res = legal_hold_add_user_command(client, {"username": _TEST_USERNAME, "mattername": "Patent Lawsuit"})
    assert cmd_res.raw_response == json.loads(MOCK_ADD_TO_MATTER_RESPONSE.json())
    assert cmd_res.outputs_prefix == "Code42.LegalHold"
    assert cmd_res.outputs_key_field == "MatterID"
    assert cmd_res.outputs["UserID"] == _TEST_USER_ID
    assert cmd_res.outputs["MatterName"] == "Patent Lawsuit"
    assert cmd_res.outputs["MatterID"] == "645576513911664484"
    incydr_legal_hold_mock.legal_hold.v1.add_custodian.assert_called_once_with(
        user_id="123412341234123412", matter_id="645576513911664484"
    )


def test_legalhold_remove_user_command(incydr_legal_hold_mock):
    client = _create_incydr_client(incydr_legal_hold_mock)
    cmd_res = legal_hold_remove_user_command(client, {"username": _TEST_USERNAME, "mattername": "Patent Lawsuit"})
    assert cmd_res.outputs_prefix == "Code42.LegalHold"
    assert cmd_res.outputs_key_field == "MatterID"
    assert cmd_res.outputs["UserID"] == _TEST_USER_ID
    assert cmd_res.outputs["MatterName"] == "Patent Lawsuit"
    assert cmd_res.outputs["MatterID"] == "645576513911664484"
    incydr_legal_hold_mock.legal_hold.v1.remove_custodian.assert_called_once_with(
        user_id=_TEST_USER_ID, matter_id="645576513911664484"
    )


def test_user_create_command(incydr_sdk_mock):
    client = _create_incydr_client(incydr_sdk_mock)
    cmd_res = user_create_command(
        client,
        {
            "orgname": _TEST_ORG_NAME,
            "username": "new.user@example.com",
            "email": "new.user@example.com",
        },
    )
    assert cmd_res.outputs_prefix == "Code42.User"
    assert cmd_res.outputs_key_field == "UserID"
    assert cmd_res.outputs == {}
    assert "Deprecated command - use the Incydr console to create users." in cmd_res.readable_output


def test_user_block_command(incydr_sdk_mock):
    client = _create_incydr_client(incydr_sdk_mock)
    cmd_res = user_block_command(client, {"username": "new.user@example.com"})
    assert cmd_res.outputs_prefix == "Code42.User"
    assert cmd_res.outputs == {}
    assert "Deprecated command - use the Incydr console to block users." in cmd_res.readable_output


def test_user_unblock_command(incydr_sdk_mock):
    client = _create_incydr_client(incydr_sdk_mock)
    cmd_res = user_unblock_command(client, {"username": "new.user@example.com"})
    assert cmd_res.outputs_prefix == "Code42.User"
    assert cmd_res.outputs == {}
    assert "Deprecated command - use the Incydr console to unblock users." in cmd_res.readable_output


def test_user_deactivate_command(incydr_users_mock):
    client = _create_incydr_client(incydr_users_mock)
    cmd_res = user_deactivate_command(client, {"username": "new.user@example.com"})
    assert cmd_res.raw_response == 123456
    assert cmd_res.outputs["UserID"] == 123456
    assert cmd_res.outputs_prefix == "Code42.User"
    incydr_users_mock.users.v1.deactivate.assert_called_once_with(123456)


def test_user_reactivate_command(incydr_users_mock):
    client = _create_incydr_client(incydr_users_mock)
    cmd_res = user_reactivate_command(client, {"username": "new.user@example.com"})
    assert cmd_res.raw_response == 123456
    assert cmd_res.outputs["UserID"] == 123456
    assert cmd_res.outputs_prefix == "Code42.User"
    incydr_users_mock.users.v1.activate.assert_called_once_with(123456)


def test_user_get_risk_profile_command(code42_user_risk_profile_mock):
    client = _create_incydr_client(code42_user_risk_profile_mock)
    cmd_res = get_user_risk_profile(client, args={"username": "profile@example.com"})
    assert cmd_res.raw_response == {
        "EndDate": "2023-10-10",
        "Notes": "test update",
        "StartDate": "2020-10-10",
        "Username": "profile@example.com",
    }
    assert cmd_res.outputs["EndDate"] == "2023-10-10"
    assert cmd_res.outputs_prefix == "Code42.UserRiskProfiles"
    code42_user_risk_profile_mock.actors.v1.get_actor_by_name.assert_called_once_with("profile@example.com", prefer_parent=True)


def test_user_update_risk_profile_command(code42_user_risk_profile_mock):
    client = _create_incydr_client(code42_user_risk_profile_mock)
    cmd_res = update_user_risk_profile(
        client,
        args={
            "username": "profile@example.com",
            "notes": "test update",
            "start_date": "2020-10-10",
            "end_date": "2023-10-10",
        },
    )
    assert cmd_res.raw_response == {
        "EndDate": "2023-10-10",
        "Notes": "test update",
        "StartDate": "2020-10-10",
        "Success": True,
        "Username": "profile@example.com",
    }
    assert cmd_res.outputs["EndDate"] == "2023-10-10"
    assert cmd_res.outputs_prefix == "Code42.UpdatedUserRiskProfiles"
    code42_user_risk_profile_mock.actors.v1.update_actor.assert_called_once_with(
        "e96364db-8557-4c82-a31b-eccc7c8e6754",
        notes="test update",
        start_date="2020-10-10",
        end_date="2023-10-10",
    )


def test_download_file_command_when_given_md5(incydr_file_events_mock, mocker):
    fr = mocker.patch("Code42.fileResult")
    incydr_file_events_mock.files.v1.stream_file_by_sha256.return_value = create_mock_requests_response(mocker, "")
    client = _create_incydr_client(incydr_file_events_mock)
    _ = download_file_command(client, {"hash": "b6312dbe4aa4212da94523ccb28c5c16"})
    incydr_file_events_mock.files.v1.stream_file_by_sha256.assert_called_once_with("testhash")
    assert fr.call_count == 1


def test_download_file_command_when_given_sha256(incydr_sdk_mock, mocker):
    fr = mocker.patch("Code42.fileResult")
    _hash = "41966f10cc59ab466444add08974fde4cd37f88d79321d42da8e4c79b51c2149"
    client = _create_incydr_client(incydr_sdk_mock)
    _ = download_file_command(client, {"hash": _hash})
    incydr_sdk_mock.files.v1.stream_file_by_sha256.assert_called_once_with(
        "41966f10cc59ab466444add08974fde4cd37f88d79321d42da8e4c79b51c2149"
    )
    assert fr.call_count == 1


def test_download_file_when_given_other_hash_raises_unsupported_hash(incydr_sdk_mock, mocker):
    mocker.patch("Code42.fileResult")
    _hash = (
        "41966f10cc59ab466444add08974fde4cd37f88d79321d42da8e4c79b51c214941966f10cc59ab466444add08974fde4cd37"
        "f88d79321d42da8e4c79b51c2149"
    )
    client = _create_incydr_client(incydr_sdk_mock)
    with pytest.raises(Code42UnsupportedHashError):
        _ = download_file_command(client, {"hash": _hash})


def test_download_file_by_xfc_id(incydr_file_events_mock, mocker):
    """
    Scenario: User attempts to download a file using a valid XFC ID.
    Given:
     - User has provided a valid XFC ID.
    When:
     - The command is called with an XFC ID.
    Then:
     - Ensure that the underlying SDK method is called once.
     - Ensure that the underlying SDK method is called with the given XFC ID.
     - Ensure that a fileResult is created.
     - Ensure the XFC ID is used as the returned file's filename.
    """
    fr = mocker.patch("Code42.fileResult")
    incydr_file_events_mock.files.v1.stream_file_by_xfc_content_id.return_value = create_mock_requests_response(mocker, "")
    client = _create_incydr_client(incydr_file_events_mock)
    _ = download_file_by_xfc_id_command(client, {"xfc_id": "b6312dbe4aa4212da94523ccb28c5c16"})
    incydr_file_events_mock.files.v1.stream_file_by_xfc_content_id.assert_called_once_with("b6312dbe4aa4212da94523ccb28c5c16")
    fr.assert_called_once_with("b6312dbe4aa4212da94523ccb28c5c16", data=b"")


def test_download_file_by_xfc_id_raises_exception(incydr_file_events_mock, mocker):
    """
    Scenario: User attempts to download a file using an invalid XFC ID.
    Given:
     - User has provided an invalid XFC ID.
    When:
     - The command is called with an invalid XFC ID.
     - The underlying SDK method raises an exception.
    Then:
     - Ensure that the underlying SDK method is called once.
     - Ensure that the underlying SDK method is called with the given XFC ID.
     - Ensure that a Code42FileDownloadError is raised.
    """
    fr = mocker.patch("Code42.fileResult")
    incydr_file_events_mock.files.v1.stream_file_by_xfc_content_id.side_effect = Exception
    client = _create_incydr_client(incydr_file_events_mock)
    with pytest.raises(Code42FileDownloadError):
        _ = download_file_by_xfc_id_command(client, {"xfc_id": "b6312dbe4aa4212da94523ccb28c5c16"})
        incydr_file_events_mock.files.v1.stream_file_by_xfc_content_id.assert_called_once_with("b6312dbe4aa4212da94523ccb28c5c16")
        assert fr.call_count == 1


def test_list_watchlists_command(incydr_watchlists_mock):
    client = _create_incydr_client(incydr_watchlists_mock)
    cmd_res = list_watchlists_command(client, {})
    expected_response = MOCK_WATCHLISTS_RESPONSE.watchlists
    actual_response = cmd_res.raw_response
    assert cmd_res.outputs_key_field == "WatchlistID"
    assert cmd_res.outputs_prefix == "Code42.Watchlists"
    assert incydr_watchlists_mock.watchlists.v2.iter_all.call_count == 1
    assert len(expected_response) == len(actual_response)
    for i in range(0, len(actual_response)):
        assert actual_response[i]["WatchlistID"] == expected_response[i].watchlist_id
        expected_count = expected_response[i].stats.included_users_count if expected_response[i].stats.included_users_count else 0
        assert actual_response[i]["IncludedUsersCount"] == expected_count


def test_list_watchlists_included_users_calls_by_id_when_watchlist_type_arg_provided_looks_up_watchlist_id(
    incydr_watchlists_included_users_mock,
):
    watchlist_id = "b55978d5-2d50-494d-bec9-678867f3830c"
    incydr_watchlists_included_users_mock.watchlists.v2.get_id_by_name.return_value = watchlist_id
    client = _create_incydr_client(incydr_watchlists_included_users_mock)
    cmd_res = list_watchlists_included_users(client, {"watchlist": "DEPARTING_EMPLOYEE"})
    actual_response = cmd_res.raw_response
    expected_response = MOCK_WATCHLISTS_INCLUDED_USERS_RESPONSE
    incydr_watchlists_included_users_mock.watchlists.v2.iter_all_members.assert_called_once_with(watchlist_id)
    assert cmd_res.outputs_prefix == "Code42.WatchlistUsers"
    assert len(expected_response) == len(actual_response)
    for i in range(0, len(actual_response)):
        assert actual_response[i]["Username"] == expected_response[i].actor_name
        assert actual_response[i]["AddedTime"] == expected_response[i].added_time.isoformat()
        assert actual_response[i]["WatchlistID"] == watchlist_id


def test_add_user_to_watchlist_command_with_UUID_calls_add_by_id_method(incydr_sdk_mock, mocker):
    watchlist_id = "b55978d5-2d50-494d-bec9-678867f3830c"
    actorobj = Actor(actorId="1234")
    incydr_sdk_mock.actors.v1.get_actor_by_name.return_value = actorobj
    incydr_sdk_mock.watchlists.v2.add_included_actors.return_value = ""
    client = _create_incydr_client(incydr_sdk_mock)
    cmd_res = add_user_to_watchlist_command(client, {"watchlist": watchlist_id, "username": "user_a@example.com"})
    incydr_sdk_mock.watchlists.v2.add_included_actors.assert_called_once_with(
        actor_ids=actorobj.actor_id, watchlist_id=watchlist_id
    )
    assert cmd_res.raw_response == {
        "Watchlist": "b55978d5-2d50-494d-bec9-678867f3830c",
        "Username": "user_a@example.com",
        "Success": True,
    }


def test_add_user_to_watchlist_command_with_watchlist_type_looks_up_id(incydr_sdk_mock, mocker):
    watchlist_type = "DEPARTING_EMPLOYEE"
    watchlist_id = "asdf"
    actorobj = Actor(actorId="1234")
    incydr_sdk_mock.actors.v1.get_actor_by_name.return_value = actorobj
    incydr_sdk_mock.watchlists.v2.get_id_by_name.return_value = watchlist_id
    incydr_sdk_mock.watchlists.v2.add_included_actors.return_value = ""
    client = _create_incydr_client(incydr_sdk_mock)
    cmd_res = add_user_to_watchlist_command(client, {"watchlist": watchlist_type, "username": "user_a@example.com"})
    incydr_sdk_mock.watchlists.v2.get_id_by_name.assert_called_once_with(watchlist_type)
    incydr_sdk_mock.watchlists.v2.add_included_actors.assert_called_once_with(
        actor_ids=actorobj.actor_id, watchlist_id=watchlist_id
    )
    assert cmd_res.raw_response == {
        "Watchlist": "DEPARTING_EMPLOYEE",
        "Username": "user_a@example.com",
        "Success": True,
    }


def test_remove_user_from_watchlist_command_with_UUID_calls_add_by_id_method(incydr_sdk_mock, mocker):
    watchlist_id = "b55978d5-2d50-494d-bec9-678867f3830c"
    actorobj = Actor(actorId="1234")
    incydr_sdk_mock.actors.v1.get_actor_by_name.return_value = actorobj
    incydr_sdk_mock.watchlists.v2.remove_included_actors.return_value = ""
    client = _create_incydr_client(incydr_sdk_mock)
    cmd_res = remove_user_from_watchlist_command(client, {"watchlist": watchlist_id, "username": "user_a@example.com"})
    incydr_sdk_mock.watchlists.v2.remove_included_actors.assert_called_once_with(
        watchlist_id=watchlist_id, actor_ids=actorobj.actor_id
    )
    assert cmd_res.raw_response == {
        "Watchlist": "b55978d5-2d50-494d-bec9-678867f3830c",
        "Username": "user_a@example.com",
        "Success": True,
    }


def test_remove_user_from_watchlist_command_with_watchlist_type_gets_watchlist_id(incydr_sdk_mock, mocker):
    watchlist_type = "DEPARTING_EMPLOYEE"
    watchlist_id = "asdf"
    actorobj = Actor(actorId="1234")
    incydr_sdk_mock.actors.v1.get_actor_by_name.return_value = actorobj
    incydr_sdk_mock.watchlists.v2.get_id_by_name.return_value = watchlist_id
    incydr_sdk_mock.watchlists.v2.remove_included_actors.return_value = ""
    client = _create_incydr_client(incydr_sdk_mock)
    cmd_res = remove_user_from_watchlist_command(client, {"watchlist": watchlist_type, "username": "user_a@example.com"})
    incydr_sdk_mock.watchlists.v2.remove_included_actors.assert_called_once_with(
        watchlist_id=watchlist_id, actor_ids=actorobj.actor_id
    )
    assert cmd_res.raw_response == {
        "Watchlist": "DEPARTING_EMPLOYEE",
        "Username": "user_a@example.com",
        "Success": True,
    }


def test_fetch_incidents_handles_single_severity(incydr_sessions_mock):
    client = _create_incydr_client(incydr_sessions_mock)
    fetch_incidents(
        client=client,
        last_run={"last_fetch": None},
        first_fetch_time=MOCK_FETCH_TIME,
        event_severity_filter="High",
        fetch_limit=10,
        include_files=True,
        integration_context={},
    )
    assert incydr_sessions_mock.sessions.v1.iter_all.call_args[1]["severities"] == 3


def test_fetch_incidents_handles_multi_severity(incydr_sessions_mock):
    client = _create_incydr_client(incydr_sessions_mock)
    fetch_incidents(
        client=client,
        last_run={"last_fetch": None},
        first_fetch_time=MOCK_FETCH_TIME,
        event_severity_filter=["High", "Low"],
        fetch_limit=10,
        include_files=True,
        integration_context={},
    )
    call_args = incydr_sessions_mock.sessions.v1.iter_all.call_args[1]["severities"]
    assert 1 in call_args
    assert 3 in call_args


def test_fetch_when_include_files_includes_files(incydr_sessions_mock):
    client = _create_incydr_client(incydr_sessions_mock)
    _, incidents, _ = fetch_incidents(
        client=client,
        last_run={"last_fetch": None},
        first_fetch_time=MOCK_FETCH_TIME,
        event_severity_filter=["High", "Low"],
        fetch_limit=10,
        include_files=True,
        integration_context={},
    )
    for i in incidents:
        _json = json.loads(i["rawJSON"])
        assert len(_json["fileevents"])


def test_fetch_when_not_include_files_excludes_files(incydr_sessions_mock):
    client = _create_incydr_client(incydr_sessions_mock)
    _, incidents, _ = fetch_incidents(
        client=client,
        last_run={"last_fetch": None},
        first_fetch_time=MOCK_FETCH_TIME,
        event_severity_filter=["High", "Low"],
        fetch_limit=10,
        include_files=False,
        integration_context={},
    )
    for i in incidents:
        _json = json.loads(i["rawJSON"])
        assert not _json.get("fileevents")


def test_fetch_incidents_first_run(incydr_sessions_mock):
    client = _create_incydr_client(incydr_sessions_mock)
    next_run, incidents, remaining_incidents = fetch_incidents(
        client=client,
        last_run={"last_fetch": None},
        first_fetch_time=MOCK_FETCH_TIME,
        event_severity_filter=None,
        fetch_limit=10,
        include_files=True,
        integration_context={},
    )
    assert len(incidents) == 3
    assert next_run["last_fetch"]


def test_fetch_incidents_next_run(incydr_sessions_mock):
    client = _create_incydr_client(incydr_sessions_mock)
    mock_date = "2020-01-01T00:00:00.000Z"
    mock_timestamp = int(time.mktime(time.strptime(mock_date, "%Y-%m-%dT%H:%M:%S.000Z")))
    next_run, incidents, remaining_incidents = fetch_incidents(
        client=client,
        last_run={"last_fetch": mock_timestamp},
        first_fetch_time=MOCK_FETCH_TIME,
        event_severity_filter=None,
        fetch_limit=10,
        include_files=True,
        integration_context={},
    )
    assert len(incidents) == 3
    assert next_run["last_fetch"]


def test_fetch_incidents_fetch_limit(incydr_sessions_mock):
    client = _create_incydr_client(incydr_sessions_mock)
    mock_date = "2020-01-01T00:00:00.000Z"
    mock_timestamp = int(time.mktime(time.strptime(mock_date, "%Y-%m-%dT%H:%M:%S.000Z")))
    next_run, incidents, remaining_incidents = fetch_incidents(
        client=client,
        last_run={"last_fetch": mock_timestamp},
        first_fetch_time=MOCK_FETCH_TIME,
        event_severity_filter=None,
        fetch_limit=2,
        include_files=True,
        integration_context={},
    )
    assert len(incidents) == 2
    assert next_run["last_fetch"]
    assert len(remaining_incidents) == 1
    # Run again to get the last incident
    next_run, incidents, remaining_incidents = fetch_incidents(
        client=client,
        last_run={"last_fetch": mock_timestamp, "incidents_at_last_fetch_timestamp": []},
        first_fetch_time=MOCK_FETCH_TIME,
        event_severity_filter=None,
        fetch_limit=2,
        include_files=True,
        integration_context={"remaining_incidents": remaining_incidents},
    )
    assert len(incidents) == 1
    assert next_run["last_fetch"]
    assert not remaining_incidents


def test_fetch_incidents_sets_fetched_incidents_in_context(incydr_sessions_mock):
    client = _create_incydr_client(incydr_sessions_mock)
    next_run, incidents, remaining_incidents = fetch_incidents(
        client=client,
        last_run={"last_fetch": None},
        first_fetch_time=MOCK_FETCH_TIME,
        event_severity_filter=None,
        fetch_limit=10,
        include_files=True,
        integration_context={},
    )
    assert len(next_run["incidents_at_last_fetch_timestamp"]) == 2
    assert "sessionid-abc-2" in next_run["incidents_at_last_fetch_timestamp"]
    assert "sessionid-abc-3" in next_run["incidents_at_last_fetch_timestamp"]


def test_fetch_incidents_deduplicates(incydr_sessions_mock):
    client = _create_incydr_client(incydr_sessions_mock)
    next_run, incidents, remaining_incidents = fetch_incidents(
        client=client,
        last_run={"last_fetch": None, "incidents_at_last_fetch_timestamp": ["sessionid-abc-1"]},
        first_fetch_time=MOCK_FETCH_TIME,
        event_severity_filter=None,
        fetch_limit=10,
        include_files=True,
        integration_context={},
    )
    assert len(incidents) == 2


def test_fetch_incidents_deduplicates_when_incidents_in_another_order(incydr_sessions_mock):
    incydr_sessions_mock.sessions.v1.iter_all.return_value = iter(
        [MOCK_SESSION_RESPONSE_3, MOCK_SESSION_RESPONSE_2, MOCK_SESSION_RESPONSE]
    )
    client = _create_incydr_client(incydr_sessions_mock)
    next_run, incidents, remaining_incidents = fetch_incidents(
        client=client,
        last_run={"last_fetch": None, "incidents_at_last_fetch_timestamp": ["sessionid-abc-1"]},
        first_fetch_time=MOCK_FETCH_TIME,
        event_severity_filter=None,
        fetch_limit=10,
        include_files=True,
        integration_context={},
    )
    assert len(incidents) == 2


def test_fetch_incidents_prunes_fetched_incidents_in_context(incydr_sessions_mock):
    client = _create_incydr_client(incydr_sessions_mock)
    next_run, incidents, remaining_incidents = fetch_incidents(
        client=client,
        last_run={"last_fetch": None, "incidents_at_last_fetch_timestamp": ["sessionid-abc-1"]},
        first_fetch_time=MOCK_FETCH_TIME,
        event_severity_filter=None,
        fetch_limit=10,
        include_files=True,
        integration_context={},
    )
    assert len(next_run["incidents_at_last_fetch_timestamp"]) == 2


def test_file_events_search_command_returns_only_table_when_add_to_context_false(mocker, incydr_file_events_mock):
    mock_demisto = mocker.patch("Code42.demisto")
    mock_demisto.params.return_value = {"v2_events": True}
    mock_demisto.incident.return_value = {"CustomFields": {"code42fileeventsversion": "2"}}
    client = _create_incydr_client(incydr_file_events_mock)
    cmd_res = file_events_search_command(
        client,
        args={
            "username": "user3@example.com",
            "results": 50,
            "add-to-context": "false",
            "min_risk_score": "1",
        },
    )
    assert cmd_res.outputs_prefix is None
    assert cmd_res.outputs is None
    assert cmd_res.readable_output


def test_file_events_search_command_returns_outputs_when_add_to_context_true(mocker, incydr_file_events_mock):
    mock_demisto = mocker.patch("Code42.demisto")
    mock_demisto.params.return_value = {"v2_events": True}
    mock_demisto.incident.return_value = {"CustomFields": {"code42fileeventsversion": "2"}}
    client = _create_incydr_client(incydr_file_events_mock)
    cmd_res = file_events_search_command(
        client,
        args={
            "username": "user3@example.com",
            "results": 50,
            "add-to-context": "true",
            "min_risk_score": "3",
        },
    )
    assert len(cmd_res.outputs) == 5
    assert cmd_res.readable_output
    assert cmd_res.outputs_prefix == "Code42.FileEvents"


def test_file_events_search_command_builds_expected_query(mocker, incydr_file_events_mock):
    mock_demisto = mocker.patch("Code42.demisto")
    mock_demisto.params.return_value = {"v2_events": True}
    mock_demisto.incident.return_value = {"CustomFields": {"code42fileeventsversion": "2"}}
    client = _create_incydr_client(incydr_file_events_mock)
    file_events_search_command(
        client,
        args={
            "username": "user3@example.com",
            "hostname": "TEST_HOSTNAME",
            "hash": "9cea266b4e07974df1982ae3b9de92ce",
            "results": 50,
            "add-to-context": "false",
            "min_risk_score": "3",
        },
    )
    query = str(incydr_file_events_mock.file_events.v2.search.call_args[0][0])
    assert "Filter(term='source.name', operator='IS', value='TEST_HOSTNAME')" in query
    assert "Filter(term='user.email', operator='IS', value='user3@example.com')" in query
    assert "Filter(term='risk.score', operator='GREATER_THAN', value=2)" in query
    assert "page_size=50" in query


@pytest.mark.parametrize(
    "hash",
    [
        ("md5", "9cea266b4e07974df1982ae3b9de92ce"),
        ("sha256", "34d0c9fc9c907ec374cf7e8ca1ff8a172e36eccee687f0a9b69dd169debb81e1"),
    ],
)
def test_file_events_search_command_builds_expected_hash_query(mocker, incydr_file_events_mock, hash):
    hash_type, hash_value = hash
    mock_demisto = mocker.patch("Code42.demisto")
    mock_demisto.params.return_value = {"v2_events": True}
    mock_demisto.incident.return_value = {"CustomFields": {"code42fileeventsversion": "2"}}
    client = _create_incydr_client(incydr_file_events_mock)
    file_events_search_command(
        client,
        args={
            "username": "user3@example.com",
            "hostname": "TEST_HOSTNAME",
            "hash": hash_value,
            "results": 50,
            "add-to-context": "false",
            "min_risk_score": "3",
        },
    )
    query = str(incydr_file_events_mock.file_events.v2.search.call_args[0][0])
    assert f"Filter(term='file.hash.{hash_type}', operator='IS', value='{hash_value}')" in query


def test_file_events_search_json_query_builds_expected_query(mocker, incydr_file_events_mock):
    mock_demisto = mocker.patch("Code42.demisto")
    mock_demisto.params.return_value = {"v2_events": True}
    mock_demisto.incident.return_value = {"CustomFields": {"code42fileeventsversion": "2"}}
    client = _create_incydr_client(incydr_file_events_mock)
    query_json = """{
  "groupClause": "AND",
  "groups": [
    {
      "filterClause": "OR",
      "filters": [
        {
          "operator": "IS",
          "term": "file.category",
          "value": "Archive"
        },
        {
          "operator": "IS",
          "term": "file.category",
          "value": "Pdf"
        }
      ]
    }
  ],
  "srtDir": "asc",
  "srtKey": "event.id",
  "pgNum": 1,
  "pgSize": 100
}
"""
    file_events_search_command(
        client,
        args={
            "json": query_json,
            "results": 50,
            "add-to-context": "false",
            "min_risk_score": "3",
        },
    )
    called_query = incydr_file_events_mock.file_events.v2.search.call_args[0][0]
    assert called_query.groups == EventQuery.parse_raw(query_json).groups
    assert called_query.page_size == 50


def test_file_events_search_with_add_to_context_adds_events_without_duplication(mocker, incydr_file_events_mock):
    mock_demisto = mocker.patch("Code42.demisto")
    v2_events = [json.loads(x.json()) for x in MOCK_V2_FILE_EVENTS_RESPONSE.file_events]
    context_events = v2_events[:3]
    mock_demisto.incident.return_value = {"CustomFields": {"code42fileeventsversion": "2", "code42fileevents": []}}
    mock_demisto.context.return_value = {"Code42": {"FileEvents": context_events}}
    client = _create_incydr_client(incydr_file_events_mock)
    cmd_res = file_events_search_command(
        client,
        args={
            "username": "test@example.com",
            "results": 50,
            "add-to-context": "true",
            "min_risk_score": "3",
        },
    )
    assert cmd_res.outputs == v2_events


def test_file_events_search_raises_when_no_args_passed(mocker, incydr_file_events_mock):
    mock_demisto = mocker.patch("Code42.demisto")
    mock_demisto.incident.return_value = {"CustomFields": {"code42fileeventsversion": "2"}}
    client = _create_incydr_client(incydr_file_events_mock)
    with pytest.raises(Code42MissingSearchArgumentsError):
        file_events_search_command(
            client,
            args={
                "min_risk_score": "1",
                "add-to-context": "false",
            },
        )


def test_file_events_search_raises_when_invalid_json_query(mocker, incydr_file_events_mock):
    mock_demisto = mocker.patch("Code42.demisto")
    mock_demisto.incident.return_value = {"CustomFields": {"code42fileeventsversion": "2"}}
    incydr_file_events_mock.file_events.v2.search.side_effect = Exception()
    client = _create_incydr_client(incydr_file_events_mock)
    with pytest.raises(SystemExit):
        file_events_search_command(
            client,
            args={
                "json": '{"invalid": "query"}',
                "min_risk_score": "1",
                "add-to-context": "false",
            },
        )


def test_file_events_table_command_handles_v2_events(mocker, incydr_file_events_mock):
    mock_demisto = mocker.patch("Code42.demisto")
    v2_events = [json.loads(x.json()) for x in MOCK_V2_FILE_EVENTS_RESPONSE.file_events]
    mock_demisto.incident.return_value = {"CustomFields": {"code42fileeventsversion": "2", "code42fileevents": v2_events}}
    client = _create_incydr_client(incydr_file_events_mock)
    cmd_res = file_events_to_table_command(client, args={"include": "all"})
    assert cmd_res.outputs is None


def test_module_authenticated_returns_ok(incydr_sdk_mock):
    from Code42 import test_module

    incydr_sdk_mock.actors.v1.get_page.return_value = []
    client = _create_incydr_client(incydr_sdk_mock)
    cmd_res = test_module(client)
    assert cmd_res == "ok"


def test_module_unauthenticated_returns_invalid(incydr_sdk_mock):
    from Code42 import test_module

    incydr_sdk_mock.actors.v1.get_page.side_effect = Exception()
    client = _create_incydr_client(incydr_sdk_mock)
    cmd_res = test_module(client)
    assert cmd_res != "ok"
