import json
import datetime
import pytest
import requests_mock
from freezegun import freeze_time

""" UTILS """


def util_load_json(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


def util_load_text(path: str) -> str:
    with open(path) as f:
        return f.read()


def mock_get_access_token():
    return {
        "access_token": "123456",
        "expires_in": 1111,
        "refresh_token": "123456",
        "refresh_token_expires_in": 2222,
    }


def mocked_admin_client():
    from CiscoWebexEventCollector import AdminClient

    class MockAdminClient(AdminClient):
        def get_access_token(self):
            return ""

    return MockAdminClient(
        "https://url.com",
        False,
        False,
        "1",
        "1",
        "https://redirect.com",
        "admin_scope",
        "1",
    )


def mocked_compliance_officer_client():
    from CiscoWebexEventCollector import ComplianceOfficerClient

    class MockComplianceOfficerClient(ComplianceOfficerClient):
        def get_access_token(self):
            return ""

    return MockComplianceOfficerClient(
        "https://url.com",
        False,
        False,
        "1",
        "1",
        "https://redirect.com",
        "co_scope",
    )


""" TEST HELPER FUNCTION """


def mock_set_integration_context(context: dict = None) -> dict | None:
    return context


def test_remove_integration_context_for_user(mocker):
    import CiscoWebexEventCollector

    mock_integration_context = {"test_user1": {"context_key": "context_value"}, "test_user2": {"context_key": "context_value"}}
    mocker.patch.object(CiscoWebexEventCollector, "get_integration_context", return_value=mock_integration_context)
    mock_context = mocker.patch("CiscoWebexEventCollector.set_integration_context", side_effect=mock_set_integration_context)

    assert CiscoWebexEventCollector.get_integration_context() == mock_integration_context
    CiscoWebexEventCollector.remove_integration_context_for_user("test_user1")
    assert mock_context.call_args.args[0] == {"test_user1": {}, "test_user2": {"context_key": "context_value"}}
    CiscoWebexEventCollector.remove_integration_context_for_user("test_user2")
    assert mock_context.call_args.args[0] == {"test_user1": {}, "test_user2": {}}


@freeze_time("2023-12-20 13:40:00 UTC")
def test_create_last_run():
    """
    Given:
        - An expected `last_run` dict.
    When:
        - create_last_run function is running.
    Then:
        - Validates that the function creates a dict with the expected items.
    """
    from CiscoWebexEventCollector import create_last_run

    expected_result = {
        "admin_audits": {"since_datetime": "2023-12-13T13:40:00.000Z", "next_url": ""},
        "security_audits": {"since_datetime": "2023-12-13T13:40:00.000Z", "next_url": ""},
        "compliance_officer_events": {"since_datetime": "2023-12-13T13:40:00.000Z", "next_url": ""},
    }

    assert create_last_run() == expected_result


@freeze_time("2023-12-20 13:40:00 UTC")
def test_date_time_to_iso_format():
    """
    Given:
        - A datetime object with freeze time set to '2023-12-20 13:40:00'.
    When:
        - date_time_to_iso_format function is running.
    Then:
        - Validates that the function returns a string is ISO format as expected.
    """
    from CiscoWebexEventCollector import date_time_to_iso_format

    assert date_time_to_iso_format(datetime.datetime.utcnow()) == "2023-12-20T13:40:00.000Z"


def test_add_fields_to_events():
    """
    Given:
        - lists of events of the following types.
            1. Admin Audit Events.
            2. Admin Audit Events.
            3. Events.
    When:
        - add_fields_to_events function is running.
    Then:
        - Validates that the function adds the fields as expected.
    """
    from CiscoWebexEventCollector import add_fields_to_events, COMMAND_FUNCTION_TO_EVENT_TYPE

    admin_audits = util_load_json("test_data/admin_audits.json").get("items")
    security_audits = util_load_json("test_data/security_audits.json").get("items")
    compliance_officer_events = util_load_json("test_data/events.json").get("items")

    assert not any(key in admin_audits[0] for key in ("_time", "source_log_type"))
    assert not any(key in security_audits[0] for key in ("_time", "source_log_type"))
    assert not any(key in compliance_officer_events[0] for key in ("_time", "source_log_type"))

    add_fields_to_events(admin_audits, "Admin Audit Events")
    add_fields_to_events(security_audits, "Security Audit Events")
    add_fields_to_events(compliance_officer_events, "Events")

    assert admin_audits[0]["_time"] == admin_audits[0]["created"]
    assert admin_audits[0]["source_log_type"] == COMMAND_FUNCTION_TO_EVENT_TYPE.get("get_admin_audits")
    assert security_audits[0]["_time"] == security_audits[0]["created"]
    assert security_audits[0]["source_log_type"] == COMMAND_FUNCTION_TO_EVENT_TYPE.get("get_security_audits")
    assert compliance_officer_events[0]["_time"] == compliance_officer_events[0]["created"]
    assert compliance_officer_events[0]["source_log_type"] == COMMAND_FUNCTION_TO_EVENT_TYPE.get("get_compliance_officer_events")


@pytest.mark.parametrize(
    "latest_datetime_previous_fetch, expected_datetime",
    [
        ("2023-12-04T07:40:06.680Z", "2023-12-04T07:40:06.691Z"),
        ("2023-12-04T07:40:06.695Z", "2023-12-04T07:40:06.696Z"),
    ],
)
def test_increase_datetime_for_next_fetch(latest_datetime_previous_fetch, expected_datetime):
    """
    Given:
        - A list of events and a string represents a datetime from the previous fetch.
            1. the datetime from the previous fetch is earlier than the latest event in the list of events.
            2. the datetime from the previous fetch is later than the latest event in the list of events.
    When:
        - increase_datetime_for_next_fetch function is running.
    Then:
        - Validates that the function returns the latest event time + a timedelta of 1 millisecond.
    """
    from CiscoWebexEventCollector import increase_datetime_for_next_fetch

    events = util_load_json("test_data/events.json").get("items")
    assert increase_datetime_for_next_fetch(events, latest_datetime_previous_fetch) == expected_datetime


""" TEST COMMAND FUNCTION """


@pytest.mark.parametrize(
    "client, expected_url",
    [
        (
            mocked_admin_client(),
            "https://url.com/authorize?response_type=code&scope=admin_scope&client_id=1"
            "&redirect_uri=https%3A%2F%2Fredirect.com",
        ),
        (
            mocked_compliance_officer_client(),
            "https://url.com/authorize?response_type=code&scope=co_scope&client_id=1&redirect_uri=https%3A%2F%2Fredirect.com",
        ),
    ],
)
def test_oauth_start(client, expected_url):
    """
    Given:
        - An AdminClient and a ComplianceOfficerClient.
    When:
        - oauth_start function is running.
    Then:
        - Validates that the expected URL is in the result.
    """
    from CiscoWebexEventCollector import oauth_start

    results = oauth_start(client)
    assert expected_url in results.readable_output


@pytest.mark.parametrize("client", [mocked_admin_client(), mocked_compliance_officer_client()])
def test_oauth_complete(client):
    """
    Given:
        - An AdminClient and a ComplianceOfficerClient.
    When:
        - oauth_complete function is running.
    Then:
        - Validates that the expected text (`Logged in successfully.`) is in the result.
    """
    from CiscoWebexEventCollector import oauth_complete

    with requests_mock.Mocker() as m:
        m.post("https://url.com/access_token", json=mock_get_access_token())
        results = oauth_complete(client, {"code": "123456"})

    assert "Authorization completed successfully." in results.readable_output


@pytest.mark.parametrize("client", [mocked_admin_client(), mocked_compliance_officer_client()])
def test_oauth_test(client):
    """
    Given:
        - An AdminClient and a ComplianceOfficerClient.
    When:
        - oauth_test function is running.
    Then:
        - Validates that the expected text (`### Test succeeded!`) is in the result.
    """
    from CiscoWebexEventCollector import oauth_test

    with requests_mock.Mocker() as m:
        m.get("https://url.com/adminAudit/events", text=util_load_text("test_data/admin_audits.json"))
        m.get("https://url.com/events", text=util_load_text("test_data/events.json"))
        result = oauth_test(client)

    assert result.readable_output == "```✅ Success!```"


@pytest.mark.parametrize(
    "command_function, args",
    [
        (mocked_admin_client().get_admin_audits, {}),
        (mocked_admin_client().get_security_audits, {}),
        (mocked_compliance_officer_client().get_compliance_officer_events, {}),
    ],
)
def test_get_events_command(command_function, args):
    """
    Given:
        - Three types of events to fetch.
    When:
        - get_events_command function is running.
            1. with event type `Admin audits`
            2. with event type `Security audits`
            3. with event type `Events`
    Then:
        - Validates that the function works as expected.
    """
    from CiscoWebexEventCollector import get_events_command, COMMAND_FUNCTION_TO_EVENT_TYPE

    with requests_mock.Mocker() as m:
        m.get("https://url.com/adminAudit/events", text=util_load_text("test_data/admin_audits.json"))
        m.get("https://url.com/admin/securityAudit/events", text=util_load_text("test_data/security_audits.json"))
        m.get("https://url.com/events", text=util_load_text("test_data/events.json"))
        command_results, events = get_events_command(command_function, args)

    assert len(events) > 0
    assert COMMAND_FUNCTION_TO_EVENT_TYPE.get(command_function.__name__) in command_results.readable_output


@freeze_time("2023-12-20 13:40:00 UTC")
def test_fetch_events():
    """
    Given:
        - An AdminClient and a ComplianceOfficerClient.
    When:
        - fetch_events function is running.
    Then:
        - Validates that the function returns
            1. A list of events and a dict with fetch data including a `next_url` link.
            2. The second interval of fetch_events uses the `next_url` link from the previous fetch,
            and returns an empty list of events and a dict with fetch data including a `next_url` link set to an empty string.
    """
    from CiscoWebexEventCollector import create_last_run, fetch_events

    with requests_mock.Mocker() as m:
        m.get(
            "https://url.com/adminAudit/events?orgId=1&from=2023-12-13T13%3A40%3A00.000Z&to=2023-12-20T13%3A40%3A00.000Z&max=1",
            text=util_load_text("test_data/admin_audits.json"),
            headers={"Link": '<https://url.com/adminAudit/events?nexturl=true>; rel="next"'},
        )
        m.get(
            "https://url.com/admin/securityAudit/events?orgId=1&startTime=2023-12-13T13%3A40%3A00.000Z&"
            "endTime=2023-12-20T13%3A40%3A00.000Z&max=1",
            text=util_load_text("test_data/security_audits.json"),
            headers={"Link": '<https://url.com/securityAudit/events?nexturl=true>; rel="next"'},
        )
        m.get(
            "https://url.com/events?from=2023-12-13T13%3A40%3A00.000Z&to=2023-12-20T13%3A40%3A00.000Z&max=1",
            text=util_load_text("test_data/events.json"),
            headers={"Link": '<https://url.com/events?nexturl=true>; rel="next"'},
        )
        events, next_run = fetch_events(mocked_admin_client(), mocked_compliance_officer_client(), create_last_run(), 1, True)

    assert len(events) > 0
    assert next_run == {
        "admin_audits": {
            "next_url": "https://url.com/adminAudit/events?nexturl=true",
            "since_datetime": "2023-12-20T09:33:26.409Z",
        },
        "compliance_officer_events": {
            "next_url": "https://url.com/events?nexturl=true",
            "since_datetime": "2023-12-13T13:40:00.001Z",
        },
        "security_audits": {
            "next_url": "https://url.com/securityAudit/events?nexturl=true",
            "since_datetime": "2023-12-19T07:01:26.487Z",
        },
    }

    with requests_mock.Mocker() as m:
        m.get("https://url.com/adminAudit/events?nexturl=true", text=util_load_text("test_data/no_events.json"))
        m.get("https://url.com/securityAudit/events?nexturl=true", text=util_load_text("test_data/no_events.json"))
        m.get("https://url.com/events?nexturl=true", text=util_load_text("test_data/no_events.json"))

        events, next_run = fetch_events(mocked_admin_client(), mocked_compliance_officer_client(), next_run, 1, True)

    assert len(events) == 0
    assert next_run == {
        "admin_audits": {"next_url": "", "since_datetime": "2023-12-20T09:33:26.409Z"},
        "compliance_officer_events": {"next_url": "", "since_datetime": "2023-12-13T13:40:00.001Z"},
        "security_audits": {"next_url": "", "since_datetime": "2023-12-19T07:01:26.487Z"},
    }
