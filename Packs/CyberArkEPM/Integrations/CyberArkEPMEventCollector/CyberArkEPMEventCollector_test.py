import json

import pytest

from CommonServerPython import *  # noqa: F403
from CyberArkEPMEventCollector import (
    Client,
    Config,
    XSIAM_EVENT_TYPE,
    add_fields_to_events,
    create_last_run,
    fetch_events,
    get_events_command,
    get_set_ids_by_set_names,
    normalize_server_url,
    parse_set_names,
    prepare_datetime,
    prepare_next_run,
    reconcile_last_run_with_current_sets,
    reconcile_split_set_names,
    # Aliased: pytest would otherwise collect the integration's `test_module` command as a test case
    # and fail it on a missing `client` fixture.
    test_module as run_test_module,
)

""" UTILS """


def util_load_json(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


def mocked_client(requests_mock):
    mock_response_sets = {"Sets": [{"Id": "id1", "Name": "set_name1"}, {"Id": "id2", "Name": "set_name2"}]}
    mock_response_admin_audits = util_load_json("test_data/admin_audits.json")
    mock_response_policy_audits = util_load_json("test_data/policy_audits.json")
    mock_response_events = util_load_json("test_data/events.json")
    mock_response_no_more_events = util_load_json("test_data/no_more_events.json")

    requests_mock.post("https://url.com/EPM/API/Auth/EPM/Logon", json={"ManagerURL": "https://mock.com", "Authorization": "123"})
    requests_mock.get("https://mock.com/EPM/API/Sets", json=mock_response_sets)
    requests_mock.get(
        "https://mock.com/EPM/API/Sets/id1/AdminAudit?dateFrom=2023-01-01T00:00:00Z&limit=10", json=mock_response_admin_audits
    )
    requests_mock.get(
        "https://mock.com/EPM/API/Sets/id2/AdminAudit?dateFrom=2023-01-01T00:00:00Z&limit=10", json=mock_response_admin_audits
    )
    requests_mock.get(
        "https://mock.com/EPM/API/Sets/id1/AdminAudit?dateFrom=2023-12-12T07:45:27.141Z&limit=10", json=mock_response_admin_audits
    )
    requests_mock.get(
        "https://mock.com/EPM/API/Sets/id2/AdminAudit?dateFrom=2023-12-12T07:45:27.141Z&limit=10", json=mock_response_admin_audits
    )
    requests_mock.post(
        "https://mock.com/EPM/API/Sets/id1/policyaudits/search?nextCursor=start&limit=10", json=mock_response_policy_audits
    )
    requests_mock.post(
        "https://mock.com/EPM/API/Sets/id1/policyaudits/search?nextCursor=1700097106000&limit=10",
        json=mock_response_no_more_events,
    )
    requests_mock.post(
        "https://mock.com/EPM/API/Sets/id2/policyaudits/search?nextCursor=start&limit=10", json=mock_response_policy_audits
    )
    requests_mock.post(
        "https://mock.com/EPM/API/Sets/id2/policyaudits/search?nextCursor=1700097106000&limit=10",
        json=mock_response_no_more_events,
    )
    requests_mock.post("https://mock.com/EPM/API/Sets/id1/Events/Search?nextCursor=start&limit=10", json=mock_response_events)
    requests_mock.post(
        "https://mock.com/EPM/API/Sets/id1/Events/Search?nextCursor=1702360757618&limit=10", json=mock_response_no_more_events
    )
    requests_mock.post("https://mock.com/EPM/API/Sets/id2/Events/Search?nextCursor=start&limit=10", json=mock_response_events)
    requests_mock.post(
        "https://mock.com/EPM/API/Sets/id2/Events/Search?nextCursor=1702360757618&limit=10", json=mock_response_no_more_events
    )

    return Client("https://url.com", "test", "123456", "1", policy_audits_event_type=["a", "b", "c"])


""" TEST HELPER FUNCTION """


def test_create_last_run():
    """
    Given:
        - A list of set_ids.

    When:
        - create_last_run function is running.

    Then:
        - Validates that the function works as expected.
    """
    set_ids = ["123", "456"]
    from_date = "2023-01-01T00:00:00Z"
    expected_result = {
        "123": {
            "admin_audits": {"from_date": from_date},
            "policy_audits": {"from_date": from_date, "next_cursor": "start"},
            "detailed_events": {"from_date": from_date, "next_cursor": "start"},
        },
        "456": {
            "admin_audits": {"from_date": from_date},
            "policy_audits": {"from_date": from_date, "next_cursor": "start"},
            "detailed_events": {"from_date": from_date, "next_cursor": "start"},
        },
    }

    assert create_last_run(set_ids, from_date) == expected_result


@pytest.mark.parametrize(
    "date_time, increase, expected_date_time",
    [
        ("2023-01-01T00:00:00", False, "2023-01-01T00:00:00.000Z"),
        (datetime.strptime("2023-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S"), False, "2023-01-01T00:00:00.000Z"),
        ("2023-01-01T00:00:00", True, "2023-01-01T00:00:00.001Z"),
    ],
)
def test_prepare_datetime(date_time, increase, expected_date_time):
    """
    Given:
        - A datetime presentation
            1. in str
            2. in datetime object

    When:
        - prepare_datetime function is running.
            1. with increase set to false.
            2. with increase set to true.

    Then:
        - Validates that the function works as expected.
    """
    assert prepare_datetime(date_time, increase) == expected_date_time


def test_add_fields_to_events():
    """
    Given:
        - lists of events
            1. admin audits.
            2. policy audits.
            3. events.

    When:
        - add_fields_to_events function is running.

    Then:
        - Validates that the function works as expected.
    """
    policy_audits = util_load_json("test_data/policy_audits.json").get("events")
    admin_audits = util_load_json("test_data/admin_audits.json").get("AdminAudits")
    events = util_load_json("test_data/events.json").get("events")

    assert not any(key in policy_audits[0] for key in ("_time", "source_log_type"))
    assert not any(key in admin_audits[0] for key in ("_time", "source_log_type"))
    assert not any(key in events[0] for key in ("_time", "source_log_type"))

    add_fields_to_events(policy_audits, "arrivalTime", "policy_audits")
    add_fields_to_events(admin_audits, "EventTime", "admin_audits")
    add_fields_to_events(events, "arrivalTime", "detailed_events")

    assert policy_audits[0]["_time"] == policy_audits[0]["arrivalTime"]
    assert policy_audits[0]["source_log_type"] == XSIAM_EVENT_TYPE.get("policy_audits")
    assert admin_audits[0]["_time"] == admin_audits[0]["EventTime"]
    assert admin_audits[0]["source_log_type"] == XSIAM_EVENT_TYPE.get("admin_audits")
    assert events[0]["_time"] == events[0]["arrivalTime"]
    assert events[0]["source_log_type"] == XSIAM_EVENT_TYPE.get("detailed_events")


@pytest.mark.parametrize(
    "last_run, current_set_ids, args, expected_set_ids, expected_new_sets, expected_removed_sets",
    [
        # Test Case 1: No changes - set IDs match exactly
        (
            {"id1": {"admin_audits": {"from_date": "2023-01-01T00:00:00.000Z"}}},
            ["id1"],
            {"from_date": "2023-01-01T00:00:00.000Z"},
            ["id1"],
            [],
            [],
        ),
        # Test Case 2: New set added - should initialize with from_date
        (
            {"id1": {"admin_audits": {"from_date": "2023-01-01T00:00:00.000Z"}}},
            ["id1", "id2"],
            {"from_date": "2023-02-01T00:00:00.000Z"},
            ["id1", "id2"],
            ["id2"],
            [],
        ),
        # Test Case 3: Old set removed - should be deleted from last_run
        (
            {
                "id1": {"admin_audits": {"from_date": "2023-01-01T00:00:00.000Z"}},
                "id2": {"admin_audits": {"from_date": "2023-01-01T00:00:00.000Z"}},
            },
            ["id1"],
            {"from_date": "2023-01-01T00:00:00.000Z"},
            ["id1"],
            [],
            ["id2"],
        ),
        # Test Case 4: Multiple sets added and removed simultaneously
        (
            {
                "id1": {"admin_audits": {"from_date": "2023-01-01T00:00:00.000Z"}},
                "id2": {"admin_audits": {"from_date": "2023-01-01T00:00:00.000Z"}},
            },
            ["id1", "id3", "id4"],
            {"from_date": "2023-03-01T00:00:00.000Z"},
            ["id1", "id3", "id4"],
            ["id3", "id4"],
            ["id2"],
        ),
        # Test Case 5: Complete replacement - all old sets removed, all new sets added
        (
            {"id1": {"admin_audits": {"from_date": "2023-01-01T00:00:00.000Z"}}},
            ["id2", "id3"],
            {"from_date": "2023-04-01T00:00:00.000Z"},
            ["id2", "id3"],
            ["id2", "id3"],
            ["id1"],
        ),
    ],
)
def test_reconcile_last_run_with_current_sets(
    last_run, current_set_ids, args, expected_set_ids, expected_new_sets, expected_removed_sets
):
    """
    Given:
        - A last_run state and currently configured set IDs.

    When:
        - Calling reconcile_last_run_with_current_sets function.
            1. When set IDs match exactly (no changes)
            2. When a new set is added to the configuration
            3. When an old set is removed from the configuration
            4. When multiple sets are added and removed simultaneously
            5. When all sets are replaced with new ones

    Then:
        - Ensure stale sets are removed from last_run
        - Ensure new sets are added with proper initialization
        - Ensure existing sets remain unchanged
        - Ensure the returned last_run contains only the current set IDs
    """
    result = reconcile_last_run_with_current_sets(last_run, current_set_ids, args)

    # Verify the result contains exactly the expected set IDs
    assert set(result.keys()) == set(expected_set_ids)

    # Verify removed sets are no longer in the result
    for removed_id in expected_removed_sets:
        assert removed_id not in result

    # Verify new sets are properly initialized
    for new_id in expected_new_sets:
        assert new_id in result
        assert "admin_audits" in result[new_id]
        assert "policy_audits" in result[new_id]
        assert "detailed_events" in result[new_id]
        assert "from_date" in result[new_id]["admin_audits"]
        assert "from_date" in result[new_id]["policy_audits"]
        assert "next_cursor" in result[new_id]["policy_audits"]
        assert "from_date" in result[new_id]["detailed_events"]
        assert "next_cursor" in result[new_id]["detailed_events"]


def test_get_set_ids_by_set_names(mocker, requests_mock):
    """
    Given:
        - A list of set_names.

    When:
        - get_set_ids_by_set_names function is running.

    Then:
        - Validates that the function works as expected.
    """
    mocker.patch("CyberArkEPMEventCollector.get_integration_context", return_value={})

    set_names = ["set_name1", "set_name2"]
    client = mocked_client(requests_mock)

    assert get_set_ids_by_set_names(client, set_names) == ["id1", "id2"]


def test_get_set_ids_by_set_names_preserves_token_in_context(mocker, requests_mock):
    """
    Given:
        - An integration context that already holds a cached OAuth token
          (access_token / valid_until) alongside no cached set_items.

    When:
        - get_set_ids_by_set_names resolves and persists set_items to the context.

    Then:
        - The cached token keys are preserved (not clobbered) and set_items is added,
          proving the set-name write and the token write can coexist in the context.
    """
    # Stateful fake integration context shared by the get/set mocks.
    fake_context = {"access_token": "cached-token", "valid_until": "9999999999"}

    mocker.patch(
        "CyberArkEPMEventCollector.get_integration_context",
        side_effect=lambda: dict(fake_context),
    )
    mocker.patch(
        "CyberArkEPMEventCollector.set_integration_context",
        side_effect=lambda ctx: fake_context.update(ctx),
    )

    set_names = ["set_name1", "set_name2"]
    client = mocked_client(requests_mock)

    assert get_set_ids_by_set_names(client, set_names) == ["id1", "id2"]
    # Token keys must survive the set_items write.
    assert fake_context["access_token"] == "cached-token"
    assert fake_context["valid_until"] == "9999999999"
    assert fake_context["set_items"] == {"set_name1": "id1", "set_name2": "id2"}


""" TEST COMMAND FUNCTION """


@pytest.mark.parametrize("event_type", ["admin_audits", "policy_audits", "detailed_events"])
def test_get_events_command(requests_mock, event_type):
    """
    Given:
        - A list of set_ids and a date form where to fetch with a CyberArkEPM (mock) client.

    When:
        - get_events_command function is running.
            1. with event type `admin_audits`
            2. with event type `policy_audits`
            3. with event type `detailed_events`

    Then:
        - Validates that the function works as expected.
    """
    client = mocked_client(requests_mock)
    last_run_per_id = create_last_run(["id1", "id2"], "2023-01-01T00:00:00Z")

    events, command_results = get_events_command(client, event_type, last_run_per_id, 10)

    assert len(events) == 6
    assert string_to_table_header(event_type) in command_results.readable_output
    assert command_results.outputs == events
    assert command_results.outputs_prefix == Config.OUTPUTS_PREFIX[event_type]


def test_fetch_events(requests_mock):
    """
    Given:
        - A cyberArk client.

    When:
        - fetch-events command is running.

    Then:
        - Validates that the function works as expected.
    """
    last_run = create_last_run(["id1", "id2"], "2023-01-01T00:00:00Z")
    events, next_run = fetch_events(mocked_client(requests_mock), last_run, 10, True)

    assert len(events) == 18
    assert (
        next_run["id1"]
        == next_run["id2"]
        == {
            "admin_audits": {"from_date": "2023-12-12T07:45:27.141Z"},
            "detailed_events": {"from_date": "2023-12-12T06:59:18.141Z", "next_cursor": "start"},
            "policy_audits": {"from_date": "2023-12-11T13:09:56.056Z", "next_cursor": "start"},
        }
    )


@pytest.mark.parametrize(
    "event_type, last_fetch, expected_next_cursor, expected_from_date",
    [
        # Test Case 1: Zero events with next_cursor="start" (pagination complete, no new events)
        ("policy_audits", {"events": [], "next_cursor": "start"}, "start", "2023-01-01T00:00:00.000Z"),
        # Test Case 2: Zero events with next_cursor="some_cursor" (pagination ongoing but empty page)
        ("detailed_events", {"events": [], "next_cursor": "new_cursor_123"}, "new_cursor_123", "2023-01-01T00:00:00.000Z"),
        # Test Case 3: Events exist with next_cursor="start" (pagination complete with events)
        (
            "policy_audits",
            {"events": [{"_time": "2023-12-11T13:09:56.055Z"}, {"_time": "2023-12-11T13:09:56.056Z"}], "next_cursor": "start"},
            "start",
            "2023-12-11T13:09:56.057Z",
        ),
    ],
)
def test_prepare_next_run_with_zero_events(event_type, last_fetch, expected_next_cursor, expected_from_date):
    """
    Given:
        - A last_run dict and last_fetch results.

    When:
        1. Zero events and next_cursor="start" (pagination complete with zero events)
        2. Zero events and next_cursor="some_cursor" (pagination ongoing with zero events)
        3. Events exist and next_cursor="start" (pagination complete with events)

    Then:
        1. next_cursor is always updated, even when 0 events are fetched
        2. from_date is NOT updated when 0 events are fetched (to avoid crash)
        3. from_date IS updated when events exist and pagination completes
    """
    last_run = {"set123": {event_type: {"from_date": "2023-01-01T00:00:00.000Z", "next_cursor": "old_cursor"}}}

    prepare_next_run("set123", event_type, last_run, last_fetch)

    assert last_run["set123"][event_type]["next_cursor"] == expected_next_cursor
    assert last_run["set123"][event_type]["from_date"] == expected_from_date


""" TEST OAUTH (IDIRA) AUTHENTICATION """


def test_oauth_uses_server_url_as_base_url(mocker, requests_mock):
    """
    Given:
        - An Idira OAuth configuration with a Server URL, Identity URL, and Web App ID.

    When:
        - Building the Client (which performs the OAuth authentication flow).

    Then:
        - The token is requested from the Identity URL token endpoint.
        - No tenant-URL discovery call is made; the Server URL is used directly.
        - The base URL is built from the Server URL with the versioned EPM SET API path,
          and the Bearer header is set from the token response.
    """
    mocker.patch("CyberArkEPMEventCollector.get_integration_context", return_value={})
    mocker.patch("CyberArkEPMEventCollector.set_integration_context")

    identity_url = "https://tenant.id.cyberark.cloud"
    server_url = "https://example.epm.cyberark.com"

    token_matcher = requests_mock.post(
        f"{identity_url}/oauth2/token/web-app-1", json={"access_token": "TOKEN123", "expires_in": 900}
    )

    client = Client(
        base_url="",
        username="user",
        password="pass",
        application_id="1",
        auth_method="Idira OAuth",
        identity_url=identity_url,
        web_app_id="web-app-1",
        server_url=server_url,
    )

    assert token_matcher.called
    # Only the token endpoint should have been called (no tenant-URL discovery).
    assert requests_mock.call_count == 1
    assert client._headers["Authorization"] == "Bearer TOKEN123"
    # Data calls must use the uppercase, versioned EPM SET API path (matches CyberArk Postman).
    assert client._base_url == f"{server_url}/EPM/API/"


def test_client_configuration_debug_log_for_oauth(mocker, requests_mock):
    """
    Given:
        - An Idira OAuth configuration.

    When:
        - Building the Client.

    Then:
        - A single configuration debug log records the OAuth-relevant fields.
        - Neither the username, the password, nor the access token appear in any log line.
    """
    mocker.patch("CyberArkEPMEventCollector.get_integration_context", return_value={})
    mocker.patch("CyberArkEPMEventCollector.set_integration_context")
    debug = mocker.patch("CyberArkEPMEventCollector.demisto.debug")

    identity_url = "https://tenant.id.cyberark.cloud"
    server_url = "https://example.epm.cyberark.com"
    requests_mock.post(f"{identity_url}/oauth2/token/web-app-1", json={"access_token": "TOKEN123", "expires_in": 900})

    Client(
        base_url="",
        username="secret-user",
        password="secret-pass",
        application_id="1",
        auth_method="Idira OAuth",
        identity_url=identity_url,
        web_app_id="web-app-1",
        server_url=server_url,
    )

    config_logs = [call.args[0] for call in debug.call_args_list if call.args[0].startswith("[Client] Configuration:")]
    assert len(config_logs) == 1
    config_log = config_logs[0]
    for expected in ("Idira OAuth", identity_url, server_url, "web-app-1", "has_username=True", "has_password=True"):
        assert expected in config_log

    all_logs = " ".join(call.args[0] for call in debug.call_args_list)
    for secret in ("secret-user", "secret-pass", "TOKEN123"):
        assert secret not in all_logs


def test_client_configuration_debug_log_for_epm(requests_mock, mocker):
    """
    Given:
        - An EPM (non-OAuth) configuration.

    When:
        - Building the Client.

    Then:
        - The configuration debug log records the EPM-relevant fields, so the log is useful for
          every authentication method and not only for OAuth.
        - The credentials do not appear in any log line.
    """
    debug = mocker.patch("CyberArkEPMEventCollector.demisto.debug")
    requests_mock.post(
        "https://example.epm.cyberark.com/EPM/API/Auth/EPM/Logon",
        json={"EPMAuthenticationResult": "TOKEN", "ManagerURL": "https://example.manager.cyberark.com"},
    )

    Client(
        base_url="https://example.epm.cyberark.com",
        username="secret-user",
        password="secret-pass",
        application_id="app-1",
        auth_method="EPM",
    )

    config_logs = [call.args[0] for call in debug.call_args_list if call.args[0].startswith("[Client] Configuration:")]
    assert len(config_logs) == 1
    config_log = config_logs[0]
    for expected in ("'EPM'", "example.manager.cyberark.com", "app-1", "has_username=True", "has_password=True"):
        assert expected in config_log

    all_logs = " ".join(call.args[0] for call in debug.call_args_list)
    for secret in ("secret-user", "secret-pass"):
        assert secret not in all_logs


def test_client_configuration_debug_log_for_saml(requests_mock, mocker):
    """
    Given:
        - A SAML configuration.

    When:
        - Building the Client.

    Then:
        - The configuration debug log records the SAML-relevant fields, completing coverage of all
          three authentication methods.
        - The credentials and the SAML assertion do not appear in any log line.
    """
    debug = mocker.patch("CyberArkEPMEventCollector.demisto.debug")
    mocker.patch.object(Client, "get_saml_response", return_value="SAML-ASSERTION")
    requests_mock.post(
        "https://example.epm.cyberark.com/SAML/Logon",
        json={"EPMAuthenticationResult": "TOKEN", "ManagerURL": "https://example.manager.cyberark.com"},
    )

    Client(
        base_url="https://example.epm.cyberark.com",
        username="secret-user",
        password="secret-pass",
        application_id="1",
        auth_method="SAML",
        authentication_url="https://example.okta.com/api/v1/authn",
        application_url="https://example.okta.com/home/app/id",
    )

    config_logs = [call.args[0] for call in debug.call_args_list if call.args[0].startswith("[Client] Configuration:")]
    assert len(config_logs) == 1
    config_log = config_logs[0]
    for expected in ("'SAML'", "example.okta.com/api/v1/authn", "example.okta.com/home/app/id"):
        assert expected in config_log

    all_logs = " ".join(call.args[0] for call in debug.call_args_list)
    for secret in ("secret-user", "secret-pass", "SAML-ASSERTION"):
        assert secret not in all_logs


def test_client_configuration_debug_log_reports_missing_credentials(requests_mock, mocker):
    """
    Given:
        - A configuration where no username or password was supplied.

    When:
        - Building the Client.

    Then:
        - The presence booleans report False, so the log distinguishes "credential missing" from
          "credential supplied" without ever revealing the value itself.
    """
    debug = mocker.patch("CyberArkEPMEventCollector.demisto.debug")
    requests_mock.post(
        "https://example.epm.cyberark.com/EPM/API/Auth/EPM/Logon",
        json={"EPMAuthenticationResult": "TOKEN", "ManagerURL": "https://example.manager.cyberark.com"},
    )

    Client(
        base_url="https://example.epm.cyberark.com",
        username="",
        password=None,
        application_id="1",
        auth_method="EPM",
    )

    config_log = next(call.args[0] for call in debug.call_args_list if call.args[0].startswith("[Client] Configuration:"))
    assert "has_username=False" in config_log
    assert "has_password=False" in config_log


OAUTH_IDENTITY_URL = "https://tenant.id.cyberark.cloud"
OAUTH_SERVER_URL = "https://example.epm.cyberark.com"


def _mock_oauth_token(mocker, requests_mock):
    """Patch the integration context and stub the OAuth token endpoint."""
    mocker.patch("CyberArkEPMEventCollector.get_integration_context", return_value={})
    mocker.patch("CyberArkEPMEventCollector.set_integration_context")
    mocker.patch("CyberArkEPMEventCollector.demisto.debug")
    requests_mock.post(f"{OAUTH_IDENTITY_URL}/oauth2/token/web-app-1", json={"access_token": "TOKEN123", "expires_in": 900})


def _build_oauth_client_versionless(mocker, requests_mock) -> Client:
    """Build an authenticated Idira OAuth Client, with the token endpoint stubbed."""
    _mock_oauth_token(mocker, requests_mock)
    return Client(
        base_url="",
        username="user",
        password="pass",
        application_id="1",
        auth_method="Idira OAuth",
        identity_url=OAUTH_IDENTITY_URL,
        web_app_id="web-app-1",
        server_url=OAUTH_SERVER_URL,
    )


def test_oauth_base_url_is_always_version_less(mocker, requests_mock):
    """
    Given:
        - An Idira OAuth configuration.

    When:
        - Building the Client (which performs the OAuth authentication flow).

    Then:
        - The data-plane base URL is the version-less form `/EPM/API/`, which CyberArk resolves to
          whichever version the tenant currently runs. A pinned version segment is only ever a
          routing token that can go stale, and when it does the request fails as a bare 404 with
          nothing to explain it. Confirmed against a live tenant: `GET /EPM/API/Sets` returned 200.
        - There is no empty path segment, which is what a "/EPM/API//" form would produce and which
          the EPM router answers with a 404.
    """
    client = _build_oauth_client_versionless(mocker, requests_mock)

    assert client._base_url == f"{OAUTH_SERVER_URL}/EPM/API/"
    assert "//" not in client._base_url.removeprefix("https://")


@pytest.mark.parametrize(
    "raw_value, expected",
    [
        pytest.param(None, None, id="not_configured_stays_none"),
        pytest.param("", None, id="empty_string_stays_none"),
        pytest.param("   ", None, id="whitespace_only_stays_none"),
        pytest.param("/", None, id="slash_only_stays_none"),
        pytest.param(
            "https://example.epm.cyberark.com",
            "https://example.epm.cyberark.com",
            id="already_normalized_is_unchanged",
        ),
        pytest.param(
            "https://example.epm.cyberark.com/",
            "https://example.epm.cyberark.com",
            id="trailing_slash_is_trimmed",
        ),
        pytest.param(
            "  https://example.epm.cyberark.com//  ",
            "https://example.epm.cyberark.com",
            id="surrounding_whitespace_and_repeated_slashes_are_trimmed",
        ),
    ],
)
def test_normalize_server_url(raw_value, expected):
    """
    Given:
        - A *Server URL* parameter value: unset/empty, whitespace or slash only, already normalized,
          or padded with whitespace and trailing slashes.

    When:
        - Normalizing the raw parameter at the parameter-parsing layer.

    Then:
        - Trailing slashes and surrounding whitespace are removed, so joining the value into a path
          cannot produce duplicated slashes.
        - A value that is empty once trimmed becomes None rather than an empty string, so the
          missing-Server-URL error still triggers instead of building a relative URL.
    """
    assert normalize_server_url(raw_value) == expected


def test_oauth_base_url_has_no_double_slash_in_path(mocker, requests_mock):
    """
    Given:
        - An Idira OAuth configuration built from already-normalized parameters.

    When:
        - Building the Client.

    Then:
        - The server URL and the EPM SET API path are joined without duplicated slashes.
    """
    client = _build_oauth_client_versionless(mocker, requests_mock)

    assert client._base_url == f"{OAUTH_SERVER_URL}/EPM/API/"
    assert "//" not in client._base_url.removeprefix("https://")


def test_epm_auth_method_base_url_comes_from_the_logon_response(requests_mock):
    """
    Given:
        - An EPM (non-OAuth) configuration.

    When:
        - Building the Client.

    Then:
        - The base URL is resolved from the logon response's ManagerURL and is untouched by the
          version-less change, which is scoped to the Idira OAuth flow.
    """
    requests_mock.post(
        "https://example.epm.cyberark.com/EPM/API/Auth/EPM/Logon",
        json={"EPMAuthenticationResult": "TOKEN", "ManagerURL": "https://example.manager.cyberark.com"},
    )

    client = Client(
        base_url="https://example.epm.cyberark.com",
        username="user",
        password="pass",
        application_id="1",
        auth_method="EPM",
    )

    assert client._base_url.startswith("https://example.manager.cyberark.com")


def test_oauth_token_refresh_keeps_the_version_less_base_url(mocker, requests_mock):
    """
    Given:
        - An authenticated Idira OAuth Client.

    When:
        - A data request returns 401, triggering the token refresh which re-runs the OAuth flow and
          therefore rebuilds the base URL.

    Then:
        - The rebuilt base URL is still the version-less form, and the retried request succeeds
          against it. A refresh must not quietly reintroduce a version segment.
    """
    client = _build_oauth_client_versionless(mocker, requests_mock)

    data_matcher = requests_mock.get(
        f"{OAUTH_SERVER_URL}/EPM/API/Sets",
        [
            {"status_code": 401, "json": {"error": "unauthorized"}},
            {"status_code": 200, "json": {"Sets": [{"Id": "id1", "Name": "set_name1"}]}},
        ],
    )

    result = client.get_set_list()

    assert result == {"Sets": [{"Id": "id1", "Name": "set_name1"}]}
    assert data_matcher.call_count == 2
    assert client._base_url == f"{OAUTH_SERVER_URL}/EPM/API/"


def test_oauth_data_call_uses_the_version_less_path(mocker, requests_mock):
    """
    Given:
        - An authenticated Idira OAuth Client.

    When:
        - A data request is issued against the Sets endpoint.

    Then:
        - The request reaches the version-less URL on the wire, proving the base URL is not merely
          stored on the client but is what the request actually uses.
    """
    client = _build_oauth_client_versionless(mocker, requests_mock)

    data_matcher = requests_mock.get(f"{OAUTH_SERVER_URL}/EPM/API/Sets", json={"Sets": [{"Id": "id1", "Name": "set_name1"}]})

    result = client.get_set_list()

    assert result == {"Sets": [{"Id": "id1", "Name": "set_name1"}]}
    assert data_matcher.call_count == 1


def test_oauth_missing_server_url_raises(mocker, requests_mock):
    """
    Given:
        - An Idira OAuth configuration WITHOUT a Server URL.

    When:
        - Building the Client (which performs the OAuth authentication flow).

    Then:
        - A DemistoException is raised indicating the Server URL is required.
    """
    mocker.patch("CyberArkEPMEventCollector.get_integration_context", return_value={})
    mocker.patch("CyberArkEPMEventCollector.set_integration_context")

    identity_url = "https://tenant.id.cyberark.cloud"
    token_matcher = requests_mock.post(
        f"{identity_url}/oauth2/token/web-app-1", json={"access_token": "TOKEN123", "expires_in": 900}
    )

    with pytest.raises(DemistoException, match="Server URL is required"):
        Client(
            base_url="",
            username="user",
            password="pass",
            application_id="1",
            auth_method="Idira OAuth",
            identity_url=identity_url,
            web_app_id="web-app-1",
            server_url="",
        )

    # The Server URL guard runs before any token request, so the token endpoint must never be hit.
    assert token_matcher.call_count == 0


def test_test_module_succeeds_against_the_version_less_path(mocker, requests_mock):
    """
    Given:
        - An Idira OAuth instance, whose data-plane URL is the version-less `/EPM/API/` form.
        - A tenant that serves that path, as confirmed in production against a live tenant:
          `GET /EPM/API/Sets` returned 200.

    When:
        - Running test-module, which performs a real 5-event fetch before calling `get_set_list`.

    Then:
        - It returns "ok", and every request went to the version-less URL. No request carries a
          version segment, and none contains the "//" that an empty segment would produce.
    """
    client = _build_oauth_client_versionless(mocker, requests_mock)
    sets_matcher = requests_mock.get(f"{OAUTH_SERVER_URL}/EPM/API/Sets", json={"Sets": []})

    assert run_test_module(client=client, last_run={}) == "ok"

    assert sets_matcher.called
    requested = [request.url for request in requests_mock.request_history if "/EPM/API/" in request.url]
    assert requested, "expected at least one EPM data call"
    for url in requested:
        assert "/EPM/API/Sets" in url
        assert "//" not in url.removeprefix("https://")


def test_fetch_events_uses_the_version_less_path(mocker, requests_mock):
    """
    Given:
        - An Idira OAuth instance.
        - A tenant that resolves a set name and returns events on the version-less path.

    When:
        - Resolving the set names and running a fetch, which is the same chain test-module drives.

    Then:
        - The set is resolved and the fetch completes, so the version-less path works for the
          event endpoints too - not only for the single `Sets` call. The version segment lived
          inside the base URL and was never logged per call, which is exactly how a stale pin
          hid for so long.
    """
    mocker.patch("CyberArkEPMEventCollector.demisto.info")

    client = _build_oauth_client_versionless(mocker, requests_mock)

    set_name = "Contoso, Ltd. - Workstations"
    requests_mock.get(f"{OAUTH_SERVER_URL}/EPM/API/Sets", json={"Sets": [{"Name": set_name, "Id": "set-id-1"}]})
    requests_mock.post(f"{OAUTH_SERVER_URL}/EPM/API/Sets/set-id-1/policyaudits/search", json={"PolicyAudits": []})
    requests_mock.post(f"{OAUTH_SERVER_URL}/EPM/API/Sets/set-id-1/Events/Search", json={"events": []})

    set_ids = get_set_ids_by_set_names(client, [set_name])
    assert set_ids == ["set-id-1"]

    last_run = create_last_run(set_ids, "2026-09-02T00:00:00Z")
    events, next_run = fetch_events(client=client, last_run=last_run, max_fetch=5)

    assert events == []
    assert list(next_run.keys()) == ["set-id-1"]
    requested = [request.url for request in requests_mock.request_history if "/EPM/API/" in request.url]
    assert len(requested) >= 3, "expected the Sets call plus both event endpoints"
    for url in requested:
        assert "//" not in url.removeprefix("https://")


def _build_oauth_client(requests_mock, identity_url, server_url):
    """Helper: build an Idira OAuth Client with the token endpoint mocked.

    Returns a tuple of (client, token_matcher) so callers can assert on the token
    endpoint call count using the same matcher that actually served the requests.
    """
    token_matcher = requests_mock.post(
        f"{identity_url}/oauth2/token/web-app-1",
        json={"access_token": "TOKEN123", "expires_in": 900},
    )
    client = Client(
        base_url="",
        username="user",
        password="pass",
        application_id="1",
        auth_method="Idira OAuth",
        identity_url=identity_url,
        web_app_id="web-app-1",
        server_url=server_url,
    )
    return client, token_matcher


def test_oauth_token_endpoint_401_raises_without_retry(mocker, requests_mock):
    """
    Given:
        - An Idira OAuth configuration whose token endpoint returns 401 (bad credentials).

    When:
        - Building the Client (which performs the initial OAuth token request).

    Then:
        - The failure surfaces as a clean "Failed to obtain access token" error.
        - The token endpoint is called exactly once (the token request must NOT enter the
          401 refresh-and-retry logic).
    """
    mocker.patch("CyberArkEPMEventCollector.get_integration_context", return_value={})
    mocker.patch("CyberArkEPMEventCollector.set_integration_context")
    # Avoid writing to stdout (the XSOAR test harness fails tests that leave stdout output).
    mocker.patch("CyberArkEPMEventCollector.demisto.error")
    mocker.patch("CyberArkEPMEventCollector.demisto.debug")

    identity_url = "https://tenant.id.cyberark.cloud"
    token_matcher = requests_mock.post(f"{identity_url}/oauth2/token/web-app-1", status_code=401, json={"error": "unauthorized"})

    with pytest.raises(DemistoException, match="Failed to obtain access token"):
        Client(
            base_url="",
            username="user",
            password="pass",
            application_id="1",
            auth_method="Idira OAuth",
            identity_url=identity_url,
            web_app_id="web-app-1",
            server_url="https://example.epm.cyberark.com",
        )

    # Exactly one token call: no refresh-and-retry for the token request itself.
    assert token_matcher.call_count == 1


def test_oauth_data_call_401_refreshes_and_retries_once(mocker, requests_mock):
    """
    Given:
        - A valid Idira OAuth Client.
        - A data endpoint that returns 401 on the first call and 200 on the second.

    When:
        - A data request is made through the overridden `_http_request`.

    Then:
        - The client refreshes the token once and retries the data request exactly once,
          ultimately returning the successful response.
        - The token endpoint is called twice (initial auth + reactive refresh).
    """
    mocker.patch("CyberArkEPMEventCollector.get_integration_context", return_value={})
    mocker.patch("CyberArkEPMEventCollector.set_integration_context")
    # Avoid writing to stdout (the XSOAR test harness fails tests that leave stdout output).
    mocker.patch("CyberArkEPMEventCollector.demisto.error")
    mocker.patch("CyberArkEPMEventCollector.demisto.debug")

    identity_url = "https://tenant.id.cyberark.cloud"
    server_url = "https://example.epm.cyberark.com"

    client, token_matcher = _build_oauth_client(requests_mock, identity_url, server_url)

    data_matcher = requests_mock.get(
        f"{server_url}/EPM/API/Sets",
        [
            {"status_code": 401, "json": {"error": "unauthorized"}},
            {"status_code": 200, "json": {"Sets": [{"Id": "id1", "Name": "set_name1"}]}},
        ],
    )

    result = client._http_request("GET", url_suffix="Sets")

    assert result == {"Sets": [{"Id": "id1", "Name": "set_name1"}]}
    # First auth token call + one reactive refresh after the 401.
    assert token_matcher.call_count == 2
    # Data endpoint hit twice: original 401 + single retry.
    assert data_matcher.call_count == 2


def test_oauth_token_expires_in_as_string_is_handled(mocker, requests_mock):
    """
    Given:
        - An Idira OAuth token response whose `expires_in` value is a string (e.g. "900").

    When:
        - Building the Client (which requests and caches the token).

    Then:
        - No TypeError is raised when computing `valid_until`.
        - The cached `valid_until` is a numeric string derived from the integer TTL.
    """
    saved_context: dict = {}
    mocker.patch("CyberArkEPMEventCollector.get_integration_context", side_effect=lambda: dict(saved_context))
    mocker.patch("CyberArkEPMEventCollector.set_integration_context", side_effect=lambda ctx: saved_context.update(ctx))
    mocker.patch("CyberArkEPMEventCollector.demisto.debug")
    mocker.patch("CyberArkEPMEventCollector.time.time", return_value=1000)

    identity_url = "https://tenant.id.cyberark.cloud"
    server_url = "https://example.epm.cyberark.com"
    # `expires_in` returned as a string.
    requests_mock.post(f"{identity_url}/oauth2/token/web-app-1", json={"access_token": "TOKEN123", "expires_in": "900"})

    client = Client(
        base_url="",
        username="user",
        password="pass",
        application_id="1",
        auth_method="Idira OAuth",
        identity_url=identity_url,
        web_app_id="web-app-1",
        server_url=server_url,
    )

    assert client._headers["Authorization"] == "Bearer TOKEN123"
    # valid_until = current_time (1000) + 900 - Config.CACHE_BUFFER_SECONDS.
    assert saved_context["valid_until"] == str(1000 + 900 - Config.CACHE_BUFFER_SECONDS)


def test_oauth_valid_cached_token_skips_token_endpoint(mocker, requests_mock):
    """
    Given:
        - An Idira OAuth Client with a still-valid token cached in the integration context.

    When:
        - Building the Client (which resolves the access token via `_get_access_token`).

    Then:
        - The cached token is used directly.
        - The token endpoint is never called (zero token requests).
        - The Authorization header reflects the cached token.
    """
    mocker.patch("CyberArkEPMEventCollector.demisto.debug")
    # `time.time()` = 1000; cached token valid until 5000 -> still valid.
    mocker.patch("CyberArkEPMEventCollector.time.time", return_value=1000)
    mocker.patch(
        "CyberArkEPMEventCollector.get_integration_context",
        return_value={Config.ACCESS_TOKEN: "CACHED_TOKEN", Config.VALID_UNTIL: "5000"},
    )
    set_context = mocker.patch("CyberArkEPMEventCollector.set_integration_context")

    identity_url = "https://tenant.id.cyberark.cloud"
    server_url = "https://example.epm.cyberark.com"
    token_matcher = requests_mock.post(
        f"{identity_url}/oauth2/token/web-app-1", json={"access_token": "FRESH_TOKEN", "expires_in": 900}
    )

    client = Client(
        base_url="",
        username="user",
        password="pass",
        application_id="1",
        auth_method="Idira OAuth",
        identity_url=identity_url,
        web_app_id="web-app-1",
        server_url=server_url,
    )

    assert client._headers["Authorization"] == "Bearer CACHED_TOKEN"
    # A valid cache means no token endpoint call and no context rewrite.
    assert token_matcher.call_count == 0
    assert set_context.call_count == 0


def test_oauth_expired_cached_token_requests_new_token(mocker, requests_mock):
    """
    Given:
        - An Idira OAuth Client with an EXPIRED token cached in the integration context.

    When:
        - Building the Client (which resolves the access token via `_get_access_token`).

    Then:
        - Exactly one token request is issued to refresh the expired token.
        - The integration context is rewritten with the new token and validity.
        - The Authorization header reflects the new token.
    """
    saved_context: dict = {Config.ACCESS_TOKEN: "OLD_TOKEN", Config.VALID_UNTIL: "500"}
    mocker.patch("CyberArkEPMEventCollector.demisto.debug")
    # `time.time()` = 1000; cached token valid only until 500 -> expired.
    mocker.patch("CyberArkEPMEventCollector.time.time", return_value=1000)
    mocker.patch("CyberArkEPMEventCollector.get_integration_context", side_effect=lambda: dict(saved_context))
    set_context = mocker.patch(
        "CyberArkEPMEventCollector.set_integration_context", side_effect=lambda ctx: saved_context.update(ctx)
    )

    identity_url = "https://tenant.id.cyberark.cloud"
    server_url = "https://example.epm.cyberark.com"
    token_matcher = requests_mock.post(
        f"{identity_url}/oauth2/token/web-app-1", json={"access_token": "NEW_TOKEN", "expires_in": 900}
    )

    client = Client(
        base_url="",
        username="user",
        password="pass",
        application_id="1",
        auth_method="Idira OAuth",
        identity_url=identity_url,
        web_app_id="web-app-1",
        server_url=server_url,
    )

    assert client._headers["Authorization"] == "Bearer NEW_TOKEN"
    # Exactly one token request for the expired cache, and the context was rewritten.
    assert token_matcher.call_count == 1
    assert set_context.call_count == 1
    assert saved_context[Config.ACCESS_TOKEN] == "NEW_TOKEN"
    assert saved_context[Config.VALID_UNTIL] == str(1000 + 900 - Config.CACHE_BUFFER_SECONDS)


def test_oauth_corrupt_valid_until_falls_through_to_fresh_token(mocker, requests_mock):
    """
    Given:
        - An Idira OAuth Client whose cached `valid_until` is not a number (e.g. "not-a-number").

    When:
        - Building the Client (which resolves the access token via `_get_access_token`).

    Then:
        - No exception is raised while parsing the corrupt cache.
        - The client falls through to a fresh token request (exactly one).
        - The Authorization header reflects the freshly requested token.
    """
    mocker.patch("CyberArkEPMEventCollector.demisto.debug")
    mocker.patch("CyberArkEPMEventCollector.time.time", return_value=1000)
    mocker.patch(
        "CyberArkEPMEventCollector.get_integration_context",
        return_value={Config.ACCESS_TOKEN: "CACHED_TOKEN", Config.VALID_UNTIL: "not-a-number"},
    )
    mocker.patch("CyberArkEPMEventCollector.set_integration_context")

    identity_url = "https://tenant.id.cyberark.cloud"
    server_url = "https://example.epm.cyberark.com"
    token_matcher = requests_mock.post(
        f"{identity_url}/oauth2/token/web-app-1", json={"access_token": "FRESH_TOKEN", "expires_in": 900}
    )

    client = Client(
        base_url="",
        username="user",
        password="pass",
        application_id="1",
        auth_method="Idira OAuth",
        identity_url=identity_url,
        web_app_id="web-app-1",
        server_url=server_url,
    )

    assert client._headers["Authorization"] == "Bearer FRESH_TOKEN"
    # The corrupt cache is ignored and a single fresh token request is made.
    assert token_matcher.call_count == 1


def test_oauth_force_refresh_bypasses_valid_cache(mocker, requests_mock):
    """
    Given:
        - An Idira OAuth Client with a still-valid cached token.

    When:
        - `_get_access_token(force_refresh=True)` is called explicitly.

    Then:
        - The valid cache is ignored and a fresh token is requested.
        - The freshly requested token (not the cached one) is returned.
    """
    mocker.patch("CyberArkEPMEventCollector.demisto.debug")
    mocker.patch("CyberArkEPMEventCollector.time.time", return_value=1000)
    mocker.patch("CyberArkEPMEventCollector.set_integration_context")

    identity_url = "https://tenant.id.cyberark.cloud"
    server_url = "https://example.epm.cyberark.com"

    # Initial build: empty cache -> one token request returning CACHED_TOKEN.
    mocker.patch(
        "CyberArkEPMEventCollector.get_integration_context",
        return_value={Config.ACCESS_TOKEN: "CACHED_TOKEN", Config.VALID_UNTIL: "5000"},
    )
    token_matcher = requests_mock.post(
        f"{identity_url}/oauth2/token/web-app-1", json={"access_token": "FRESH_TOKEN", "expires_in": 900}
    )

    client = Client(
        base_url="",
        username="user",
        password="pass",
        application_id="1",
        auth_method="Idira OAuth",
        identity_url=identity_url,
        web_app_id="web-app-1",
        server_url=server_url,
    )
    # Build used the valid cache -> no token request yet.
    assert token_matcher.call_count == 0

    token = client._get_access_token(force_refresh=True)

    assert token == "FRESH_TOKEN"
    # force_refresh must bypass the valid cache and issue exactly one token request.
    assert token_matcher.call_count == 1


def test_oauth_missing_access_token_in_response_raises(mocker, requests_mock):
    """
    Given:
        - An Idira OAuth token endpoint that returns HTTP 200 but omits `access_token`.

    When:
        - Building the Client (which requests the token).

    Then:
        - A DemistoException is raised indicating the response is missing the access token.
    """
    mocker.patch("CyberArkEPMEventCollector.get_integration_context", return_value={})
    mocker.patch("CyberArkEPMEventCollector.set_integration_context")
    mocker.patch("CyberArkEPMEventCollector.demisto.debug")

    identity_url = "https://tenant.id.cyberark.cloud"
    requests_mock.post(f"{identity_url}/oauth2/token/web-app-1", json={"expires_in": 900})

    with pytest.raises(DemistoException, match="missing access_token"):
        Client(
            base_url="",
            username="user",
            password="pass",
            application_id="1",
            auth_method="Idira OAuth",
            identity_url=identity_url,
            web_app_id="web-app-1",
            server_url="https://example.epm.cyberark.com",
        )


def test_oauth_data_call_non_401_error_propagates_without_refresh(mocker, requests_mock):
    """
    Given:
        - A valid Idira OAuth Client.
        - A data endpoint that fails with a NON-401 error (e.g. 500 Server Error).

    When:
        - A data request is made through the overridden `_http_request`.

    Then:
        - The original exception propagates unchanged.
        - No token refresh occurs (the token endpoint is called only once, for initial auth).
        - The data endpoint is called only once (no retry).
    """
    mocker.patch("CyberArkEPMEventCollector.get_integration_context", return_value={})
    mocker.patch("CyberArkEPMEventCollector.set_integration_context")
    mocker.patch("CyberArkEPMEventCollector.demisto.error")
    mocker.patch("CyberArkEPMEventCollector.demisto.debug")

    identity_url = "https://tenant.id.cyberark.cloud"
    server_url = "https://example.epm.cyberark.com"

    client, token_matcher = _build_oauth_client(requests_mock, identity_url, server_url)

    data_matcher = requests_mock.get(f"{server_url}/EPM/API/Sets", status_code=500, json={"error": "server error"})

    with pytest.raises(DemistoException):
        client._http_request("GET", url_suffix="Sets")

    # Only the initial auth token request; no reactive refresh for a non-401 error.
    assert token_matcher.call_count == 1
    # The data endpoint is hit once and NOT retried.
    assert data_matcher.call_count == 1


def test_is_unauthorized_error_incidental_401_not_treated_as_unauthorized():
    """
    Given:
        - A DemistoException with no response object, whose message merely contains "401"
          incidentally (e.g. as part of a set ID) rather than as an HTTP status.

    When:
        - `Client._is_unauthorized_error` inspects the exception.

    Then:
        - A message whose "401" is a standalone HTTP status token IS treated as unauthorized.
        - A message where "401" is embedded inside another token (e.g. "S40199") is NOT.
    """
    # A genuine 401 status token in the message is still recognized (fallback path).
    assert Client._is_unauthorized_error(DemistoException("Error in API call [401] - Unauthorized")) is True
    # "401" embedded inside an unrelated identifier must NOT be treated as unauthorized.
    assert Client._is_unauthorized_error(DemistoException("No events for set S40199")) is False


def test_client_defaults_to_epm_when_auth_method_missing(requests_mock):
    """
    Given:
        - A Client configuration WITHOUT an explicit `auth_method` and WITHOUT SAML URLs.

    When:
        - Building the Client.

    Then:
        - The legacy inference selects the EPM authentication method (no error raised).
    """
    requests_mock.post(
        "https://url.com/EPM/API/Auth/EPM/Logon",
        json={"ManagerURL": "https://mock.com", "EPMAuthenticationResult": "123"},
    )

    client = Client("https://url.com", "test", "123456", "1")

    assert client.auth_method == Config.AUTH_METHOD_EPM


def test_client_defaults_to_saml_when_saml_urls_present(requests_mock, mocker):
    """
    Given:
        - A Client configuration WITHOUT an explicit `auth_method` but WITH both SAML URLs set.

    When:
        - Building the Client.

    Then:
        - The legacy inference selects the SAML authentication method (no error raised).
    """
    # SAML flow performs its own multi-step auth; stub it so we only assert the inference result.
    saml_auth = mocker.patch("CyberArkEPMEventCollector.Client.saml_auth_to_cyber_ark")

    client = Client(
        "https://url.com",
        "test",
        "123456",
        "1",
        authentication_url="https://auth.example.com",
        application_url="https://app.example.com",
    )

    assert client.auth_method == Config.AUTH_METHOD_SAML
    assert saml_auth.call_count == 1


# --- Set names that contain commas -----------------------------------------------------------
# CyberArk EPM appends the account name to every set on a tenant, so an account registered with a
# comma in its name (for example "Northwind Traders, Inc.") puts a comma in every set name. Those
# names cannot be changed from within EPM, so a comma-separated parameter can never express them.
SET_NAME_FIXTURES = util_load_json("test_data/set_names.json")
TENANT_SETS = SET_NAME_FIXTURES["tenant_sets"]
TENANT_SET_WINDOWS = TENANT_SETS[1]
TENANT_SET_LINUX = TENANT_SETS[3]


@pytest.mark.parametrize(
    "raw_value, expected",
    [
        (json.dumps([TENANT_SET_WINDOWS]), [TENANT_SET_WINDOWS]),
        (json.dumps([TENANT_SET_WINDOWS, TENANT_SET_LINUX]), [TENANT_SET_WINDOWS, TENANT_SET_LINUX]),
        (json.dumps(TENANT_SETS), TENANT_SETS),
        # Whitespace around the array and around each element is tolerated.
        (f'  [ "{TENANT_SET_WINDOWS}" ,  "{TENANT_SET_LINUX}" ]  ', [TENANT_SET_WINDOWS, TENANT_SET_LINUX]),
        # Empty strings inside the array are dropped rather than becoming unmatchable names.
        (json.dumps([TENANT_SET_WINDOWS, "", "   "]), [TENANT_SET_WINDOWS]),
        (json.dumps([]), []),
    ],
    ids=[
        "json_single_name_with_commas",
        "json_two_names_with_commas",
        "json_all_five_tenant_sets",
        "json_tolerates_whitespace",
        "json_drops_empty_elements",
        "json_empty_array",
    ],
)
def test_parse_set_names_json_preserves_commas(raw_value, expected):
    """
    Given: A *Set name* parameter written as a JSON array, where the names themselves contain commas.
    When:  parse_set_names parses it.
    Then:  Each name survives whole - the commas inside the names are not treated as separators.
    """
    assert parse_set_names(raw_value) == expected


@pytest.mark.parametrize(
    "raw_value, expected",
    [
        ("Set One", ["Set One"]),
        ("Set One,Set Two", ["Set One", "Set Two"]),
        ("Set One, Set Two", ["Set One", "Set Two"]),
        ("", []),
        (None, []),
        # Already a list (e.g. a value the platform hands back pre-split) passes straight through.
        (["Set One", "Set Two"], ["Set One", "Set Two"]),
    ],
    ids=[
        "single_name",
        "comma_separated",
        "comma_separated_with_spaces",
        "empty_string",
        "none",
        "already_a_list",
    ],
)
def test_parse_set_names_preserves_legacy_behavior(raw_value, expected):
    """
    Given: A *Set name* parameter in the historical comma-separated form.
    When:  parse_set_names parses it.
    Then:  It behaves exactly as argToList did, so no existing instance changes behavior.
    """
    assert parse_set_names(raw_value) == expected


def test_parse_set_names_comma_split_still_breaks_names_containing_commas():
    """
    Given: A set name containing a comma, supplied in the legacy comma-separated form.
    When:  parse_set_names parses it.
    Then:  It is still split into fragments - documenting precisely why JSON is required for such
           names. The legacy behavior is preserved deliberately for backward compatibility.
    """
    assert parse_set_names(TENANT_SET_WINDOWS) == ["NwtWorld-Windows(northwind traders", "inc._11)"]


@pytest.mark.parametrize(
    "raw_value",
    SET_NAME_FIXTURES["malformed_json_values"],
    ids=["unterminated", "single_quotes", "trailing_comma", "valid_array_with_trailing_junk"],
)
def test_parse_set_names_rejects_malformed_json(raw_value):
    """
    Given: A value that clearly intends to be a JSON array but is not valid JSON.
    When:  parse_set_names parses it.
    Then:  It raises immediately, rather than silently falling back to a comma split that would
           produce fragments and a baffling "set not found" error much later.
    """
    with pytest.raises(DemistoException, match="looks like a JSON array"):
        parse_set_names(raw_value)


def test_parse_set_names_accepts_the_full_tenant_set_list():
    """
    Given: A complete five-set tenant list as a JSON array. Every name carries a comma-containing
           account suffix, and the first also contains a slash, an "@" and a dot.
    When:  parse_set_names parses it.
    Then:  All five names come back byte-for-byte intact - the configuration that a comma-separated
           parameter could never express.
    """
    parsed = parse_set_names(json.dumps(TENANT_SETS))

    assert parsed == TENANT_SETS
    assert len(parsed) == 5
    # Every name kept its commas; none was torn into fragments.
    assert all(name.count(",") >= 1 for name in parsed)


def test_parse_set_names_rejects_a_python_style_list():
    """
    Given: A set list pasted in Python repr form, with single quotes instead of double quotes.
           This is a realistic mistake: it is the shape our own error message prints back at the
           operator, so it is tempting to copy it straight into the parameter.
    When:  parse_set_names parses it.
    Then:  It raises with a message naming JSON, rather than silently comma-splitting into
           fragments and failing later with an unrelated-looking "set not found".
    """
    python_repr = str(TENANT_SETS)  # single-quoted - valid Python, invalid JSON
    assert python_repr.startswith("['")

    with pytest.raises(DemistoException, match="looks like a JSON array"):
        parse_set_names(python_repr)


@pytest.mark.parametrize("set_name", SET_NAME_FIXTURES["awkward_names"])
def test_parse_set_names_json_survives_awkward_characters(set_name):
    """
    Given: A single set name containing characters that break naive delimiter parsing - commas,
           quotes, slashes, ampersands, dashes and backslashes.
    When:  parse_set_names parses it as a JSON array.
    Then:  The name is returned as one element, unchanged apart from surrounding whitespace.
    """
    assert parse_set_names(json.dumps([set_name])) == [set_name.strip()]


def test_parse_set_names_json_handles_many_awkward_names_together():
    """
    Given: Several comma-containing names of differing shapes in one JSON array.
    When:  parse_set_names parses it.
    Then:  The count is exact and no name is split - more than twice as many fragments would have
           come back from a naive comma split.
    """
    names = SET_NAME_FIXTURES["multiple_awkward_names"]

    parsed = parse_set_names(json.dumps(names))

    assert parsed == names
    assert len(parsed) == 3
    # The legacy comma split turns these 3 names into 7 fragments, none of which is a real set.
    legacy_fragments = ",".join(names).split(",")
    assert len(legacy_fragments) == 7
    assert not any(fragment.strip() in names for fragment in legacy_fragments)


def test_get_set_ids_resolves_tenant_set_names_from_json(mocker, requests_mock):
    """
    Given: A tenant whose set names all contain commas, configured as a JSON array.
    When:  The full resolution path runs against the API's real set list.
    Then:  The set IDs are resolved - the end-to-end proof that multiple such sets can be
           configured, which no input format allowed before this fix.
    """
    mocker.patch("CyberArkEPMEventCollector.get_integration_context", return_value={})
    mocker.patch("CyberArkEPMEventCollector.set_integration_context")

    identity_url = "https://tenant.id.cyberark.cloud"
    server_url = "https://example.epm.cyberark.com"

    requests_mock.post(f"{identity_url}/oauth2/token/web-app-1", json={"access_token": "TOKEN123", "expires_in": 900})
    requests_mock.get(
        f"{server_url}/EPM/API/Sets",
        json={"Sets": [{"Name": name, "Id": f"id-{index}"} for index, name in enumerate(TENANT_SETS)]},
    )

    client = Client(
        base_url="",
        username="user",
        password="pass",
        application_id="1",
        auth_method="Idira OAuth",
        identity_url=identity_url,
        web_app_id="web-app-1",
        server_url=server_url,
    )

    set_names = parse_set_names(json.dumps([TENANT_SET_WINDOWS, TENANT_SET_LINUX]))
    set_ids = get_set_ids_by_set_names(client, set_names)

    # Both names survived the JSON parse whole and matched the tenant's real set list.
    assert sorted(set_ids) == ["id-1", "id-3"]


""" TEST COMMA-SPLIT REPAIR AGAINST THE TENANT SET LIST """


def test_reconcile_rejoins_the_customers_actual_configuration():
    """
    Given: A single comma-bearing set name entered as plain text, exactly as the customer has it
           configured, which `argToList` has already torn into two fragments.
    When:  Reconciling those fragments against the tenant's real set list.
    Then:  The original name is restored. This is the reported failure, reproduced from the
           production log line
           `names=['CybrWorld-Windows(cyberark software', 'inc._11)']` and then repaired.
    """
    fragments = argToList(TENANT_SET_WINDOWS)
    assert len(fragments) == 2, "the comma split must break this name, or the test proves nothing"

    assert reconcile_split_set_names(fragments, TENANT_SETS) == [TENANT_SET_WINDOWS]


def test_reconcile_rejoins_several_comma_bearing_names_at_once():
    """
    Given: Two comma-bearing set names configured together, which the comma split reduces to four
           meaningless fragments.
    When:  Reconciling against the tenant's set list.
    Then:  Both names are restored, in order. Configuring more than one such set was impossible
           before this repair - the fragments of one name ran into the next.
    """
    fragments = argToList(f"{TENANT_SET_WINDOWS},{TENANT_SET_LINUX}")
    assert len(fragments) == 4

    assert reconcile_split_set_names(fragments, TENANT_SETS) == [TENANT_SET_WINDOWS, TENANT_SET_LINUX]


def test_reconcile_rejoins_every_set_on_the_tenant():
    """
    Given: All five of the tenant's sets configured at once as plain comma-separated text.
    When:  Reconciling against the tenant's set list.
    Then:  All five are restored from the eleven fragments the split produced, proving the repair
           scales past two names and does not mis-pair adjacent ones.
    """
    fragments = argToList(",".join(TENANT_SETS))
    assert len(fragments) == 11

    assert reconcile_split_set_names(fragments, TENANT_SETS) == TENANT_SETS


@pytest.mark.parametrize(
    "configured, tenant, expected",
    [
        pytest.param(["Alpha", "Beta"], ["Alpha", "Beta"], ["Alpha", "Beta"], id="plain_names_are_untouched"),
        pytest.param(["Alpha"], ["Alpha", "Beta"], ["Alpha"], id="single_plain_name"),
        pytest.param([], ["Alpha"], [], id="nothing_configured"),
        pytest.param(["Alpha"], [], ["Alpha"], id="empty_tenant_list_is_a_no_op"),
        pytest.param(["ALPHA"], ["Alpha"], ["Alpha"], id="match_is_case_insensitive_and_returns_the_tenant_spelling"),
    ],
)
def test_reconcile_leaves_unambiguous_input_alone(configured, tenant, expected):
    """
    Given: Configurations that contain no comma-split damage, plus the degenerate empty cases.
    When:  Reconciling against the tenant's set list.
    Then:  The names pass through unchanged. Every existing instance without comma-bearing names
           must behave exactly as it did before, and an empty tenant list must never discard the
           operator's input.
    """
    assert reconcile_split_set_names(configured, tenant) == expected


def test_reconcile_prefers_the_longest_matching_name():
    """
    Given: A tenant that has BOTH "Alpha" and "Alpha, Inc." as set names, and a configuration
           naming only the longer one.
    When:  Reconciling the two fragments the split produced.
    Then:  The longer name wins. Matching the shortest run first would let "Alpha" swallow the
           first fragment and strand ", Inc." - silently collecting events from the wrong set,
           which is worse than failing outright.
    """
    tenant = ["Alpha", "Alpha, Inc.", "Beta"]

    assert reconcile_split_set_names(["Alpha", "Inc."], tenant) == ["Alpha, Inc."]


def test_reconcile_preserves_a_genuine_typo_instead_of_absorbing_it():
    """
    Given: A misspelled set name that matches nothing on the tenant.
    When:  Reconciling against the tenant's set list.
    Then:  The fragments are returned untouched, so the existing "could not resolve" error still
           fires and names them. A repair that quietly attached a typo to some neighbouring set
           would turn a clear configuration error into silent, wrong data collection.
    """
    typo = "CybrWorld-Windwos(cyberark software, inc._11)"
    fragments = argToList(typo)

    assert reconcile_split_set_names(fragments, TENANT_SETS) == fragments


def test_reconcile_handles_names_joined_without_a_space():
    """
    Given: Fragments from a value written without a space after the comma ("a,b" rather than
           "a, b"). `argToList` strips whitespace, so the original spacing is unrecoverable.
    When:  Reconciling against a tenant whose real name has no space after its comma.
    Then:  The name is still restored, because both join forms are tried.
    """
    tenant = ["Contoso,Ltd. - Workstations"]

    assert reconcile_split_set_names(["Contoso", "Ltd. - Workstations"], tenant) == tenant


def test_get_set_ids_resolves_comma_bearing_names_entered_as_plain_text(mocker, requests_mock):
    """
    Given: A tenant whose set names all contain commas, configured the way the customer configures
           them - a plain comma-separated list, with no JSON and no awareness that anything is
           being repaired.
    When:  The full resolution path runs, from the raw parameter through to the set IDs.
    Then:  The IDs resolve. This is the end-to-end proof of the customer-visible fix: the input
           format never changed, only what we do with it after the tenant list arrives.
    """
    mocker.patch("CyberArkEPMEventCollector.get_integration_context", return_value={})
    mocker.patch("CyberArkEPMEventCollector.set_integration_context")
    mocker.patch("CyberArkEPMEventCollector.demisto.info")

    identity_url = "https://tenant.id.cyberark.cloud"
    server_url = "https://example.epm.cyberark.com"

    requests_mock.post(f"{identity_url}/oauth2/token/web-app-1", json={"access_token": "TOKEN123", "expires_in": 900})
    requests_mock.get(
        f"{server_url}/EPM/API/Sets",
        json={"Sets": [{"Name": name, "Id": f"id-{index}"} for index, name in enumerate(TENANT_SETS)]},
    )

    client = Client(
        base_url="",
        username="user",
        password="pass",
        application_id="1",
        auth_method="Idira OAuth",
        identity_url=identity_url,
        web_app_id="web-app-1",
        server_url=server_url,
    )

    # Plain text, exactly as typed into the *Set name* field - no JSON.
    set_names = parse_set_names(f"{TENANT_SET_WINDOWS},{TENANT_SET_LINUX}")
    assert len(set_names) == 4, "the parameter arrives at the resolver already split into fragments"

    assert sorted(get_set_ids_by_set_names(client, set_names)) == ["id-1", "id-3"]


def test_get_set_ids_cache_hits_on_the_second_fetch_for_comma_bearing_names(mocker, requests_mock):
    """
    Given: A comma-bearing set name, and an integration context already holding the resolved
           mapping from a previous fetch - keyed, necessarily, by the REPAIRED name.
    When:  A second fetch resolves the same configured value, which still arrives as fragments.
    Then:  The cache is used and no second `GET /Sets` is issued. The cache is keyed by the
           repaired name while the parameter yields fragments, so comparing the two directly could
           never match and every fetch cycle would re-request the full set list forever.
    """
    mocker.patch("CyberArkEPMEventCollector.demisto.info")
    cached = {TENANT_SET_WINDOWS: "id-1"}
    mocker.patch("CyberArkEPMEventCollector.get_integration_context", return_value={"set_items": cached})
    mocker.patch("CyberArkEPMEventCollector.set_integration_context")

    identity_url = "https://tenant.id.cyberark.cloud"
    server_url = "https://example.epm.cyberark.com"
    requests_mock.post(f"{identity_url}/oauth2/token/web-app-1", json={"access_token": "TOKEN123", "expires_in": 900})
    sets_matcher = requests_mock.get(f"{server_url}/EPM/API/Sets", json={"Sets": []})

    client = Client(
        base_url="",
        username="user",
        password="pass",
        application_id="1",
        auth_method="Idira OAuth",
        identity_url=identity_url,
        web_app_id="web-app-1",
        server_url=server_url,
    )

    set_ids = get_set_ids_by_set_names(client, argToList(TENANT_SET_WINDOWS))

    assert set_ids == ["id-1"]
    assert not sets_matcher.called, "the cached mapping must be reused instead of re-fetching the set list"
