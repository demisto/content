import datetime
import json

import pytest

""" UTILS """


def util_load_json(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


def mocked_client(requests_mock):
    from CyberArkEPMEventCollector import Client

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
    from CyberArkEPMEventCollector import create_last_run

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
        (datetime.datetime.strptime("2023-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S"), False, "2023-01-01T00:00:00.000Z"),
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
    from CyberArkEPMEventCollector import prepare_datetime

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
    from CyberArkEPMEventCollector import XSIAM_EVENT_TYPE, add_fields_to_events

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
    from CyberArkEPMEventCollector import reconcile_last_run_with_current_sets

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
    from CyberArkEPMEventCollector import get_set_ids_by_set_names

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
    from CyberArkEPMEventCollector import get_set_ids_by_set_names

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
    from CyberArkEPMEventCollector import Config, create_last_run, get_events_command

    from CommonServerPython import string_to_table_header

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
    from CyberArkEPMEventCollector import create_last_run, fetch_events

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
    from CyberArkEPMEventCollector import prepare_next_run

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
    from CyberArkEPMEventCollector import Client

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
    assert client._base_url == f"{server_url}/EPM/API/26.7.0/"


@pytest.mark.parametrize(
    "epm_api_version, expected_version",
    [
        pytest.param(None, "26.7.0", id="not_configured_falls_back_to_default"),
        pytest.param("", "26.7.0", id="empty_string_falls_back_to_default"),
        pytest.param("26.8.0", "26.8.0", id="custom_three_segment_version"),
        pytest.param("26.8", "26.8", id="custom_two_segment_version"),
        pytest.param(" /26.8.0/ ", "26.8.0", id="surrounding_whitespace_and_slashes_are_trimmed"),
    ],
)
def test_oauth_base_url_uses_configured_epm_api_version(mocker, requests_mock, epm_api_version, expected_version):
    """
    Given:
        - An Idira OAuth configuration with the *EPM API Version* parameter set to various values,
          including unset/empty, a three-segment version, a two-segment version, and a value
          padded with whitespace and slashes.

    When:
        - Building the Client (which performs the OAuth authentication flow).

    Then:
        - The EPM SET API base URL embeds the configured version verbatim, apart from trimming
          surrounding whitespace and slashes.
        - When the parameter is unset or empty, the default version is used, so existing instances
          keep their current behavior.
    """
    from CyberArkEPMEventCollector import Client

    mocker.patch("CyberArkEPMEventCollector.get_integration_context", return_value={})
    mocker.patch("CyberArkEPMEventCollector.set_integration_context")
    mocker.patch("CyberArkEPMEventCollector.demisto.debug")

    identity_url = "https://tenant.id.cyberark.cloud"
    server_url = "https://example.epm.cyberark.com"

    requests_mock.post(f"{identity_url}/oauth2/token/web-app-1", json={"access_token": "TOKEN123", "expires_in": 900})

    client = Client(
        base_url="",
        username="user",
        password="pass",
        application_id="1",
        auth_method="Idira OAuth",
        identity_url=identity_url,
        web_app_id="web-app-1",
        server_url=server_url,
        epm_api_version=epm_api_version,
    )

    assert client._base_url == f"{server_url}/EPM/API/{expected_version}/"


def test_oauth_data_call_uses_configured_epm_api_version(mocker, requests_mock):
    """
    Given:
        - An Idira OAuth Client configured with a non-default EPM API version.

    When:
        - A data request is issued against the Sets endpoint.

    Then:
        - The request is sent to the versioned path built from the configured version, proving the
          parameter reaches the wire and is not only stored on the client.
    """
    from CyberArkEPMEventCollector import Client

    mocker.patch("CyberArkEPMEventCollector.get_integration_context", return_value={})
    mocker.patch("CyberArkEPMEventCollector.set_integration_context")
    mocker.patch("CyberArkEPMEventCollector.demisto.debug")

    identity_url = "https://tenant.id.cyberark.cloud"
    server_url = "https://example.epm.cyberark.com"

    requests_mock.post(f"{identity_url}/oauth2/token/web-app-1", json={"access_token": "TOKEN123", "expires_in": 900})
    client = Client(
        base_url="",
        username="user",
        password="pass",
        application_id="1",
        auth_method="Idira OAuth",
        identity_url=identity_url,
        web_app_id="web-app-1",
        server_url=server_url,
        epm_api_version="26.8",
    )

    data_matcher = requests_mock.get(f"{server_url}/EPM/API/26.8/Sets", json={"Sets": [{"Id": "id1", "Name": "set_name1"}]})

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
    from CyberArkEPMEventCollector import Client
    from CommonServerPython import DemistoException

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


def _build_oauth_client(requests_mock, identity_url, server_url):
    """Helper: build an Idira OAuth Client with the token endpoint mocked.

    Returns a tuple of (client, token_matcher) so callers can assert on the token
    endpoint call count using the same matcher that actually served the requests.
    """
    from CyberArkEPMEventCollector import Client

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
    from CyberArkEPMEventCollector import Client
    from CommonServerPython import DemistoException

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
        f"{server_url}/EPM/API/26.7.0/Sets",
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
    from CyberArkEPMEventCollector import Client, Config

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
    from CyberArkEPMEventCollector import Client, Config

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
    from CyberArkEPMEventCollector import Client, Config

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
    from CyberArkEPMEventCollector import Client, Config

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
    from CyberArkEPMEventCollector import Client, Config

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
    from CyberArkEPMEventCollector import Client
    from CommonServerPython import DemistoException

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
    from CommonServerPython import DemistoException

    mocker.patch("CyberArkEPMEventCollector.get_integration_context", return_value={})
    mocker.patch("CyberArkEPMEventCollector.set_integration_context")
    mocker.patch("CyberArkEPMEventCollector.demisto.error")
    mocker.patch("CyberArkEPMEventCollector.demisto.debug")

    identity_url = "https://tenant.id.cyberark.cloud"
    server_url = "https://example.epm.cyberark.com"

    client, token_matcher = _build_oauth_client(requests_mock, identity_url, server_url)

    data_matcher = requests_mock.get(f"{server_url}/EPM/API/26.7.0/Sets", status_code=500, json={"error": "server error"})

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
    from CyberArkEPMEventCollector import Client
    from CommonServerPython import DemistoException

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
    from CyberArkEPMEventCollector import Client, Config

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
    from CyberArkEPMEventCollector import Client, Config

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
