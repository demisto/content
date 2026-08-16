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
    requests_mock.post(f"{identity_url}/oauth2/token/web-app-1", json={"access_token": "TOKEN123", "expires_in": 900})

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
