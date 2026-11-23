from datetime import UTC, datetime, timedelta

import CiscoMerakiApiModule
import CommonServerPython
import demistomock as demisto
import pytest
from CiscoMerakiEventCollectorStandardConnector import (
    API_REQUESTS,
    APPLIANCE_SECURITY_EVENTS,
    CONFIGURATION_CHANGES,
    NETWORK_EVENTS,
    PRODUCT,
    VENDOR,
    WINDOWED_EVENT_TYPES,
    CiscoMerakiEventCollectorClient,
    DemistoException,
    EntryType,
    collector_test_module,
    enrich_events,
    event_hash,
    fetch_events_by_type,
    fetch_events_command,
    fetch_network_events,
    fetch_windowed_events,
    format_meraki_time,
    get_events_command,
    main,
    parse_event_types,
)

HOST = "https://api.meraki.com"
BASE_URL = f"{HOST}/api/v1"
ORG_ID = "123"
NOW = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
INTEGRATION = "CiscoMerakiEventCollectorStandardConnector"


@pytest.fixture
def client() -> CiscoMerakiEventCollectorClient:
    return CiscoMerakiEventCollectorClient(organization_id=ORG_ID, base_url=HOST, api_key="key", verify=False, proxy=False)


@pytest.fixture(autouse=True)
def demisto_error(mocker):
    """Capture demisto.error, which writes to stdout (forbidden in unit tests)."""
    return mocker.patch.object(demisto, "error")


@pytest.fixture
def ucp_auth(mocker):
    """Simulate connector-brokered (UCP) API key credentials, without BaseClient injecting a real credential."""
    mocker.patch.object(CiscoMerakiApiModule, "should_use_ucp_auth", return_value=True)
    mocker.patch.object(CiscoMerakiApiModule, "ucp_credentials_are_oauth", return_value=False)
    mocker.patch.object(CommonServerPython, "should_use_ucp_auth", return_value=False)


def config_change(ts: str, label: str = "x") -> dict:
    return {"ts": ts, "label": label}


def test_parse_event_types_defaults_to_all():
    assert parse_event_types(None) == [CONFIGURATION_CHANGES, API_REQUESTS, APPLIANCE_SECURITY_EVENTS, NETWORK_EVENTS]


def test_event_type_display_names_come_from_the_registry():
    """
    Given: the display name of every windowed event type in the registry.
    When:  parsing the event types param.
    Then:  each display name maps to its registry entry, so the registry is the single source of the names.
    """
    displays = [event_type.display for event_type in WINDOWED_EVENT_TYPES.values()]
    assert parse_event_types(",".join(displays)) == list(WINDOWED_EVENT_TYPES)


def test_parse_event_types_maps_display_names():
    assert parse_event_types("API requests,Network events") == [API_REQUESTS, NETWORK_EVENTS]


def test_parse_event_types_rejects_unknown():
    with pytest.raises(DemistoException, match="Unknown event types"):
        parse_event_types("Bogus")


def test_enrich_events_sets_time_and_source_log_type():
    events = enrich_events([{"occurredAt": "2026-01-01T00:00:00Z"}], NETWORK_EVENTS)
    assert events[0]["_time"] == "2026-01-01T00:00:00Z"
    assert events[0]["_source_log_type"] == NETWORK_EVENTS


def test_get_page_returns_body_and_links(client, requests_mock):
    """
    Given: a first page with a rel=next link.
    When:  getting the page.
    Then:  the JSON body and the relationship links are returned.
    """
    next_url = f"{BASE_URL}/organizations/{ORG_ID}/networks?startingAfter=abc"
    requests_mock.get(
        f"{BASE_URL}/organizations/{ORG_ID}/networks", json=[{"id": "1"}], headers={"Link": f'<{next_url}>; rel="next"'}
    )
    page, links = client.get_page(f"organizations/{ORG_ID}/networks")
    assert page == [{"id": "1"}]
    assert links["next"]["url"] == next_url


def test_fetch_windowed_first_run_uses_one_hour_lookback(client, requests_mock):
    """
    Given: no saved state.
    When:  fetching configuration changes.
    Then:  the window is [now - 1h, now] and the next state records the window end.
    """
    mock = requests_mock.get(
        f"{BASE_URL}/organizations/{ORG_ID}/configurationChanges", json=[config_change("2026-01-01T11:30:00Z")]
    )
    events, state = fetch_windowed_events(client, WINDOWED_EVENT_TYPES[CONFIGURATION_CHANGES], {}, 100, NOW)
    assert len(events) == 1
    assert mock.last_request.qs["t0"] == ["2026-01-01t11:00:00z"]
    assert mock.last_request.qs["t1"] == ["2026-01-01t12:00:00z"]
    assert state["last_window_end"] == "2026-01-01T12:00:00Z"
    assert "next_url" not in state


def test_fetch_windowed_clamps_to_max_lookback(client, requests_mock):
    mock = requests_mock.get(f"{BASE_URL}/organizations/{ORG_ID}/apiRequests", json=[])
    fetch_windowed_events(client, WINDOWED_EVENT_TYPES[API_REQUESTS], {"last_window_end": "2025-01-01T00:00:00Z"}, 100, NOW)
    assert mock.last_request.qs["t0"] == [format_meraki_time(NOW - timedelta(days=31)).lower()]


def test_fetch_windowed_saves_next_url_when_budget_reached(client, requests_mock):
    """
    Given: a page with a rel=next link and a budget equal to the page size.
    When:  fetching.
    Then:  the next URL and the current window are saved for the next cycle.
    """
    next_link = f"{BASE_URL}/organizations/{ORG_ID}/configurationChanges?startingAfter=abc"
    requests_mock.get(
        f"{BASE_URL}/organizations/{ORG_ID}/configurationChanges",
        json=[
            config_change("2026-01-01T11:10:00Z", "a"),
            config_change("2026-01-01T11:11:00Z", "b"),
            config_change("2026-01-01T11:12:00Z", "c"),
        ],
        headers={"Link": f'<{next_link}>; rel="next"'},
    )
    events, state = fetch_windowed_events(client, WINDOWED_EVENT_TYPES[CONFIGURATION_CHANGES], {}, 3, NOW)
    assert len(events) == 3
    assert state["next_url"] == next_link
    assert state["window_end"] == "2026-01-01T12:00:00Z"


@pytest.mark.parametrize(
    "event_type, limit, expected_per_page",
    [
        (CONFIGURATION_CHANGES, 10000, "10000"),  # the endpoint accepts up to 100,000 per page: one request covers the limit
        (CONFIGURATION_CHANGES, 500, "500"),  # a small limit is never exceeded
        (CONFIGURATION_CHANGES, 250000, "100000"),  # capped at the endpoint maximum, the rest comes from pagination
        (API_REQUESTS, 10000, "1000"),  # the endpoint maximum is 1,000 per page: pagination is needed
        (APPLIANCE_SECURITY_EVENTS, 10000, "1000"),
    ],
)
def test_fetch_windowed_requests_the_largest_page_that_fits_the_limit(
    client, requests_mock, event_type, limit, expected_per_page
):
    """
    Given: a per-type event limit and an endpoint with its own maximum page size.
    When:  fetching the first page.
    Then:  perPage is the smaller of the limit and the endpoint maximum, so a high limit is served by as few requests as possible.
    """
    mock = requests_mock.get(
        f"{BASE_URL}/{WINDOWED_EVENT_TYPES[event_type].url_template.format(organization_id=ORG_ID)}", json=[]
    )
    fetch_windowed_events(client, WINDOWED_EVENT_TYPES[event_type], {}, limit, NOW)
    assert mock.call_count == 1
    assert mock.last_request.qs["perpage"] == [expected_per_page]


def test_fetch_windowed_configuration_changes_single_request_for_default_limit(client, requests_mock):
    """
    Given: the default limit of 10,000 and fewer events than that in the window.
    When:  fetching configuration changes.
    Then:  exactly one request is made and the window is completed.
    """
    mock = requests_mock.get(
        f"{BASE_URL}/organizations/{ORG_ID}/configurationChanges",
        json=[config_change("2026-01-01T11:10:00Z", str(i)) for i in range(2500)],
    )
    events, state = fetch_windowed_events(client, WINDOWED_EVENT_TYPES[CONFIGURATION_CHANGES], {}, 10000, NOW)
    assert mock.call_count == 1
    assert len(events) == 2500
    assert "next_url" not in state


def test_fetch_windowed_resumes_next_url(client, requests_mock):
    next_link = f"{BASE_URL}/organizations/{ORG_ID}/configurationChanges?startingAfter=abc"
    requests_mock.get(next_link, json=[config_change("2026-01-01T11:50:00Z")])
    state = {"next_url": next_link, "window_start": "2026-01-01T11:00:00Z", "window_end": "2026-01-01T11:55:00Z"}
    events, new_state = fetch_windowed_events(client, WINDOWED_EVENT_TYPES[CONFIGURATION_CHANGES], state, 100, NOW)
    assert len(events) == 1
    assert new_state["last_window_end"] == "2026-01-01T11:55:00Z"


def test_fetch_windowed_rejects_foreign_next_url(client):
    state = {"next_url": "https://evil.example.com/x", "window_start": "a", "window_end": "b"}
    with pytest.raises(DemistoException, match="does not match the Base URL"):
        fetch_windowed_events(client, WINDOWED_EVENT_TYPES[CONFIGURATION_CHANGES], state, 100, NOW)


def test_fetch_windowed_follows_pagination_within_the_budget(client, requests_mock):
    """
    Given: a first page with a rel=next link and a budget larger than both pages.
    When:  fetching.
    Then:  the next page is fetched through the shared call_link helper and the window is completed.
    """
    next_link = f"{BASE_URL}/organizations/{ORG_ID}/configurationChanges?startingAfter=abc"
    requests_mock.get(
        f"{BASE_URL}/organizations/{ORG_ID}/configurationChanges",
        json=[config_change("2026-01-01T11:10:00Z", "a")],
        headers={"Link": f'<{next_link}>; rel="next"'},
    )
    requests_mock.get(next_link, json=[config_change("2026-01-01T11:20:00Z", "b")], complete_qs=True)
    events, state = fetch_windowed_events(client, WINDOWED_EVENT_TYPES[CONFIGURATION_CHANGES], {}, 100, NOW)
    assert [event["label"] for event in events] == ["a", "b"]
    assert "next_url" not in state


def test_fetch_windowed_dedups_boundary_events(client, requests_mock):
    """
    Given: an event at the previous window end, whose hash is saved in the state.
    When:  the next window returns it again.
    Then:  it is dropped.
    """
    duplicate = config_change("2026-01-01T11:00:00Z", "dup")
    requests_mock.get(
        f"{BASE_URL}/organizations/{ORG_ID}/configurationChanges", json=[duplicate, config_change("2026-01-01T11:30:00Z", "new")]
    )
    state = {"last_window_end": "2026-01-01T11:00:00Z", "boundary_hashes": [event_hash(duplicate)]}
    events, _ = fetch_windowed_events(client, WINDOWED_EVENT_TYPES[CONFIGURATION_CHANGES], state, 100, NOW)
    assert [event["label"] for event in events] == ["new"]


def test_appliance_security_events_sorted_ascending(client, requests_mock):
    mock = requests_mock.get(f"{BASE_URL}/organizations/{ORG_ID}/appliance/security/events", json=[])
    fetch_windowed_events(client, WINDOWED_EVENT_TYPES[APPLIANCE_SECURITY_EVENTS], {}, 100, NOW)
    assert mock.last_request.qs["sortorder"] == ["ascending"]


def mock_networks(requests_mock, networks):
    return requests_mock.get(f"{BASE_URL}/organizations/{ORG_ID}/networks", json=networks)


def test_fetch_network_events_per_product_type_cursor(client, requests_mock):
    """
    Given: one network with appliance and wireless product types.
    When:  fetching network events.
    Then:  each (network, product type) gets its own cursor.
    """
    mock_networks(requests_mock, [{"id": "N1", "productTypes": ["appliance", "wireless"]}])
    requests_mock.get(
        f"{BASE_URL}/networks/N1/events",
        json={"events": [{"occurredAt": "2026-01-01T11:40:00Z", "type": "x"}]},
    )
    events, state = fetch_network_events(client, [], {}, 100, NOW)
    assert len(events) == 2
    assert set(state["cursors"]) == {"N1:appliance", "N1:wireless"}
    assert state["cursors"]["N1:appliance"]["starting_after"] == "2026-01-01T11:40:00Z"
    assert state["network_cache"]["networks"][0]["id"] == "N1"


def test_fetch_network_events_uses_cache_and_filters(client, requests_mock):
    networks_mock = mock_networks(requests_mock, [])
    requests_mock.get(f"{BASE_URL}/networks/N2/events", json={"events": []})
    state = {
        "network_cache": {
            "updated_at": format_meraki_time(NOW - timedelta(hours=1)),
            "networks": [{"id": "N1", "productTypes": ["switch"]}, {"id": "N2", "productTypes": ["switch", "sensor"]}],
        }
    }
    _, new_state = fetch_network_events(client, ["N2"], state, 100, NOW)
    assert not networks_mock.called
    assert set(new_state["cursors"]) == {"N2:switch"}


def test_fetch_network_events_shared_budget_rotates(client, requests_mock):
    mock_networks(requests_mock, [{"id": "N1", "productTypes": ["switch"]}, {"id": "N2", "productTypes": ["switch"]}])
    requests_mock.get(
        f"{BASE_URL}/networks/N1/events", json={"events": [{"occurredAt": f"2026-01-01T11:4{i}:00Z", "n": 1} for i in range(3)]}
    )
    requests_mock.get(
        f"{BASE_URL}/networks/N2/events", json={"events": [{"occurredAt": f"2026-01-01T11:4{i}:00Z", "n": 2} for i in range(3)]}
    )
    events, state = fetch_network_events(client, [], {}, 3, NOW)
    assert {event["n"] for event in events} == {1}
    events, _ = fetch_network_events(client, [], state, 3, NOW)
    assert {event["n"] for event in events} == {2}


def test_fetch_network_events_failing_network_keeps_cursor_and_continues(client, requests_mock, demisto_error):
    """
    Given: two networks, where the events endpoint of N1 fails.
    When:  fetching network events.
    Then:  N2's events are returned, N1 keeps its previous cursor and the failure is reported in errors.
    """
    mock_networks(requests_mock, [{"id": "N1", "productTypes": ["switch"]}, {"id": "N2", "productTypes": ["switch"]}])
    requests_mock.get(f"{BASE_URL}/networks/N1/events", status_code=400, json={"errors": ["bad"]})
    requests_mock.get(f"{BASE_URL}/networks/N2/events", json={"events": [{"occurredAt": "2026-01-01T11:40:00Z", "n": 2}]})
    old_cursor = {"starting_after": "2026-01-01T11:00:00Z", "boundary_hashes": []}
    errors: list[str] = []

    events, state = fetch_network_events(client, [], {"cursors": {"N1:switch": old_cursor}}, 100, NOW, errors)

    assert [event["n"] for event in events] == [2]
    assert state["cursors"]["N1:switch"] == old_cursor
    assert state["cursors"]["N2:switch"]["starting_after"] == "2026-01-01T11:40:00Z"
    assert len(errors) == 1
    assert errors[0].startswith("network N1 (switch)")
    assert "network N1 (switch)" in demisto_error.call_args.args[0]


def test_fetch_events_by_type_independent_state(client, requests_mock):
    requests_mock.get(f"{BASE_URL}/organizations/{ORG_ID}/configurationChanges", json=[config_change("2026-01-01T11:30:00Z")])
    requests_mock.get(f"{BASE_URL}/organizations/{ORG_ID}/apiRequests", json=[{"ts": "2026-01-01T11:31:00Z"}])
    events_by_type, next_run, errors = fetch_events_by_type(
        client, [CONFIGURATION_CHANGES, API_REQUESTS], [], {"other": 1}, 10, NOW
    )
    assert events_by_type[CONFIGURATION_CHANGES][0]["_source_log_type"] == CONFIGURATION_CHANGES
    assert events_by_type[API_REQUESTS][0]["_time"] == "2026-01-01T11:31:00Z"
    assert set(next_run) == {"other", CONFIGURATION_CHANGES, API_REQUESTS}
    assert errors == []


def test_fetch_events_by_type_failing_type_keeps_state_and_continues(client, requests_mock, demisto_error):
    """
    Given: configuration changes fail (403) and API requests succeed.
    When:  fetching both types.
    Then:  API requests are returned and advance, configuration changes keep their previous state, and one error is reported.
    """
    requests_mock.get(f"{BASE_URL}/organizations/{ORG_ID}/configurationChanges", status_code=403, json={"errors": ["no"]})
    requests_mock.get(f"{BASE_URL}/organizations/{ORG_ID}/apiRequests", json=[{"ts": "2026-01-01T11:31:00Z"}])
    previous_state = {"last_window_end": "2026-01-01T11:00:00Z", "boundary_hashes": []}

    events_by_type, next_run, errors = fetch_events_by_type(
        client, [CONFIGURATION_CHANGES, API_REQUESTS], [], {CONFIGURATION_CHANGES: previous_state}, 10, NOW
    )

    assert events_by_type[CONFIGURATION_CHANGES] == []
    assert len(events_by_type[API_REQUESTS]) == 1
    assert next_run[CONFIGURATION_CHANGES] == previous_state
    assert next_run[API_REQUESTS]["last_window_end"] == "2026-01-01T12:00:00Z"
    assert len(errors) == 1
    assert errors[0].startswith(f"{CONFIGURATION_CHANGES}:")
    assert "keeping the previous state" in demisto_error.call_args.args[0]


def test_fetch_events_command_sends_and_saves_before_raising(client, requests_mock, mocker):
    """
    Given: one type that fails and one that succeeds.
    When:  running fetch-events.
    Then:  the successful events are sent and the last run is saved before the combined error is raised.
    """
    requests_mock.get(f"{BASE_URL}/organizations/{ORG_ID}/configurationChanges", status_code=500, json={"errors": ["boom"]})
    requests_mock.get(f"{BASE_URL}/organizations/{ORG_ID}/apiRequests", json=[{"ts": "2026-01-01T11:31:00Z"}])
    mocker.patch.object(demisto, "getLastRun", return_value={})
    set_last_run = mocker.patch.object(demisto, "setLastRun")
    send = mocker.patch(f"{INTEGRATION}.send_events_to_xsiam")

    with pytest.raises(DemistoException, match="retried next cycle"):
        fetch_events_command(client, [CONFIGURATION_CHANGES, API_REQUESTS], [], 10)

    assert len(send.call_args.args[0]) == 1
    saved = set_last_run.call_args.args[0]
    assert API_REQUESTS in saved
    assert CONFIGURATION_CHANGES not in saved


def test_get_events_command_reports_errors(client, requests_mock):
    requests_mock.get(f"{BASE_URL}/organizations/{ORG_ID}/apiRequests", status_code=500, json={"errors": ["boom"]})
    results = get_events_command(client, {"event_types": "API requests"}, [])
    assert results[-1].entry_type == EntryType.ERROR
    assert API_REQUESTS in results[-1].readable_output


def test_get_events_command_does_not_push_by_default(client, requests_mock, mocker):
    send = mocker.patch(f"{INTEGRATION}.send_events_to_xsiam")
    requests_mock.get(
        f"{BASE_URL}/organizations/{ORG_ID}/configurationChanges",
        json=[config_change(f"2026-01-01T11:3{i}:00Z", str(i)) for i in range(5)],
    )
    results = get_events_command(client, {"event_types": "Configuration changes", "limit": "2"}, [])
    assert len(results[0].raw_response) == 2
    send.assert_not_called()


def test_collector_test_module_ok(client, requests_mock):
    requests_mock.get(f"{BASE_URL}/organizations/{ORG_ID}", json={"id": ORG_ID})
    assert collector_test_module(client) == "ok"


def test_collector_test_module_unauthorized(client, requests_mock):
    requests_mock.get(f"{BASE_URL}/organizations/{ORG_ID}", status_code=401, json={"errors": ["Invalid API key"]})
    assert collector_test_module(client) == "Authorization Error: invalid credentials."


def test_collector_test_module_not_found(client, requests_mock):
    requests_mock.get(f"{BASE_URL}/organizations/{ORG_ID}", status_code=404, json={"errors": ["Not found"]})
    assert "was not found" in collector_test_module(client)


def mock_main(mocker, command: str, params: dict, args: dict | None = None):
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "args", return_value=args or {})
    mocker.patch.object(demisto, "command", return_value=command)
    return mocker.patch(f"{INTEGRATION}.return_error")


def test_main_fetch_events_with_connector_credentials(ucp_auth, mocker, requests_mock):
    """
    Given: connector-brokered (UCP) credentials, an endpoint region and one event type.
    When:  running fetch-events.
    Then:  no legacy Authorization header is built, events are sent with vendor/product and the last run is saved.
    """
    mock_main(mocker, "fetch-events", {"organization_id": ORG_ID, "endpoint_region": "Europe", "event_types": ["API requests"]})
    mocker.patch.object(demisto, "getLastRun", return_value={})
    set_last_run = mocker.patch.object(demisto, "setLastRun")
    send = mocker.patch(f"{INTEGRATION}.send_events_to_xsiam")
    api_mock = requests_mock.get(f"{BASE_URL}/organizations/{ORG_ID}/apiRequests", json=[{"ts": "2026-01-01T11:31:00Z"}])

    main()

    assert "Authorization" not in api_mock.last_request.headers
    assert send.call_args.kwargs == {"vendor": VENDOR, "product": PRODUCT}
    assert len(send.call_args.args[0]) == 1
    assert API_REQUESTS in set_last_run.call_args.args[0]


def test_main_test_module(ucp_auth, mocker, requests_mock):
    mock_main(mocker, "test-module", {"organization_id": ORG_ID})
    return_results = mocker.patch(f"{INTEGRATION}.return_results")
    requests_mock.get(f"{BASE_URL}/organizations/{ORG_ID}", json={"id": ORG_ID})

    main()

    return_results.assert_called_once_with("ok")


def test_main_get_events(ucp_auth, mocker, requests_mock):
    mock_main(mocker, "cisco-meraki-get-events", {"organization_id": ORG_ID}, {"event_types": "API requests"})
    return_results = mocker.patch(f"{INTEGRATION}.return_results")
    requests_mock.get(f"{BASE_URL}/organizations/{ORG_ID}/apiRequests", json=[{"ts": "2026-01-01T11:31:00Z"}])

    main()

    assert return_results.call_args.args[0][0].raw_response[0]["_source_log_type"] == API_REQUESTS


@pytest.mark.parametrize(
    "command, params, expected_error",
    [
        ("test-module", {}, "The Organization ID parameter is required."),
        ("cisco-meraki-auth-test", {"organization_id": ORG_ID}, "is not implemented"),
        ("test-module", {"organization_id": ORG_ID, "endpoint_region": "Mars"}, "Unknown Cisco Meraki endpoint region"),
    ],
)
def test_main_reports_errors(ucp_auth, mocker, command, params, expected_error):
    """
    Given: a missing Organization ID, a removed OAuth command or an unknown endpoint region.
    When:  running the integration.
    Then:  the error is reported through return_error.
    """
    return_error = mock_main(mocker, command, params)

    main()

    assert expected_error in return_error.call_args.args[0]
