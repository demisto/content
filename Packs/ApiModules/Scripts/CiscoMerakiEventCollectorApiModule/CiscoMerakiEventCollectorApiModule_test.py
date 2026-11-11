from datetime import UTC, datetime, timedelta

import demistomock as demisto
import pytest
from CiscoMerakiEventCollectorApiModule import (
    API_REQUESTS,
    APPLIANCE_SECURITY_EVENTS,
    CONFIGURATION_CHANGES,
    NETWORK_EVENTS,
    PRODUCT,
    VENDOR,
    WINDOWED_EVENT_TYPES,
    CiscoMerakiEventCollectorClient,
    DemistoException,
    collector_test_module,
    enrich_events,
    event_hash,
    fetch_events_by_type,
    fetch_network_events,
    fetch_windowed_events,
    format_meraki_time,
    get_events_command,
    parse_event_types,
)

HOST = "https://api.meraki.com"
BASE_URL = f"{HOST}/api/v1"
ORG_ID = "123"
NOW = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def client() -> CiscoMerakiEventCollectorClient:
    return CiscoMerakiEventCollectorClient(organization_id=ORG_ID, base_url=HOST, api_key="key", verify=False, proxy=False)


def config_change(ts: str, label: str = "x") -> dict:
    return {"ts": ts, "label": label}


def test_parse_event_types_defaults_to_all():
    assert parse_event_types(None) == [CONFIGURATION_CHANGES, NETWORK_EVENTS, API_REQUESTS, APPLIANCE_SECURITY_EVENTS]


def test_parse_event_types_maps_display_names():
    assert parse_event_types("API requests,Network events") == [API_REQUESTS, NETWORK_EVENTS]


def test_parse_event_types_rejects_unknown():
    with pytest.raises(DemistoException, match="Unknown event types"):
        parse_event_types("Bogus")


def test_enrich_events_sets_time_and_source_log_type():
    events = enrich_events([{"occurredAt": "2026-01-01T00:00:00Z"}], NETWORK_EVENTS)
    assert events[0]["_time"] == "2026-01-01T00:00:00Z"
    assert events[0]["_source_log_type"] == NETWORK_EVENTS


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


def test_fetch_windowed_resumes_next_url(client, requests_mock):
    next_link = f"{BASE_URL}/organizations/{ORG_ID}/configurationChanges?startingAfter=abc"
    requests_mock.get(next_link, json=[config_change("2026-01-01T11:50:00Z")])
    state = {"next_url": next_link, "window_start": "2026-01-01T11:00:00Z", "window_end": "2026-01-01T11:55:00Z"}
    events, new_state = fetch_windowed_events(client, WINDOWED_EVENT_TYPES[CONFIGURATION_CHANGES], state, 100, NOW)
    assert len(events) == 1
    assert new_state["last_window_end"] == "2026-01-01T11:55:00Z"


def test_fetch_windowed_rejects_foreign_next_url(client):
    state = {"next_url": "https://evil.example.com/x", "window_start": "a", "window_end": "b"}
    with pytest.raises(DemistoException, match="does not match"):
        fetch_windowed_events(client, WINDOWED_EVENT_TYPES[CONFIGURATION_CHANGES], state, 100, NOW)


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


def test_fetch_events_by_type_independent_state(client, requests_mock):
    requests_mock.get(f"{BASE_URL}/organizations/{ORG_ID}/configurationChanges", json=[config_change("2026-01-01T11:30:00Z")])
    requests_mock.get(f"{BASE_URL}/organizations/{ORG_ID}/apiRequests", json=[{"ts": "2026-01-01T11:31:00Z"}])
    events_by_type, next_run = fetch_events_by_type(client, [CONFIGURATION_CHANGES, API_REQUESTS], [], {"other": 1}, 10, NOW)
    assert events_by_type[CONFIGURATION_CHANGES][0]["_source_log_type"] == CONFIGURATION_CHANGES
    assert events_by_type[API_REQUESTS][0]["_time"] == "2026-01-01T11:31:00Z"
    assert set(next_run) == {"other", CONFIGURATION_CHANGES, API_REQUESTS}


def test_collector_test_module_ok(client, requests_mock):
    requests_mock.get(f"{BASE_URL}/organizations/{ORG_ID}", json={"id": ORG_ID})
    assert collector_test_module(client) == "ok"


def test_collector_test_module_unauthorized(client, requests_mock):
    requests_mock.get(f"{BASE_URL}/organizations/{ORG_ID}", status_code=401, json={"errors": ["Invalid API key"]})
    assert collector_test_module(client) == "Authorization Error: invalid credentials."


def test_collector_test_module_not_found(client, requests_mock):
    requests_mock.get(f"{BASE_URL}/organizations/{ORG_ID}", status_code=404, json={"errors": ["Not found"]})
    assert "was not found" in collector_test_module(client)


def test_get_events_command_does_not_push_by_default(client, requests_mock, mocker):
    send = mocker.patch("CiscoMerakiEventCollectorApiModule.send_events_to_xsiam")
    requests_mock.get(
        f"{BASE_URL}/organizations/{ORG_ID}/configurationChanges",
        json=[config_change(f"2026-01-01T11:3{i}:00Z", str(i)) for i in range(5)],
    )
    results = get_events_command(client, {"event_types": "Configuration changes", "limit": "2"}, [])
    assert len(results[0].raw_response) == 2
    send.assert_not_called()


def test_run_collector_fetch_events(mocker, requests_mock):
    """
    Given: collector params with one event type.
    When:  running fetch-events.
    Then:  events are sent with vendor/product and the last run is saved.
    """
    from CiscoMerakiEventCollectorApiModule import run_cisco_meraki_event_collector

    mocker.patch.object(
        demisto,
        "params",
        return_value={"organization_id": ORG_ID, "api_key": {"password": "key"}, "event_types": ["API requests"]},
    )
    mocker.patch.object(demisto, "command", return_value="fetch-events")
    mocker.patch.object(demisto, "getLastRun", return_value={})
    set_last_run = mocker.patch.object(demisto, "setLastRun")
    send = mocker.patch("CiscoMerakiEventCollectorApiModule.send_events_to_xsiam")
    requests_mock.get(f"{BASE_URL}/organizations/{ORG_ID}/apiRequests", json=[{"ts": "2026-01-01T11:31:00Z"}])

    run_cisco_meraki_event_collector()

    assert send.call_args.kwargs == {"vendor": VENDOR, "product": PRODUCT}
    assert len(send.call_args.args[0]) == 1
    assert API_REQUESTS in set_last_run.call_args.args[0]
