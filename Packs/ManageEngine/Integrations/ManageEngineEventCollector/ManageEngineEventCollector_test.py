import pytest
import random
from ManageEngineEventCollector import Client, AUDIT_LOGS_URL, TOKEN_URL, PAGE_LIMIT_DEFAULT


@pytest.fixture()
def client() -> Client:
    return Client(base_url="https://endpointcentral.manageengine.com", client_id="id", client_secret="secret", client_code="code")


# ─────── Tests for get_access_token ────────────────────────────────────────────


def test_get_access_token_cached(client: Client, mocker):
    """Case 1: refresh exists and access still valid → returns cached token without HTTP call."""

    future = "3000-01-01T00:00:00"
    ctx = {"access_token": "cached_token", "refresh_token": "rtoken", "expire_date": future}
    mocker.patch("ManageEngineEventCollector.demisto.getIntegrationContext", return_value=ctx)

    mocker.patch.object(client, "_http_request", side_effect=AssertionError("HTTP should not be called when token is valid"))

    token = client.get_access_token()

    assert token == "cached_token"


def test_get_access_token_refresh(client: Client, mocker):
    """Case 2: refresh exists but token expired → requests new access tokens."""

    past = "2000-01-01T00:00:00"
    ctx = {"access_token": "old_token", "refresh_token": "rtoken", "expire_date": past}
    mocker.patch("ManageEngineEventCollector.demisto.getIntegrationContext", return_value=ctx)
    stored = {}
    mocker.patch("ManageEngineEventCollector.demisto.setIntegrationContext", side_effect=lambda x: stored.update(x))

    def fake_http_request(**kwargs):
        return {"access_token": "new_token", "refresh_token": "rtoken", "expires_in": "3600"}

    mocker.patch.object(client, "_http_request", side_effect=fake_http_request)

    token = client.get_access_token()

    assert token == "new_token"
    assert stored["access_token"] == "new_token"
    assert stored["refresh_token"] == "rtoken"
    assert "expire_date" in stored


def test_get_access_token_code(client: Client, mocker):
    """Case 3: no refresh token but auth code exists → exchanges code for tokens."""
    # Arrange
    mocker.patch("ManageEngineEventCollector.demisto.getIntegrationContext", return_value={})
    stored = {}
    mocker.patch("ManageEngineEventCollector.demisto.setIntegrationContext", side_effect=lambda x: stored.update(x))

    mocker.patch.object(
        client,
        "_http_request",
        return_value={"access_token": "code_token", "refresh_token": "code_refresh", "expires_in": "3600"},
    )

    token = client.get_access_token()

    assert token == "code_token"
    assert stored["refresh_token"] == "code_refresh"


# ─────── Tests for test_module ────────────────────────────────────────────────


def test_test_module_success(client: Client, mocker):
    """test_module returns 'ok' when search_events succeeds."""
    from ManageEngineEventCollector import test_module

    mocker.patch.object(client, "search_events", return_value=[{}])

    result = test_module(client)
    assert result == "ok"


def test_test_module_auth_error(client: Client, mocker):
    """test_module returns Authorization Error message on unauthorized exception."""
    from ManageEngineEventCollector import test_module

    mocker.patch.object(client, "search_events", side_effect=Exception("Unauthorized access"))

    result = test_module(client)
    assert "Authorization Error" in result


# ─────── Tests for add_time_to_events ─────────────────────────────────────────


def test_add_time_to_events():
    from ManageEngineEventCollector import add_time_to_events

    iso = "2021-01-01T00:00:00Z"
    ts = 1609459200000  # ms for that exact UTC moment

    evs = [{"eventTime": ts}]
    add_time_to_events(evs)

    assert evs[0]["_time"] == iso


# ─────── Tests for get_events ─────────────────────────────────────────────────


def test_get_events_no_push(client: Client, mocker):
    """get_events returns results and does NOT push when should_push_events=false."""
    from ManageEngineEventCollector import get_events, CommandResults

    dummy = [{"id": "1", "eventTime": 1609459200000}]
    client = mocker.Mock(spec=Client)
    client.search_events.return_value = dummy

    # patch send_events_to_xsiam to error if called
    mocker.patch(
        "ManageEngineEventCollector.send_events_to_xsiam", side_effect=AssertionError("send_events_to_xsiam should NOT be called")
    )

    args = {"should_push_events": "false", "limit": "1", "start_date": "2021-01-01", "end_date": "2021-01-02"}
    results = get_events(client, args)

    assert isinstance(results, CommandResults)
    assert results.outputs == [{"id": "1", "eventTime": 1609459200000, "_time": "2021-01-01T00:00:00Z"}]


def test_fetch_events_all_new_events_updates_to_max(client, mocker):
    """
    If no event matches last_run, we keep them all and last_run is the max.
    """
    from ManageEngineEventCollector import fetch_events

    events = [
        {"eventTime": "1002"},
        {"eventTime": "1001"},
        {"eventTime": "1005"},
    ]
    mocker.patch.object(client, "search_events", return_value=events)

    next_run, events_returned = fetch_events(client, {}, max_events_per_fetch=10)

    # No dedup, so order preserved
    assert events_returned == events
    # last_run is the max timestamp seen: 1005
    assert next_run["last_time"] == "1005"


def test_fetch_events_dedup_one_event_updates_to_max(client, mocker):
    """
    One event matches, dedup and return without it.
    """
    from ManageEngineEventCollector import fetch_events

    events = [
        {"eventTime": "1002"},
        {"eventTime": "1001"},
        {"eventTime": "1005"},
    ]
    mocker.patch.object(client, "search_events", return_value=events)

    next_run, events_returned = fetch_events(client, {"last_time": "1001"}, max_events_per_fetch=10)

    assert len(events_returned) == 2
    # last_run is the max timestamp seen: 1005
    assert next_run["last_time"] == "1005"


# ─────── Tests fetching logics ─────────────────────────────────────────────────


class HttpRequestsMocker:
    """
    Mocks Client._http_request for both token POSTs and paginated GETs
    over a synthetic universe of events with timestamps 0..num_events-1.
    """

    def __init__(self, num_events: int):
        self.num_events = num_events
        self.all_events = []

    def valid_http_request_side_effect(
        self, method: str, url_suffix: str = "", params: dict | None = None, full_url: str = "", **kwargs
    ) -> dict:
        # 1) Token exchange
        if method.upper() == "POST" and full_url.endswith(TOKEN_URL):
            return {"access_token": "fake_token", "refresh_token": "fake_rt", "expires_in": "3600"}

        # 2) Paginated audit‐logs GET
        if method.upper() == "GET" and url_suffix == AUDIT_LOGS_URL:
            if not self.all_events:
                events = list(range(self.num_events))
                random.shuffle(events)
                self.all_events = events
            limit = int(params.get("pageLimit", PAGE_LIMIT_DEFAULT))  # type: ignore
            page = int(params.get("page", "1"))  # type: ignore

            # slice for this page
            lo = (page - 1) * limit
            hi = lo + limit
            page_ts = self.all_events[lo:hi]

            # build the response
            events = [{"id": ts, "eventTime": ts} for ts in page_ts]
            return {"status": "success", "messageResponse": events}

        return {}


@pytest.fixture
def stub_get_access_token(mocker):
    """Only stub get_access_token in tests that ask for it."""
    mocker.patch.object(Client, "get_access_token", return_value="stub-token")


@pytest.fixture
def http_mocker(mocker):
    """
    Stub out HTTP and auth for a universe of 100 events (0–99).
    """
    http_mocker = HttpRequestsMocker(100)
    mocker.patch.object(Client, "_http_request", side_effect=http_mocker.valid_http_request_side_effect)
    mocker.patch.object(Client, "get_access_token", return_value="stub-token")
    return http_mocker


def _run_search(start: int, end: int, limit: int) -> list[dict]:
    """
    Helper to instantiate a real Client and call search_events().
    """
    client = Client(
        base_url="https://endpointcentral.manageengine.com", client_id="id", client_secret="secret", client_code="code"
    )
    return client.search_events(str(start), str(end), limit)


# ─────── Tests ────────────────────────────────────────


def test_returns_all_events_when_page_and_limit_exceed_total(http_mocker):
    """
    Test when PAGE_LIMIT_DEFAULT exceeds total events and requested limit exceeds total.

    Given:
    - Total events in time range = 100.
    - PAGE_LIMIT_DEFAULT (5000) > 100 events.
    - Requested limit = 200 > total events.

    When:
    - search_events(0, 100, 200) is called.

    Then:
    - All 100 events are returned.
    - eventTime values range from 0 to 99.
    """
    events = _run_search(0, 99, 200)
    assert len(events) == 100
    assert {event["eventTime"] for event in events} == set(range(100))


def test_returns_first_n_events_when_limit_less_than_total(http_mocker):
    """
    Test when PAGE_LIMIT_DEFAULT exceeds total events and requested limit is below total.

    Given:
    - Total events in time range = 100.
    - PAGE_LIMIT_DEFAULT (5000) > 100 events.
    - Requested limit = 30 < total events.

    When:
    - search_events(0, 100, 30) is called.

    Then:
    - 30 events are returned (timestamps 0–29).
    """
    events = _run_search(0, 99, 30)
    assert len(events) == 30
    assert {event["eventTime"] for event in events} == set(range(30))


def test_page_limit_less_and_limit_exceed_total(http_mocker, mocker):
    """
    Test when a smaller PAGE_LIMIT_DEFAULT is set but overall limit exceeds total events.

    Given:
    - Total events in time range = 100.
    - PAGE_LIMIT_DEFAULT overridden to 20.
    - Requested limit = 150 > total events.

    When:
    - search_events(0, 100, 150) is called.

    Then:
    - All 100 events are returned despite the lower page limit.
    """
    import ManageEngineEventCollector

    # Override PAGE_LIMIT to 20 < 100; limit=150 > 100 → should return all 100
    mocker.patch.object(ManageEngineEventCollector, "PAGE_LIMIT_DEFAULT", 20)
    events = _run_search(0, 99, 150)
    assert len(events) == 100
    assert {event["eventTime"] for event in events} == set(range(100))


def test_page_limit_greater_fetch_limit_less_total(http_mocker, mocker):
    """
    Test fetching when limit is between page limit and total.

    Given:
    - Total events in time range = 100.
    - PAGE_LIMIT_DEFAULT overridden to 20.
    - Requested limit = 50 (20 < 50 < 100).

    When:
    - search_events(0, 100, 50) is called.

    Then:
    - 50 events are returned (timestamps 0–49).
    """
    import ManageEngineEventCollector

    mocker.patch.object(ManageEngineEventCollector, "PAGE_LIMIT_DEFAULT", 20)
    events = _run_search(0, 99, 50)
    assert len(events) == 50
    assert {event["eventTime"] for event in events} == set(range(50))


def test_zero_events(http_mocker, mocker):
    """
    Test behavior when there are zero events in the server.

    Given:
    - No events in the server.

    When:
    - search_events is called with any range and limit.

    Then:
    - An empty list is returned.
    """
    http_mocker = HttpRequestsMocker(0)
    mocker.patch.object(Client, "_http_request", side_effect=http_mocker.valid_http_request_side_effect)
    mocker.patch.object(Client, "get_access_token", return_value="stub-token")

    events = Client(
        base_url="https://endpointcentral.manageengine.com", client_id="id", client_secret="secret", client_code="code"
    ).search_events("0", "100", 10)
    assert events == []
