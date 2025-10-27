import pytest
import random
import json
from ManageEngineEventCollector import Client, PAGE_LIMIT_DEFAULT
import ManageEngineEventCollector as manage


@pytest.fixture()
def client() -> Client:
    return Client(base_url="https://endpointcentral.manageengine.com", client_id="id", client_secret="secret", client_code="code")


def util_load_json():
    with open("test_data/response.json", encoding="utf-8") as f:
        return json.loads(f.read())


# ─────── Tests for get_access_token ────────────────────────────────────────────


def test_get_access_token_cached(client: Client, mocker):
    """
    Given:
        - An integration context with a valid (non-expired) access token and a refresh token.
    When:
        - Calling `get_access_token()`.
    Then:
        - The cached access token is returned.
        - No HTTP request is made to refresh the token.
    """

    future = "3000-01-01T00:00:00"
    ctx = {"access_token": "cached_token", "refresh_token": "rtoken", "expire_date": future}
    mocker.patch("ManageEngineEventCollector.demisto.getIntegrationContext", return_value=ctx)

    mocker.patch.object(client, "_http_request", side_effect=AssertionError("HTTP should not be called when token is valid"))

    token = client.get_access_token()

    assert token == "cached_token"


def test_get_access_token_refresh(client: Client, mocker):
    """
    Given:
        - An integration context with an expired access token and a valid refresh token.
    When:
        - Calling `get_access_token()`.
    Then:
        - A new access token is requested via an HTTP call.
        - The integration context is updated with the new access token, refresh token, and expiration date.
        - The new access token is returned.
    """

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
    """
    Given:
        - No refresh token is present in the integration context.
        - An authorization code flow is expected to be triggered (e.g., during first login).
    When:
        - Calling `get_access_token()`.
    Then:
        - An HTTP request is made to exchange the authorization code for access and refresh tokens.
        - The returned access token is used.
        - The integration context is updated with the new refresh token.
    """

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
    """
    Given:
        - The client's `search_events` method returns a non-empty list (indicating success).
    When:
        - Calling the `test_module`.
    Then:
        - test_module do not raise error and return message 'Connection is valid.'
    """

    from ManageEngineEventCollector import test_module

    mocker.patch.object(client, "search_events", return_value=[{}])

    result = test_module(client)
    assert result == "Connection is valid."


def test_test_module_auth_error(client: Client, mocker):
    """
    Given:
        - The client's `search_events` method raises an unauthorized access exception.
    When:
        - Calling the `test_module` function.
    Then:
        - The result should include an 'Authorization Error' message indicating invalid credentials or permissions.
    """
    from ManageEngineEventCollector import test_module

    mocker.patch.object(client, "search_events", side_effect=Exception("Unauthorized access"))

    result = test_module(client)
    assert "Authorization Error" in result


# ─────── Tests for add_time_to_events ─────────────────────────────────────────


def test_add_time_to_events():
    """
    Given:
        - A list of events with 'eventTime' in timestamp.
    When:
        - Calling `add_time_to_events()` on the list.
    Then:
        - Each event should have an added '_time' field with the correct ISO 8601 UTC datetime string.
    """
    from ManageEngineEventCollector import add_time_to_events

    iso = "2021-01-01T00:00:00.000000Z"
    ts = 1609459200000  # ms for that exact UTC moment

    evs = [{"eventTime": ts}]
    add_time_to_events(evs)

    assert evs[0]["_time"] == iso


# ─────── Tests for get_events ─────────────────────────────────────────────────


def test_get_events_no_push(client: Client, mocker):
    """
    Given:
        - A list of events returned by the client's `search_events` method.
        - 'should_push_events' is 'false'.
    When:
        - Calling the `get_events` function.
    Then:
        - The function returns a `CommandResults` object with the fetched events.
        - The `send_events_to_xsiam` function is NOT called.
        - Each event includes a properly formatted '_time' field.
    """
    from ManageEngineEventCollector import get_events, CommandResults
    from CommonServerPython import tableToMarkdown

    return_event = [{"id": "1", "eventTime": 1609459200000}]
    client = mocker.Mock(spec=Client)
    client.search_events.return_value = return_event

    # patch send_events_to_xsiam to error if called
    mocker.patch(
        "ManageEngineEventCollector.send_events_to_xsiam", side_effect=AssertionError("send_events_to_xsiam should NOT be called")
    )
    result_markdown = tableToMarkdown(
        name="ManageEngine Audit Logs",
        t={"id": "1", "eventTime": 1609459200000, "_time": "2021-01-01T00:00:00.000000Z"},
    )
    args = {
        "should_push_events": "false",
        "limit": "1",
        "start_date": "2021-01-01T00:00:00.0Z",
        "end_date": "2021-01-01T00:00:00.0Z",
    }
    results = get_events(client, args)

    assert isinstance(results, CommandResults)

    assert results.readable_output == result_markdown


def test_fetch_events_all_new_events_updates_to_max(client, mocker):
    """
    Given:
        - A list of events with eventTime values.
        - last_run is empty
    When:
        - Calling `fetch_events()`.
    Then:
        - All events are returned without deduplication.
        - The `last_run` is updated to the maximum `eventTime` value among the events.
    """
    from ManageEngineEventCollector import fetch_events

    events = [
        {"eventTime": 1001},
        {"eventTime": 1002},
        {"eventTime": 1005},
    ]
    mocker.patch.object(client, "search_events", return_value=events)

    next_run, events_returned = fetch_events(client, {}, max_events_per_fetch=10)

    # No dedup, so order preserved
    assert events_returned == events
    # last_run is the max timestamp seen: 1005
    assert next_run["last_time"] == "1006"


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
        if method.upper() == "POST" and full_url.endswith("/oauth/v2/token"):
            return {"access_token": "fake_token", "refresh_token": "fake_rt", "expires_in": "3600"}

        # 2) Paginated audit‐logs GET
        if method.upper() == "GET" and url_suffix == "/emsapi/server/auditLogs":
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
    Stub out HTTP and auth for a universe of 100 events (0-99).
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
    - 30 events are returned (timestamps 0-29).
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
    - 50 events are returned (timestamps 0-49).
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


# ─────── Tests Real Response ────────────────────────────────────
class HttpRealMocker:
    """
    Mocker http_request with real data response.
    """

    def __init__(self, payload: dict):
        self.payload = payload
        self.served_first_page = False

    def __call__(self, method, url_suffix="", params=None, full_url="", **kw):  # noqa: ANN001
        if method.upper() == "POST" and full_url.endswith("/oauth/v2/token"):
            return {"access_token": "stub", "refresh_token": "rt", "expires_in": "3600"}

        if method.upper() == "GET" and url_suffix == "/emsapi/server/auditLogs":
            return self.payload

        return {}


@pytest.fixture
def client_with_real_payload(mocker):
    data = util_load_json()
    mocker.patch.object(Client, "_http_request", side_effect=HttpRealMocker(data))

    return Client(
        base_url="https://endpointcentral.manageengine.com",
        client_id="id",
        client_secret="secret",
        client_code="code",
    )


class TestRealResponse:
    raw_data = util_load_json()

    def test_fetch_all_events_when_limit_exceeds_total(self, client_with_real_payload):
        """
        Given:
        - The http_request returns 17 events.

        When:
        - `search_events` is called with limit=50.

        Then:
        - Exactly 17 events are returned, sorted ascending by `eventTime`.
        """
        events = client_with_real_payload.search_events("0", "9999999999999", limit=50)

        assert len(events) == 17
        assert events == sorted(events, key=lambda ev: int(ev["eventTime"]))

    def test_fetch_first_n_when_limit_smaller(self, client_with_real_payload):
        """
        Given:
        - The http_request returns 17 events.

        When:
        - `search_events` is called with limit=5.

        Then:
        - Exactly 5  earliest events are returned, sorted ascending by `eventTime`.
        """
        events = client_with_real_payload.search_events("0", "9999999999999", limit=5)

        all_sorted = sorted(
            client_with_real_payload.search_events("0", "9999999999999", 17),
            key=lambda ev: int(ev["eventTime"]),
        )
        assert events == all_sorted[:5]

    def test_fetch_events_dedup_logic(self, client_with_real_payload, mocker):
        """
        Given:
        - The `_http_request` stub returns 17 events.

        When:
        - `fetch_events` is executed.

        Then:
        - `next_run['last_time']` equals the newest `eventTime` in the fixture.
        - Exactly 17 events are returned.
        """
        newest_ts = max(int(ev["eventTime"]) for ev in self.raw_data["messageResponse"])

        mocker.patch.object(manage, "send_events_to_xsiam")  # avoid side-effect

        next_run, events = manage.fetch_events(
            client=client_with_real_payload,
            last_run={"last_time": 0},
            max_events_per_fetch=50,
        )

        assert len(events) == 17
        assert int(next_run["last_time"]) == newest_ts + 1
