from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch
from urllib.parse import quote, quote_plus

import pytest
from pytest_mock import MockerFixture

import KELAIdentityGuard
from KELAIdentityGuard import (
    DATE_FORMAT,
    search_incidents_command,
    search_bot_markets_command,
    search_cookie_incidents_command,
    resolve_workspace_id,
    date_range_filter,
    normalize_severity,
    cookie_severity_to_xsoar,
    fetch_incidents,
    main,
    mask_secret,
    test_module as run_test_module,
)


@pytest.fixture(autouse=True)
def mock_support_multithreading(mocker: MockerFixture) -> None:
    """Mock support_multithreading to prevent demistomock attribute errors.

    Called during ContentClient initialization; without this mock, tests fail with:
    AttributeError: module 'demistomock' has no attribute '_Demisto__do'
    """
    mocker.patch("ContentClientApiModule.support_multithreading")


def test_search_incidents_command():
    """
    Given:
        - A mocked client whose search_incidents returns two incidents (the real API's
          "results" envelope, with incidentId as the key field).
    When:
        - kela-identityguard-search-incidents is called with a severity filter.
    Then:
        - The command returns a CommandResults with the incidents under
          KELA.IdentityGuard.Incident and a readable table.
    """
    client = MagicMock()
    client.search_incidents.return_value = {
        "results": [
            {"incidentId": "1", "severity": "critical", "status": "UNRESOLVED", "accountUserName": "jdoe"},
            {"incidentId": "2", "severity": "high", "status": "UNRESOLVED", "accountUserName": "asmith"},
        ],
        "total": 2,
        "totalUnfilteredCount": 2,
    }

    results = search_incidents_command(client, args={"workspace_id": "ws-1", "severity": "critical"}, params={})

    assert results.outputs_prefix == "KELA.IdentityGuard.Incident"
    assert len(results.outputs) == 2
    assert results.outputs[0]["incidentId"] == "1"
    client.search_incidents.assert_called_once()
    called_workspace_id = client.search_incidents.call_args[0][0]
    assert called_workspace_id == "ws-1"


def test_search_bot_markets_command():
    """
    Given:
        - A mocked client whose search_bot_markets returns one alert.
    When:
        - kela-identityguard-search-bot-markets is called.
    Then:
        - The command returns a CommandResults with the alert under KELA.IdentityGuard.BotMarket.
    """
    client = MagicMock()
    client.search_bot_markets.return_value = {
        "results": [{"alertId": "a-1", "marketName": "RussianMarket", "requestStatus": "pending"}]
    }

    results = search_bot_markets_command(client, args={"workspace_id": "ws-1"}, params={})

    assert results.outputs_prefix == "KELA.IdentityGuard.BotMarket"
    assert results.outputs[0]["alertId"] == "a-1"


def test_search_cookie_incidents_command():
    """
    Given:
        - A mocked client whose search_cookie_incidents returns one cookie incident.
    When:
        - kela-identityguard-search-cookie-incidents is called.
    Then:
        - The command returns a CommandResults with the incident under KELA.IdentityGuard.CookieIncident.
    """
    client = MagicMock()
    client.search_cookie_incidents.return_value = {
        "results": [{"incidentId": "c-1", "severity": "critical", "status": "unresolved"}]
    }

    results = search_cookie_incidents_command(client, args={"workspace_id": "ws-1"}, params={})

    assert results.outputs_prefix == "KELA.IdentityGuard.CookieIncident"
    assert results.outputs[0]["incidentId"] == "c-1"


def test_search_cookie_incidents_command_uppercases_severity_and_status():
    """
    Given:
        - severity and status args in the lower/hyphenated casing the command's own
          predefined argument options used to advertise (e.g. "critical", "resolved").
    When:
        - kela-identityguard-search-cookie-incidents is called.
    Then:
        - The filters sent to the client are upper-cased (CRITICAL/RESOLVED), since the
          live API rejects the lower-case values on this endpoint with a 400 Bad Request
          (confirmed manually against the real API - general incidents and bot-market
          alerts do NOT have this quirk, only cookie incidents).
    """
    client = MagicMock()
    client.search_cookie_incidents.return_value = {"results": []}

    search_cookie_incidents_command(
        client, args={"workspace_id": "ws-1", "severity": "critical", "status": "resolved"}, params={}
    )

    sent_payload = client.search_cookie_incidents.call_args[0][1]
    assert sent_payload["filters"]["severity"] == "CRITICAL"
    assert sent_payload["filters"]["status"] == "RESOLVED"


def test_resolve_workspace_id_falls_back_to_param():
    assert resolve_workspace_id({}, {"workspace_id": "default-ws"}) == "default-ws"
    assert resolve_workspace_id({"workspace_id": "arg-ws"}, {"workspace_id": "default-ws"}) == "arg-ws"


def test_date_range_filter_returns_none_when_empty():
    assert date_range_filter({}, "created_date") is None


def test_date_range_filter_rejects_unparseable_dates():
    """
    Given: a start/end date argument dateparser cannot understand.
    When: date_range_filter runs.
    Then: a clear ValueError is raised, instead of an AttributeError from calling
          .strftime() on dateparser's None result.
    """
    with pytest.raises(ValueError, match="created_date_start"):
        date_range_filter({"created_date_start": "not a date"}, "created_date")


def test_date_range_filter_converts_offsets_to_utc():
    """
    Given: start/end dates with a non-UTC offset and with an explicit Z.
    When: date_range_filter runs.
    Then: both are sent to the API as UTC, so the filter window doesn't shift with the offset.
    """
    result = date_range_filter(
        {"source_date_start": "2024-01-15T12:34:56+02:00", "source_date_end": "2024-01-16T00:00:00Z"}, "source_date"
    )
    assert result == {"startDate": "2024-01-15T10:34:56.000Z", "endDate": "2024-01-16T00:00:00.000Z"}


def test_normalize_severity_handles_label_and_int():
    assert normalize_severity("critical") == 3
    assert normalize_severity(2) == 2
    assert normalize_severity("unexpected") == 0
    assert normalize_severity(None) == 0


def test_cookie_severity_to_xsoar():
    assert cookie_severity_to_xsoar("critical") == 4
    assert cookie_severity_to_xsoar("non-critical") == 2


def test_module_success():
    """
    Given: a client that answers correctly for the configured workspace.
    When: test-module runs.
    Then: it returns 'ok'.
    """
    client = MagicMock()
    client.search_incidents.return_value = {"results": []}
    assert run_test_module(client, {"workspace_id": "ws-1"}) == "ok"
    client.search_incidents.assert_called_once_with("ws-1", {"pagination": {"offset": 0, "size": 1}})


def test_module_requires_workspace_id():
    """
    Given: no Default Workspace ID configured on the instance.
    When: test-module runs.
    Then: it fails locally with a clear message, before any request is made.
    """
    client = MagicMock()
    with pytest.raises(ValueError, match="Default Workspace ID"):
        run_test_module(client, {})
    client.search_incidents.assert_not_called()


def test_mask_secret():
    """
    Given: a text that contains the API key in raw and URL-encoded forms.
    When: mask_secret runs.
    Then: every form is replaced, and an empty key leaves the text unchanged.
    """
    secret = "key/with+chars="
    text = f"raw={secret} quoted={quote(secret, safe='')} plus={quote_plus(secret)}"
    masked = mask_secret(text, secret)
    assert secret not in masked
    assert quote(secret, safe="") not in masked
    assert quote_plus(secret) not in masked
    assert masked.count("<API_KEY>") == 3
    assert mask_secret("nothing to hide", "") == "nothing to hide"


def test_main_never_logs_or_returns_the_api_key(mocker: MockerFixture):
    """
    Given: a request that fails the way ContentClient fails, with an error chained to an HTTP error whose
           message holds the request URL, including the apiToken query parameter.
    When: main() handles the failure.
    Then: neither the logged traceback nor the error returned to the user contains the API key.
    """
    api_key = "SuperSecretKey123"
    demisto_mock = mocker.patch("KELAIdentityGuard.demisto")
    demisto_mock.params.return_value = {
        "url": "https://api.ke-la.com/bots-client-api/v1",
        "credentials": {"password": api_key},
        "workspace_id": "ws-1",
    }
    demisto_mock.args.return_value = {}
    demisto_mock.command.return_value = "kela-identityguard-search-incidents"

    def failing_request(*_args, **_kwargs):
        try:
            raise RuntimeError(
                "Client error '401 Unauthorized' for url "
                f"'https://api.ke-la.com/bots-client-api/v1/search-incidents?apiToken={api_key}'"
            )
        except RuntimeError as exc:
            raise KELAIdentityGuard.ContentClientAuthenticationError(f"Authentication failed: key {api_key}") from exc

    mocker.patch.object(KELAIdentityGuard.Client, "search_incidents", side_effect=failing_request)
    return_error = mocker.patch("KELAIdentityGuard.return_error")

    main()

    logged = [str(call) for call in demisto_mock.error.call_args_list + demisto_mock.debug.call_args_list]
    assert any("apiToken=<API_KEY>" in line for line in logged)
    assert all(api_key not in line for line in logged)
    message = return_error.call_args.args[0]
    assert "Authentication failed" in message
    assert api_key not in message


@patch("KELAIdentityGuard.demisto")
def test_fetch_incidents_translates_kela_severity_to_xsoar_scale(mock_demisto):
    """
    Given:
        - A general-incidents record with KELA severity "high" (KELA scale: 2).
    When:
        - fetch_incidents runs.
    Then:
        - The created XSOAR incident's severity is 3 (XSOAR's High), not the raw KELA
          value 2 (XSOAR's Medium) - regression test for XSOAR_SEVERITY_BY_KELA_SEVERITY
          previously being defined but never applied.
    """
    mock_demisto.getLastRun.return_value = {}

    client = MagicMock()
    client.search_incidents.return_value = {
        "results": [{"incidentId": "i-1", "severity": "high", "createdDate": "2026-01-01T00:00:00.000Z"}]
    }
    client.search_bot_markets.return_value = {"results": []}
    client.search_cookie_incidents.return_value = {"results": []}

    fetch_incidents(
        client,
        {
            "workspace_id": "ws-1",
            "max_fetch": "50",
            "first_fetch": "3 days",
            "fetch_bot_markets": False,
            "fetch_cookie_incidents": False,
        },
    )

    incidents_arg = mock_demisto.incidents.call_args[0][0]
    assert incidents_arg[0]["severity"] == 3


@patch("KELAIdentityGuard.demisto")
def test_fetch_incidents_merges_all_three_sources_by_default(mock_demisto):
    """
    Given:
        - A mocked client returning one result from each of the three search endpoints,
          and default params (both bot-market and cookie fetching enabled).
    When:
        - fetch_incidents runs.
    Then:
        - demisto.incidents is called with 3 incidents, one per source, each named with
          its source-specific prefix.
    """
    mock_demisto.getLastRun.return_value = {}
    mock_demisto.params = None  # not used directly; params passed explicitly below

    client = MagicMock()
    client.search_incidents.return_value = {
        "results": [{"incidentId": "i-1", "severity": "high", "createdDate": "2026-01-01T00:00:00.000Z"}]
    }
    client.search_bot_markets.return_value = {"results": [{"alertId": "a-1", "createdDate": "2026-01-01T00:00:00.000Z"}]}
    client.search_cookie_incidents.return_value = {
        "results": [{"incidentId": "c-1", "severity": "critical", "createdDate": "2026-01-01T00:00:00.000Z"}]
    }

    fetch_incidents(client, {"workspace_id": "ws-1", "max_fetch": "50", "first_fetch": "3 days"})

    incidents_arg = mock_demisto.incidents.call_args[0][0]
    names = {inc["name"] for inc in incidents_arg}
    assert len(incidents_arg) == 3
    assert any(n.startswith("KELA Identity Guard incident") for n in names)
    assert any(n.startswith("KELA Bot Market alert") for n in names)
    assert any(n.startswith("KELA Cookie incident") for n in names)


@patch("KELAIdentityGuard.demisto")
def test_fetch_incidents_sends_upper_case_status_for_cookie_source(mock_demisto):
    """
    Given:
        - Default fetch params (cookie-incident fetching enabled).
    When:
        - fetch_incidents runs.
    Then:
        - The status filter sent to search_cookie_incidents is the upper-case
          "UNRESOLVED", not "unresolved" - regression test for a live 400 Bad Request
          this endpoint returns for the lower-case value (general incidents and
          bot-market alerts don't have this quirk).
    """
    mock_demisto.getLastRun.return_value = {}

    client = MagicMock()
    client.search_incidents.return_value = {"results": []}
    client.search_bot_markets.return_value = {"results": []}
    client.search_cookie_incidents.return_value = {"results": []}

    fetch_incidents(client, {"workspace_id": "ws-1", "max_fetch": "50", "first_fetch": "3 days"})

    sent_payload = client.search_cookie_incidents.call_args[0][1]
    assert sent_payload["filters"]["status"] == "UNRESOLVED"


@patch("KELAIdentityGuard.demisto")
def test_fetch_incidents_respects_source_toggles(mock_demisto):
    """
    Given:
        - Bot-market and cookie-incident fetching both disabled via params.
    When:
        - fetch_incidents runs.
    Then:
        - Only the general search_incidents source is called and fetched.
    """
    mock_demisto.getLastRun.return_value = {}

    client = MagicMock()
    client.search_incidents.return_value = {
        "results": [{"incidentId": "i-1", "severity": "low", "createdDate": "2026-01-01T00:00:00.000Z"}]
    }

    fetch_incidents(
        client,
        {
            "workspace_id": "ws-1",
            "max_fetch": "50",
            "first_fetch": "3 days",
            "fetch_bot_markets": False,
            "fetch_cookie_incidents": False,
        },
    )

    client.search_bot_markets.assert_not_called()
    client.search_cookie_incidents.assert_not_called()
    incidents_arg = mock_demisto.incidents.call_args[0][0]
    assert len(incidents_arg) == 1


# ############################################################################
# Fetch de-duplication tests
#
# The KELA API treats dateFilters.createdDate.startDate as INCLUSIVE. Using the newest
# createdDate as the next startDate without ID-level dedup would return the record sitting
# exactly at the watermark - and re-create it in Cortex - every cycle.
# ############################################################################

# Relative to "now" so the records always fall inside the "3 days" first-fetch window.
_BASE = datetime.now(UTC).replace(microsecond=0) - timedelta(days=1)
T0 = _BASE.strftime(DATE_FORMAT)
T1 = (_BASE + timedelta(minutes=30)).strftime(DATE_FORMAT)
FIRST_RUN_PARAMS = {
    "workspace_id": "ws-1",
    "max_fetch": "50",
    "first_fetch": "3 days",
    "fetch_bot_markets": False,
    "fetch_cookie_incidents": False,
}


class FakeKela:
    """Fake KELA endpoint that behaves like the real API: startDate is INCLUSIVE, results
    are sorted by createdDate asc and capped by pagination.size."""

    def __init__(self, records):
        self.records = records
        self.calls = 0

    def search(self, workspace_id, payload):
        self.calls += 1
        start = payload["filters"]["dateFilters"]["createdDate"]["startDate"]
        rows = sorted((r for r in self.records if r["createdDate"] >= start), key=lambda r: r["createdDate"])
        return {"results": rows[: payload["pagination"]["size"]]}


class FakeDemisto:
    """Persists last run between cycles like XSOAR does and records every created incident."""

    def __init__(self, last_run=None):
        self.last_run = last_run or {}
        self.created = []

    def attach(self, mock_demisto):
        mock_demisto.getLastRun.side_effect = lambda: dict(self.last_run)
        mock_demisto.setLastRun.side_effect = lambda value: setattr(self, "last_run", dict(value))
        mock_demisto.incidents.side_effect = lambda incs: self.created.extend(i["name"] for i in incs)


def _client_for(fake):
    client = MagicMock()
    client.search_incidents.side_effect = fake.search
    return client


@patch("KELAIdentityGuard.demisto")
def test_fetch_does_not_recreate_incident_sitting_exactly_at_the_watermark(mock_demisto):
    """
    Given:
        - An API that (like the real one) returns the record whose createdDate equals the
          startDate, and a single record in the workspace.
    When:
        - fetch_incidents runs many cycles with nothing new arriving.
    Then:
        - The incident is created exactly once, not once per cycle.
    """
    fake = FakeKela([{"incidentId": "A", "severity": "NON_CRITICAL", "createdDate": T0}])
    state = FakeDemisto()
    state.attach(mock_demisto)
    client = _client_for(fake)

    for _ in range(10):
        fetch_incidents(client, FIRST_RUN_PARAMS)

    assert state.created == ["KELA Identity Guard incident A"]


@patch("KELAIdentityGuard.demisto")
def test_fetch_picks_up_new_records_without_duplicating_old_ones(mock_demisto):
    """
    Given:
        - A record already ingested, then a new one arriving later, then a second one with
          the exact same createdDate as the previous watermark.
    When:
        - fetch_incidents keeps running.
    Then:
        - Every record is created exactly once, in order.
    """
    fake = FakeKela([{"incidentId": "A", "severity": "NON_CRITICAL", "createdDate": T0}])
    state = FakeDemisto()
    state.attach(mock_demisto)
    client = _client_for(fake)

    fetch_incidents(client, FIRST_RUN_PARAMS)
    fetch_incidents(client, FIRST_RUN_PARAMS)
    fake.records.append({"incidentId": "B", "severity": "NON_CRITICAL", "createdDate": T1})
    fetch_incidents(client, FIRST_RUN_PARAMS)
    fetch_incidents(client, FIRST_RUN_PARAMS)
    # Late record that shares the watermark timestamp with an already-ingested one.
    fake.records.append({"incidentId": "C", "severity": "NON_CRITICAL", "createdDate": T1})
    fetch_incidents(client, FIRST_RUN_PARAMS)
    fetch_incidents(client, FIRST_RUN_PARAMS)

    assert state.created == [
        "KELA Identity Guard incident A",
        "KELA Identity Guard incident B",
        "KELA Identity Guard incident C",
    ]


@patch("KELAIdentityGuard.demisto")
def test_fetch_compares_dates_as_utc_datetimes_not_strings(mock_demisto):
    """
    Given:
        - A watermark stored as "...T10:00:00.000Z" with record A already ingested at it.
        - An API that returns the same instant in another format ("...T12:00:00+02:00"), plus a
          record B one millisecond later written with real milliseconds ("...T10:00:00.001Z").
    When:
        - fetch_incidents runs twice.
    Then:
        - A is recognised as the record at the watermark and is not re-created, B is created once,
          and the watermark keeps the API's own string so no precision is lost.
    """
    day = (datetime.now(UTC) - timedelta(days=1)).strftime("%Y-%m-%d")
    records = [
        {"incidentId": "A", "severity": "NON_CRITICAL", "createdDate": f"{day}T12:00:00+02:00"},
        {"incidentId": "B", "severity": "NON_CRITICAL", "createdDate": f"{day}T10:00:00.001Z"},
    ]
    client = MagicMock()
    client.search_incidents.return_value = {"results": records}
    state = FakeDemisto({"last_fetch_incidents": f"{day}T10:00:00.000Z", "last_ids_incidents": ["A"]})
    state.attach(mock_demisto)

    fetch_incidents(client, FIRST_RUN_PARAMS)
    client.search_incidents.return_value = {"results": records[1:]}
    fetch_incidents(client, FIRST_RUN_PARAMS)

    assert state.created == ["KELA Identity Guard incident B"]
    assert state.last_run["last_fetch_incidents"] == f"{day}T10:00:00.001Z"
    assert state.last_run["last_ids_incidents"] == ["B"]


@patch("KELAIdentityGuard.demisto")
def test_fetch_first_fetch_window_starts_in_utc(mock_demisto):
    """
    Given: no last run and first_fetch="3 days".
    When: fetch_incidents runs.
    Then: the startDate sent to the API is 3 days before now in UTC (not shifted by the engine's timezone).
    """
    client = MagicMock()
    client.search_incidents.return_value = {"results": []}
    FakeDemisto().attach(mock_demisto)

    fetch_incidents(client, FIRST_RUN_PARAMS)

    start = client.search_incidents.call_args.args[1]["filters"]["dateFilters"]["createdDate"]["startDate"]
    sent = datetime.strptime(start, DATE_FORMAT).replace(tzinfo=UTC)
    assert abs((datetime.now(UTC) - timedelta(days=3) - sent).total_seconds()) < 120


@patch("KELAIdentityGuard.demisto")
def test_fetch_many_records_with_same_createdDate_and_small_max_fetch(mock_demisto):
    """
    Given:
        - 5 records sharing one createdDate and max_fetch=2.
    When:
        - fetch_incidents runs until it is drained.
    Then:
        - All 5 are created exactly once (a boundary group must not stall the watermark
          nor cause duplicates).
    """
    records = [{"incidentId": f"R{i}", "severity": "NON_CRITICAL", "createdDate": T0} for i in range(5)]
    fake = FakeKela(records)
    state = FakeDemisto()
    state.attach(mock_demisto)
    client = _client_for(fake)

    for _ in range(8):
        fetch_incidents(client, {**FIRST_RUN_PARAMS, "max_fetch": "2"})

    assert sorted(state.created) == sorted(f"KELA Identity Guard incident R{i}" for i in range(5))


@patch("KELAIdentityGuard.demisto")
def test_fetch_filtered_by_min_severity_still_advances_watermark(mock_demisto):
    """
    Given:
        - min_severity=high and only a low-severity record in the workspace.
    When:
        - fetch_incidents runs.
    Then:
        - No incident is created, but the watermark moves to that record so it is not
          re-read as "new" forever.
    """
    fake = FakeKela([{"incidentId": "L", "severity": "low", "createdDate": T1}])
    state = FakeDemisto()
    state.attach(mock_demisto)
    client = _client_for(fake)

    fetch_incidents(client, {**FIRST_RUN_PARAMS, "min_severity": "2 - high"})

    assert state.created == []
    assert state.last_run["last_fetch_incidents"] == T1
    assert state.last_run["last_ids_incidents"] == ["L"]


@patch("KELAIdentityGuard.demisto")
def test_fetch_disabled_source_keeps_its_last_run_state(mock_demisto):
    """
    Given:
        - A last run holding bot-market state, with bot-market fetching now disabled.
    When:
        - fetch_incidents runs.
    Then:
        - The bot-market watermark and IDs are preserved for when it is re-enabled.
    """
    fake = FakeKela([])
    state = FakeDemisto({"last_fetch_bot_markets": T0, "last_ids_bot_markets": ["x"]})
    state.attach(mock_demisto)
    client = _client_for(fake)

    fetch_incidents(client, FIRST_RUN_PARAMS)

    assert state.last_run["last_fetch_bot_markets"] == T0
    assert state.last_run["last_ids_bot_markets"] == ["x"]
