"""Tests for the SAP Enterprise Threat Detection integration."""

import copy
import json
import os
import re
from datetime import datetime, UTC
from http import HTTPStatus
from typing import Any
from unittest.mock import patch

import demistomock as demisto
import pytest
from CommonServerPython import *  # noqa: F401,F403

with patch("ContentClientApiModule.support_multithreading"):
    from SAPETD import (
        INTEGRATION_NAME,
        Commands,
        Config,
        Messages,
        SAPETDClient,
        add_time_to_events,
        build_next_last_run,
        deduplicate_events,
        fetch_alerts_with_pagination,
        fetch_events_command,
        filter_new_alerts,
        format_timestamp,
        get_error_status_code,
        get_events_command,
        main,
        parse_date_to_iso,
        parse_integration_params,
        test_module as run_test_module,
    )

# region Test data and helpers
# =================================
# Test data and helpers
# =================================

TEST_DATA_DIR = os.path.join(os.path.dirname(__file__), "test_data")
SERVER_URL = "https://etd.example.com:4300"
FROM_TIMESTAMP = "2022-04-29T14:00:00.000Z"
OUTPUT_TIMESTAMP_PATTERN = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$"
OUTPUT_TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"


def load_test_data(filename: str) -> Any:
    """Load a JSON file from the test_data directory."""
    with open(os.path.join(TEST_DATA_DIR, filename)) as file:
        return json.load(file)


SAMPLE_ALERTS: list[dict[str, Any]] = load_test_data("sample_alerts.json")


def make_alert(alert_id: int, timestamp: str) -> dict[str, Any]:
    """Build a minimal alert."""
    return {Config.ALERT_ID_FIELD: alert_id, Config.ALERT_TIME_FIELD: timestamp}


def make_page(start_id: int, count: int, timestamp: str | None = None) -> list[dict[str, Any]]:
    """Build a page of alerts, each with its own timestamp unless one is given."""
    return [
        make_alert(alert_id, timestamp or f"2022-04-29T14:{alert_id % 60:02d}:{alert_id % 60:02d}.000Z")
        for alert_id in range(start_id, start_id + count)
    ]


class FakeResponse:
    """Minimal stand-in for an HTTP response carrying a status code."""

    def __init__(self, status_code: Any) -> None:
        self.status_code = status_code


def http_error(status_code: Any, message: str = "Request failed") -> DemistoException:
    """Build a client error carrying an HTTP response, like ContentClientError does."""
    error = DemistoException(message)
    error.response = FakeResponse(status_code)  # type: ignore[attr-defined]
    return error


# endregion

# region Fixtures
# =================================
# Fixtures
# =================================


@pytest.fixture(autouse=True)
def mock_support_multithreading():
    """Prevent ContentClient from calling the XSOAR runtime during client creation."""
    with patch("ContentClientApiModule.support_multithreading"):
        yield


@pytest.fixture
def sample_alerts() -> list[dict[str, Any]]:
    """Deep copy of the sample alerts, for test isolation."""
    return copy.deepcopy(SAMPLE_ALERTS)


@pytest.fixture
def mock_config() -> dict[str, Any]:
    """A validated configuration dict."""
    return {
        "base_url": SERVER_URL,
        "username": "test_user",
        "password": "test_password",
        "verify": False,
        "proxy": False,
        "max_fetch": Config.DEFAULT_MAX_FETCH,
    }


@pytest.fixture
def mock_params() -> dict[str, Any]:
    """Raw integration params, as returned by demisto.params()."""
    return {
        "url": SERVER_URL,
        "credentials": {"identifier": "test_user", "password": "test_password"},
        "insecure": False,
        "proxy": False,
        "max_fetch": str(Config.DEFAULT_MAX_FETCH),
    }


@pytest.fixture
def client(mock_config: dict[str, Any]) -> SAPETDClient:
    """A SAPETDClient instance."""
    return SAPETDClient(mock_config)


# endregion

# region Date helpers
# =================================
# Date helpers
# =================================


class TestFormatTimestamp:
    @pytest.mark.parametrize(
        "value, expected",
        [
            pytest.param(datetime(2026, 1, 15, 15, 0, 0, tzinfo=UTC), "2026-01-15T15:00:00.000Z", id="no_fraction"),
            pytest.param(datetime(2022, 4, 29, 14, 20, 29, 682999, tzinfo=UTC), "2022-04-29T14:20:29.682Z", id="truncates_us"),
            pytest.param(datetime(2022, 4, 29, 14, 20, 29, 5000), "2022-04-29T14:20:29.005Z", id="naive_pads_ms"),
        ],
    )
    def test_format_timestamp(self, value: datetime, expected: str) -> None:
        """Milliseconds are kept, zero-padded, and microseconds are dropped."""
        assert format_timestamp(value) == expected


class TestParseDateToIso:
    @pytest.mark.parametrize(
        "date_input, expected",
        [
            pytest.param("2026-01-15T15:00:00Z", "2026-01-15T15:00:00.000Z", id="absolute"),
            pytest.param("2022-04-29T14:20:29.682Z", "2022-04-29T14:20:29.682Z", id="api_timestamp_round_trips"),
            pytest.param("2022-04-29T14:20:29.682999Z", "2022-04-29T14:20:29.682Z", id="microseconds_dropped"),
        ],
    )
    def test_absolute_dates(self, date_input: str, expected: str) -> None:
        assert parse_date_to_iso(date_input) == expected

    @pytest.mark.parametrize("date_input", ["5 minutes ago", Config.DEFAULT_FIRST_FETCH, Config.TEST_MODULE_LOOKBACK])
    def test_relative_date_is_in_the_past(self, date_input: str) -> None:
        result = parse_date_to_iso(date_input)
        assert re.match(OUTPUT_TIMESTAMP_PATTERN, result)
        assert datetime.strptime(result, OUTPUT_TIMESTAMP_FORMAT).replace(tzinfo=UTC) < datetime.now(tz=UTC)

    @pytest.mark.parametrize(
        "date_input, side_effect",
        [
            pytest.param(None, None, id="none"),
            pytest.param("", None, id="empty"),
            pytest.param("not a date", ValueError("bad date"), id="parser_raises"),
        ],
    )
    def test_unparsable_input_falls_back_to_now(self, date_input: str | None, side_effect: Exception | None) -> None:
        """Empty or invalid input returns the current UTC time instead of failing."""
        before = datetime.now(tz=UTC).replace(microsecond=0)
        with patch("SAPETD.arg_to_datetime", side_effect=side_effect, return_value=None):
            result = parse_date_to_iso(date_input)
        parsed = datetime.strptime(result, OUTPUT_TIMESTAMP_FORMAT).replace(tzinfo=UTC)
        assert before <= parsed <= datetime.now(tz=UTC)


# endregion

# region Event helpers
# =================================
# Event helpers
# =================================


class TestAddTimeToEvents:
    @pytest.mark.parametrize(
        "event, expected_time",
        [
            pytest.param(make_alert(1, "2022-04-29T14:20:29.682Z"), "2022-04-29T14:20:29.682000+00:00", id="valid_timestamp"),
            pytest.param({Config.ALERT_ID_FIELD: 2}, None, id="missing_timestamp"),
            pytest.param(make_alert(3, ""), None, id="empty_timestamp"),
            pytest.param({Config.ALERT_TIME_FIELD: ""}, None, id="missing_id_and_timestamp"),
        ],
    )
    def test_sets_time_field(self, event: dict[str, Any], expected_time: str | None) -> None:
        add_time_to_events([event])
        assert event.get(Config.XSIAM_TIME_FIELD) == expected_time

    def test_unparsable_timestamp_is_kept_as_is(self) -> None:
        event = make_alert(1, "garbage")
        with patch("SAPETD.arg_to_datetime", return_value=None):
            add_time_to_events([event])
        assert event[Config.XSIAM_TIME_FIELD] == "garbage"

    def test_empty_list(self) -> None:
        events: list[dict[str, Any]] = []
        add_time_to_events(events)
        assert events == []


class TestDeduplicateEvents:
    @pytest.mark.parametrize(
        "events, last_ids, expected_ids",
        [
            pytest.param([], [1], [], id="no_events"),
            pytest.param([make_alert(1, "t")], [], [1], id="no_previous_ids"),
            pytest.param([make_alert(1, "t"), make_alert(2, "t")], [1], [2], id="one_duplicate"),
            pytest.param([make_alert(1, "t"), make_alert(2, "t")], [1, 2], [], id="all_duplicates"),
            pytest.param([make_alert(1, "t"), make_alert(2, "t")], [3], [1, 2], id="no_duplicates"),
            pytest.param([{Config.ALERT_TIME_FIELD: "t"}], [1], [None], id="alert_without_id_kept"),
        ],
    )
    def test_deduplicate(self, events: list[dict], last_ids: list[int], expected_ids: list[int | None]) -> None:
        assert [event.get(Config.ALERT_ID_FIELD) for event in deduplicate_events(events, last_ids)] == expected_ids


class TestFilterNewAlerts:
    @pytest.mark.parametrize(
        "batch, seen, expected_ids, expected_seen",
        [
            pytest.param([make_alert(1, "t"), make_alert(2, "t")], set(), [1, 2], {1, 2}, id="all_new"),
            pytest.param([make_alert(1, "t"), make_alert(2, "t")], {1}, [2], {1, 2}, id="boundary_overlap"),
            pytest.param([make_alert(1, "t")], {1}, [], {1}, id="all_seen"),
            pytest.param([], {1}, [], {1}, id="empty_batch"),
            pytest.param(
                [{Config.ALERT_TIME_FIELD: "t"}, make_alert(5, "t")], set(), [None, 5], {5}, id="missing_id_not_tracked"
            ),
        ],
    )
    def test_filter(self, batch: list[dict], seen: set, expected_ids: list, expected_seen: set) -> None:
        result = filter_new_alerts(batch, seen)
        assert [alert.get(Config.ALERT_ID_FIELD) for alert in result] == expected_ids
        assert seen == expected_seen


class TestBuildNextLastRun:
    @pytest.mark.parametrize(
        "events, expected",
        [
            pytest.param(
                [make_alert(1, "t1"), make_alert(2, "t2"), make_alert(3, "t2")],
                {Config.LAST_RUN_TIMESTAMP_KEY: "t2", Config.LAST_RUN_IDS_KEY: [2, 3]},
                id="ids_at_high_water_mark",
            ),
            pytest.param(
                [make_alert(1, "t1"), {Config.ALERT_TIME_FIELD: "t1"}],
                {Config.LAST_RUN_TIMESTAMP_KEY: "t1", Config.LAST_RUN_IDS_KEY: [1]},
                id="alert_without_id_ignored",
            ),
            pytest.param([make_alert(1, "t1"), {Config.ALERT_ID_FIELD: 2}], None, id="last_alert_without_timestamp"),
        ],
    )
    def test_build(self, events: list[dict], expected: dict | None) -> None:
        assert build_next_last_run(events) == expected


class TestGetErrorStatusCode:
    @pytest.mark.parametrize(
        "error, expected",
        [
            pytest.param(http_error(HTTPStatus.UNAUTHORIZED), 401, id="with_status"),
            pytest.param(Exception("no response"), None, id="no_response"),
            pytest.param(http_error(None), None, id="response_without_status"),
            pytest.param(http_error("401"), None, id="non_int_status"),
        ],
    )
    def test_status_code(self, error: Exception, expected: int | None) -> None:
        assert get_error_status_code(error) == expected


# endregion

# region Params
# =================================
# Params
# =================================


class TestParseIntegrationParams:
    def test_valid_params(self, mock_params: dict[str, Any]) -> None:
        assert parse_integration_params(mock_params) == {
            "base_url": SERVER_URL,
            "username": "test_user",
            "password": "test_password",
            "verify": True,
            "proxy": False,
            "max_fetch": Config.DEFAULT_MAX_FETCH,
        }

    @pytest.mark.parametrize(
        "overrides, key, expected",
        [
            pytest.param({"url": f"  {SERVER_URL}/  "}, "base_url", SERVER_URL, id="url_trimmed"),
            pytest.param({"insecure": True}, "verify", False, id="insecure"),
            pytest.param({"proxy": True}, "proxy", True, id="proxy"),
            pytest.param({"max_fetch": "500"}, "max_fetch", 500, id="custom_max_fetch"),
            pytest.param({"max_fetch": None}, "max_fetch", Config.DEFAULT_MAX_FETCH, id="max_fetch_none"),
            pytest.param({"max_fetch": "0"}, "max_fetch", Config.DEFAULT_MAX_FETCH, id="max_fetch_zero"),
            pytest.param({"credentials": {"identifier": " u ", "password": " p "}}, "username", "u", id="creds_trimmed"),
        ],
    )
    def test_options(self, mock_params: dict[str, Any], overrides: dict, key: str, expected: Any) -> None:
        assert parse_integration_params(mock_params | overrides)[key] == expected

    def test_max_fetch_missing(self, mock_params: dict[str, Any]) -> None:
        mock_params.pop("max_fetch")
        assert parse_integration_params(mock_params)["max_fetch"] == Config.DEFAULT_MAX_FETCH

    @pytest.mark.parametrize(
        "overrides, expected_error",
        [
            pytest.param({"url": ""}, Messages.MISSING_URL, id="empty_url"),
            pytest.param({"url": "   "}, Messages.MISSING_URL, id="blank_url"),
            pytest.param({"credentials": {}}, Messages.MISSING_CREDENTIALS, id="no_credentials"),
            pytest.param({"credentials": {"identifier": "u"}}, Messages.MISSING_CREDENTIALS, id="no_password"),
            pytest.param({"credentials": {"password": "p"}}, Messages.MISSING_CREDENTIALS, id="no_username"),
        ],
    )
    def test_missing_required(self, mock_params: dict[str, Any], overrides: dict, expected_error: str) -> None:
        with pytest.raises(DemistoException, match=re.escape(expected_error)):
            parse_integration_params(mock_params | overrides)

    @pytest.mark.parametrize("missing_key", ["url", "credentials"])
    def test_missing_keys(self, mock_params: dict[str, Any], missing_key: str) -> None:
        mock_params.pop(missing_key)
        with pytest.raises(DemistoException):
            parse_integration_params(mock_params)

    def test_password_not_logged(self, mock_params: dict[str, Any]) -> None:
        with patch.object(demisto, "debug") as mock_debug:
            parse_integration_params(mock_params)
        assert all("test_password" not in str(call) for call in mock_debug.call_args_list)


# endregion

# region Client
# =================================
# Client
# =================================


class TestClient:
    """ContentClient uses httpx, so client.get() is mocked directly."""

    @pytest.mark.parametrize(
        "api_response, expected_count",
        [
            pytest.param(SAMPLE_ALERTS, len(SAMPLE_ALERTS), id="multiple_alerts"),
            pytest.param([SAMPLE_ALERTS[0]], 1, id="single_alert"),
            pytest.param([], 0, id="empty"),
        ],
    )
    def test_get_alerts_returns_list(self, client: SAPETDClient, api_response: list, expected_count: int) -> None:
        with patch.object(client, "get", return_value=api_response) as mock_get:
            result = client.get_alerts(from_timestamp=FROM_TIMESTAMP, batch_size=100)
        assert len(result) == expected_count
        mock_get.assert_called_once()

    def test_get_alerts_request(self, client: SAPETDClient) -> None:
        """The documented endpoint and query parameters are sent, and parsed JSON is requested."""
        with patch.object(client, "get", return_value=[]) as mock_get:
            client.get_alerts(from_timestamp=FROM_TIMESTAMP, batch_size=500)
        kwargs = mock_get.call_args.kwargs
        assert kwargs["url_suffix"] == Config.ALERTS_ENDPOINT
        assert kwargs["resp_type"] == "json"
        assert kwargs["params"] == {
            "$query": f"{Config.ALERT_TIME_FIELD} ge {FROM_TIMESTAMP}",
            "$format": Config.RESPONSE_FORMAT,
            "$batchSize": "500",
            "$includeEvents": Config.INCLUDE_EVENTS,
        }

    def test_get_alerts_default_batch_size(self, client: SAPETDClient) -> None:
        with patch.object(client, "get", return_value=[]) as mock_get:
            client.get_alerts(from_timestamp=FROM_TIMESTAMP)
        assert mock_get.call_args.kwargs["params"]["$batchSize"] == str(Config.MAX_PAGE_SIZE)

    @pytest.mark.parametrize(
        "api_response",
        [
            pytest.param({"error": "unexpected"}, id="dict"),
            pytest.param("<html>login</html>", id="string"),
            pytest.param(None, id="none"),
        ],
    )
    def test_get_alerts_non_list_raises(self, client: SAPETDClient, api_response: Any) -> None:
        """A non-list response raises instead of silently returning no alerts."""
        with patch.object(client, "get", return_value=api_response), pytest.raises(DemistoException, match="JSON array"):
            client.get_alerts(from_timestamp=FROM_TIMESTAMP)

    @pytest.mark.parametrize(
        "error",
        [
            pytest.param(DemistoException("API Error 500"), id="demisto_exception"),
            pytest.param(ConnectionError("Connection refused"), id="connection_error"),
        ],
    )
    def test_get_alerts_propagates_errors(self, client: SAPETDClient, error: Exception) -> None:
        with patch.object(client, "get", side_effect=error), pytest.raises(type(error)):
            client.get_alerts(from_timestamp=FROM_TIMESTAMP)

    @pytest.mark.parametrize("events", [pytest.param(SAMPLE_ALERTS, id="events"), pytest.param([], id="empty")])
    def test_send_events(self, client: SAPETDClient, events: list[dict]) -> None:
        with patch("SAPETD.send_events_to_xsiam") as mock_send:
            client.send_events(events)
        mock_send.assert_called_once_with(events=events, vendor=Config.VENDOR, product=Config.PRODUCT)


# endregion

# region Pagination
# =================================
# Pagination
# =================================


class TestFetchAlertsWithPagination:
    def test_sorted_by_creation_time(self, client: SAPETDClient) -> None:
        unsorted = [make_alert(2, "2022-04-29T15:00:00.000Z"), make_alert(1, "2022-04-29T14:00:00.000Z")]
        with patch.object(client, "get_alerts", return_value=unsorted):
            result = fetch_alerts_with_pagination(client, FROM_TIMESTAMP, max_alerts=10)
        assert [alert[Config.ALERT_ID_FIELD] for alert in result] == [1, 2]

    @pytest.mark.parametrize(
        "pages, max_alerts, expected_count, expected_calls, expected_batch_sizes",
        [
            pytest.param([[]], 10, 0, 1, [10], id="empty"),
            pytest.param([make_page(1, 3)], 10, 3, 1, [10], id="single_partial_page"),
            pytest.param([make_page(1, 50)], 50, 50, 1, [50], id="exact_small_page"),
            pytest.param([make_page(1, 1000), make_page(1001, 500)], 1500, 1500, 2, [1000, 500], id="two_full_pages"),
            pytest.param([make_page(1, 1000), []], 2000, 1000, 2, [1000, 1000], id="stops_on_empty_page"),
            pytest.param([make_page(1, 800)], 2000, 800, 1, [1000], id="stops_on_partial_page"),
            pytest.param(
                [make_page(1, 1000), make_page(1001, 1000), make_page(2001, 1000)],
                3000,
                3000,
                3,
                [1000, 1000, 1000],
                id="three_full_pages",
            ),
        ],
    )
    def test_pagination(
        self,
        client: SAPETDClient,
        pages: list,
        max_alerts: int,
        expected_count: int,
        expected_calls: int,
        expected_batch_sizes: list[int],
    ) -> None:
        with patch.object(client, "get_alerts", side_effect=pages) as mock_get:
            result = fetch_alerts_with_pagination(client, FROM_TIMESTAMP, max_alerts=max_alerts)
        assert len(result) == expected_count
        assert mock_get.call_count == expected_calls
        assert [call.kwargs["batch_size"] for call in mock_get.call_args_list] == expected_batch_sizes

    def test_cursor_moves_to_last_alert_timestamp(self, client: SAPETDClient) -> None:
        first_page = make_page(1, 1000)
        with patch.object(client, "get_alerts", side_effect=[first_page, make_page(1001, 10)]) as mock_get:
            fetch_alerts_with_pagination(client, FROM_TIMESTAMP, max_alerts=1500)
        assert mock_get.call_args_list[0].kwargs["from_timestamp"] == FROM_TIMESTAMP
        assert mock_get.call_args_list[1].kwargs["from_timestamp"] == first_page[-1][Config.ALERT_TIME_FIELD]

    def test_boundary_alerts_not_duplicated(self, client: SAPETDClient) -> None:
        """Alerts repeated at the start of the next page ('ge' filter) are collected once."""
        boundary = "2022-04-29T15:00:00.000Z"
        first_page = make_page(1, 998) + [make_alert(9001, boundary), make_alert(9002, boundary)]
        second_page = [make_alert(9001, boundary), make_alert(9002, boundary), make_alert(9003, "2022-04-29T16:00:00.000Z")]
        with patch.object(client, "get_alerts", side_effect=[first_page, second_page]):
            result = fetch_alerts_with_pagination(client, FROM_TIMESTAMP, max_alerts=1500)
        ids = [alert[Config.ALERT_ID_FIELD] for alert in result]
        assert len(ids) == len(set(ids)) == 1001

    def test_stops_when_cursor_does_not_advance(self, client: SAPETDClient) -> None:
        """A full page sharing one timestamp is not re-fetched forever."""
        uniform_page = make_page(1, Config.MAX_PAGE_SIZE, timestamp="2022-04-29T14:00:00.000Z")
        with patch.object(client, "get_alerts", return_value=uniform_page) as mock_get:
            result = fetch_alerts_with_pagination(client, FROM_TIMESTAMP, max_alerts=Config.DEFAULT_MAX_FETCH)
        assert len(result) == Config.MAX_PAGE_SIZE
        assert mock_get.call_count == 2

    def test_stops_when_last_alert_has_no_timestamp(self, client: SAPETDClient) -> None:
        page = make_page(1, Config.MAX_PAGE_SIZE)
        page[-1].pop(Config.ALERT_TIME_FIELD)
        with patch.object(client, "get_alerts", return_value=page) as mock_get:
            result = fetch_alerts_with_pagination(client, FROM_TIMESTAMP, max_alerts=2000)
        assert len(result) == Config.MAX_PAGE_SIZE
        assert mock_get.call_count == 1

    def test_truncates_when_server_ignores_batch_size(self, client: SAPETDClient) -> None:
        with patch.object(client, "get_alerts", return_value=make_page(1, 5)):
            result = fetch_alerts_with_pagination(client, FROM_TIMESTAMP, max_alerts=2)
        assert len(result) == 2

    def test_propagates_client_errors(self, client: SAPETDClient) -> None:
        with patch.object(client, "get_alerts", side_effect=DemistoException("API Error")), pytest.raises(DemistoException):
            fetch_alerts_with_pagination(client, FROM_TIMESTAMP, max_alerts=10)


# endregion

# region test-module
# =================================
# test-module
# =================================


class TestTestModule:
    @pytest.mark.parametrize("alerts", [pytest.param([SAMPLE_ALERTS[0]], id="alerts"), pytest.param([], id="no_alerts")])
    def test_success(self, client: SAPETDClient, alerts: list[dict]) -> None:
        with patch.object(client, "get_alerts", return_value=alerts) as mock_get:
            assert run_test_module(client) == "ok"
        assert mock_get.call_args.kwargs["batch_size"] == Config.TEST_MODULE_MAX_EVENTS

    @pytest.mark.parametrize(
        "status_code",
        [
            pytest.param(HTTPStatus.UNAUTHORIZED, id="401"),
            pytest.param(HTTPStatus.FORBIDDEN, id="403"),
            pytest.param(HTTPStatus.NOT_FOUND, id="404"),
        ],
    )
    def test_http_errors_classified_by_status(self, client: SAPETDClient, status_code: HTTPStatus) -> None:
        with patch.object(client, "get_alerts", side_effect=http_error(int(status_code))):
            assert run_test_module(client) == Messages.HTTP_ERRORS[status_code]

    def test_404_body_with_401_is_not_auth_error(self, client: SAPETDClient) -> None:
        """Regression: a 404 page containing '401' inside a number is not reported as an auth error."""
        error = http_error(HTTPStatus.NOT_FOUND, "Page not found. lastModification=1791401531072")
        with patch.object(client, "get_alerts", side_effect=error):
            assert run_test_module(client) == Messages.HTTP_ERRORS[HTTPStatus.NOT_FOUND]

    def test_non_json_response(self, client: SAPETDClient) -> None:
        """An HTML page returned with 200 fails the test instead of reporting 'ok'."""
        with patch.object(client, "get_alerts", side_effect=json.JSONDecodeError("Expecting value", "<html>", 0)):
            assert run_test_module(client) == Messages.NON_JSON_RESPONSE

    def test_non_list_response_raises(self, client: SAPETDClient) -> None:
        with patch.object(client, "get", return_value={"error": "x"}), pytest.raises(DemistoException, match="JSON array"):
            run_test_module(client)

    @pytest.mark.parametrize(
        "error",
        [
            pytest.param(Exception("401 Unauthorized"), id="auth_text_without_status"),
            pytest.param(http_error(HTTPStatus.INTERNAL_SERVER_ERROR), id="500"),
            pytest.param(ConnectionError("timeout"), id="connection_error"),
        ],
    )
    def test_other_errors_are_raised(self, client: SAPETDClient, error: Exception) -> None:
        """Errors without a known status code are raised, never guessed from their text."""
        with patch.object(client, "get_alerts", side_effect=error), pytest.raises(type(error)):
            run_test_module(client)

    def test_error_body_not_logged(self, client: SAPETDClient) -> None:
        error = http_error(HTTPStatus.UNAUTHORIZED, "secret-response-body")
        with patch.object(client, "get_alerts", side_effect=error), patch.object(demisto, "debug") as mock_debug:
            run_test_module(client)
        assert all("secret-response-body" not in str(call) for call in mock_debug.call_args_list)


# endregion

# region get-events
# =================================
# get-events
# =================================


class TestGetEventsCommand:
    def test_returns_command_results(self, client: SAPETDClient, sample_alerts: list[dict]) -> None:
        with patch.object(client, "get_alerts", return_value=sample_alerts):
            result = get_events_command(client, {"from_date": "3 days ago", "limit": "50"})
        assert isinstance(result, CommandResults)
        assert result.outputs_prefix == Config.OUTPUTS_PREFIX
        assert result.outputs_key_field == Config.ALERT_ID_FIELD
        assert result.outputs == sample_alerts
        assert Config.TABLE_TITLE in result.readable_output
        for header in Config.TABLE_HEADERS:
            assert header in result.readable_output

    @pytest.mark.parametrize(
        "args, expected_limit",
        [
            pytest.param({}, Config.DEFAULT_LIMIT, id="defaults"),
            pytest.param({"limit": "1"}, 1, id="custom_limit"),
            pytest.param({"limit": "0"}, Config.DEFAULT_LIMIT, id="zero_limit_uses_default"),
        ],
    )
    def test_limit(self, client: SAPETDClient, args: dict, expected_limit: int) -> None:
        with patch.object(client, "get_alerts", return_value=[]) as mock_get:
            get_events_command(client, args)
        assert mock_get.call_args.kwargs["batch_size"] == expected_limit

    def test_default_from_date(self, client: SAPETDClient) -> None:
        with (
            patch("SAPETD.parse_date_to_iso", return_value=FROM_TIMESTAMP) as mock_parse,
            patch.object(client, "get_alerts", return_value=[]),
        ):
            get_events_command(client, {})
        mock_parse.assert_called_once_with(Config.DEFAULT_FIRST_FETCH)

    def test_push_events(self, client: SAPETDClient, sample_alerts: list[dict]) -> None:
        with patch.object(client, "get_alerts", return_value=sample_alerts), patch("SAPETD.send_events_to_xsiam") as mock_send:
            result = get_events_command(client, {"should_push_events": "true"})
        assert result == Messages.PUSHED_EVENTS.format(count=len(sample_alerts))
        sent = mock_send.call_args.kwargs["events"]
        assert all(Config.XSIAM_TIME_FIELD in event for event in sent)

    @pytest.mark.parametrize("should_push", ["true", "false"])
    def test_no_alerts(self, client: SAPETDClient, should_push: str) -> None:
        with patch.object(client, "get_alerts", return_value=[]), patch("SAPETD.send_events_to_xsiam") as mock_send:
            result = get_events_command(client, {"should_push_events": should_push})
        assert isinstance(result, CommandResults)
        assert result.outputs == []
        mock_send.assert_not_called()


# endregion

# region fetch-events
# =================================
# fetch-events
# =================================


class TestFetchEventsCommand:
    def test_first_run(self, client: SAPETDClient, sample_alerts: list[dict]) -> None:
        with (
            patch.object(demisto, "getLastRun", return_value={}),
            patch.object(demisto, "setLastRun") as mock_set,
            patch("SAPETD.parse_date_to_iso", return_value=FROM_TIMESTAMP) as mock_parse,
            patch.object(client, "get_alerts", return_value=sample_alerts) as mock_get,
            patch("SAPETD.send_events_to_xsiam") as mock_send,
        ):
            fetch_events_command(client, max_fetch=100)
        mock_parse.assert_called_once_with(Config.DEFAULT_FIRST_FETCH)
        assert mock_get.call_args.kwargs["from_timestamp"] == FROM_TIMESTAMP
        assert len(mock_send.call_args.kwargs["events"]) == len(sample_alerts)
        mock_set.assert_called_once_with(build_next_last_run(sample_alerts))

    def test_subsequent_run_deduplicates(self, client: SAPETDClient, sample_alerts: list[dict]) -> None:
        last_run = {Config.LAST_RUN_TIMESTAMP_KEY: "2022-04-29T14:20:29.682Z", Config.LAST_RUN_IDS_KEY: [6101]}
        with (
            patch.object(demisto, "getLastRun", return_value=last_run),
            patch.object(demisto, "setLastRun"),
            patch.object(client, "get_alerts", return_value=sample_alerts) as mock_get,
            patch("SAPETD.send_events_to_xsiam") as mock_send,
        ):
            fetch_events_command(client, max_fetch=100)
        assert mock_get.call_args.kwargs["from_timestamp"] == last_run[Config.LAST_RUN_TIMESTAMP_KEY]
        sent_ids = [event[Config.ALERT_ID_FIELD] for event in mock_send.call_args.kwargs["events"]]
        assert 6101 not in sent_ids

    def test_all_duplicates_still_advance_last_run(self, client: SAPETDClient) -> None:
        alert = make_alert(1, "2022-04-29T14:00:00.000Z")
        last_run = {Config.LAST_RUN_TIMESTAMP_KEY: alert[Config.ALERT_TIME_FIELD], Config.LAST_RUN_IDS_KEY: [1]}
        with (
            patch.object(demisto, "getLastRun", return_value=last_run),
            patch.object(demisto, "setLastRun") as mock_set,
            patch.object(client, "get_alerts", return_value=[alert]),
            patch("SAPETD.send_events_to_xsiam") as mock_send,
        ):
            fetch_events_command(client, max_fetch=100)
        mock_send.assert_not_called()
        mock_set.assert_called_once()

    @pytest.mark.parametrize(
        "alerts",
        [pytest.param([], id="no_alerts"), pytest.param([{Config.ALERT_ID_FIELD: 1}], id="last_alert_without_timestamp")],
    )
    def test_last_run_not_updated(self, client: SAPETDClient, alerts: list[dict]) -> None:
        with (
            patch.object(demisto, "getLastRun", return_value={}),
            patch.object(demisto, "setLastRun") as mock_set,
            patch.object(client, "get_alerts", return_value=alerts),
            patch("SAPETD.send_events_to_xsiam"),
        ):
            fetch_events_command(client, max_fetch=100)
        mock_set.assert_not_called()

    def test_failed_send_does_not_update_last_run(self, client: SAPETDClient, sample_alerts: list[dict]) -> None:
        """If sending to XSIAM fails, the same alerts are fetched again on the next cycle."""
        with (
            patch.object(demisto, "getLastRun", return_value={}),
            patch.object(demisto, "setLastRun") as mock_set,
            patch.object(client, "get_alerts", return_value=sample_alerts),
            patch("SAPETD.send_events_to_xsiam", side_effect=DemistoException("XSIAM down")),
            pytest.raises(DemistoException),
        ):
            fetch_events_command(client, max_fetch=100)
        mock_set.assert_not_called()

    @pytest.mark.parametrize("raw_ids", [pytest.param(None, id="none"), pytest.param("6101", id="string")])
    def test_invalid_previous_ids_ignored(self, client: SAPETDClient, sample_alerts: list[dict], raw_ids: Any) -> None:
        last_run = {Config.LAST_RUN_TIMESTAMP_KEY: FROM_TIMESTAMP, Config.LAST_RUN_IDS_KEY: raw_ids}
        with (
            patch.object(demisto, "getLastRun", return_value=last_run),
            patch.object(demisto, "setLastRun"),
            patch.object(client, "get_alerts", return_value=sample_alerts),
            patch("SAPETD.send_events_to_xsiam") as mock_send,
        ):
            fetch_events_command(client, max_fetch=100)
        assert len(mock_send.call_args.kwargs["events"]) == len(sample_alerts)


# endregion

# region main
# =================================
# main
# =================================


class TestMain:
    @pytest.mark.parametrize(
        "command, handler",
        [
            pytest.param(Commands.TEST_MODULE, "test_module", id="test_module"),
            pytest.param(Commands.GET_EVENTS, "get_events_command", id="get_events"),
        ],
    )
    def test_routes_commands_with_results(self, mock_params: dict[str, Any], command: str, handler: str) -> None:
        with (
            patch.object(demisto, "command", return_value=command),
            patch.object(demisto, "params", return_value=mock_params),
            patch.object(demisto, "args", return_value={}),
            patch(f"SAPETD.{handler}", return_value="result") as mock_handler,
            patch("SAPETD.return_results") as mock_return,
        ):
            main()
        mock_handler.assert_called_once()
        mock_return.assert_called_once_with("result")

    def test_routes_fetch_events(self, mock_params: dict[str, Any]) -> None:
        with (
            patch.object(demisto, "command", return_value=Commands.FETCH_EVENTS),
            patch.object(demisto, "params", return_value=mock_params | {"max_fetch": "123"}),
            patch("SAPETD.fetch_events_command") as mock_fetch,
        ):
            main()
        assert mock_fetch.call_args.kwargs["max_fetch"] == 123

    @pytest.mark.parametrize(
        "command, params_override, expected_in_error",
        [
            pytest.param("unknown-command", {}, "unknown-command", id="unknown_command"),
            pytest.param(Commands.TEST_MODULE, {"credentials": {}}, Messages.MISSING_CREDENTIALS, id="invalid_params"),
        ],
    )
    def test_errors_reported(
        self, mock_params: dict[str, Any], command: str, params_override: dict, expected_in_error: str
    ) -> None:
        with (
            patch.object(demisto, "command", return_value=command),
            patch.object(demisto, "params", return_value=mock_params | params_override),
            patch.object(demisto, "error"),
            patch("SAPETD.return_error") as mock_error,
        ):
            main()
        error_message = mock_error.call_args.args[0]
        assert command in error_message
        assert expected_in_error in error_message

    def test_handler_exception_reported(self, mock_params: dict[str, Any]) -> None:
        with (
            patch.object(demisto, "command", return_value=Commands.FETCH_EVENTS),
            patch.object(demisto, "params", return_value=mock_params),
            patch.object(demisto, "error"),
            patch("SAPETD.fetch_events_command", side_effect=DemistoException("API Error")),
            patch("SAPETD.return_error") as mock_error,
        ):
            main()
        assert "API Error" in mock_error.call_args.args[0]


# endregion

# region Config
# =================================
# Config
# =================================


class TestConfig:
    def test_values(self) -> None:
        assert INTEGRATION_NAME == "SAP Enterprise Threat Detection"
        assert (Config.VENDOR, Config.PRODUCT) == ("SAP", "Threat Detection")
        assert Config.ALERTS_ENDPOINT == "/sap/secmon/services/Alerts.xsjs"
        assert Config.DEFAULT_MAX_FETCH == 10000
        assert Config.DEFAULT_FIRST_FETCH == "5 minutes ago"
        assert Config.MAX_PAGE_SIZE <= Config.DEFAULT_MAX_FETCH


# endregion
