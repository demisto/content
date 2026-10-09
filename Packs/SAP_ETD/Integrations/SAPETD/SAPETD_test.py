"""Tests for the SAP Enterprise Threat Detection integration (On-Premise and Cloud Edition)."""

import asyncio
import copy
import json
import os
import re
from datetime import UTC, datetime
from http import HTTPStatus
from typing import Any
from unittest.mock import AsyncMock, patch

import demistomock as demisto
import httpx
import pytest
from CommonServerPython import *  # noqa: F401,F403
from ContentClientApiModule import ContentClientAuthenticationError, OAuth2ClientCredentialsHandler

with patch("ContentClientApiModule.support_multithreading"):
    from SAPETD import (
        ALERTS_APIS,
        INTEGRATION_NAME,
        CloudAlertsApi,
        CloudOAuth2Handler,
        Commands,
        Config,
        Edition,
        Messages,
        OnPremAlertsApi,
        SAPETDClient,
        add_time_to_events,
        build_next_last_run,
        build_token_url,
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
        truncate_to_milliseconds,
    )

# region Test data and helpers
# =================================
# Test data and helpers
# =================================

TEST_DATA_DIR = os.path.join(os.path.dirname(__file__), "test_data")
SERVER_URL = "https://etd.example.com:4300"
CLOUD_SERVICE_URL = "https://retrieval.example.cfapps.eu10.hana.ondemand.com"
CLOUD_TOKEN_BASE = "https://tenant.authentication.eu10.hana.ondemand.com"
FROM_TIMESTAMP = "2022-04-29T14:00:00.000Z"
OUTPUT_TIMESTAMP_PATTERN = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$"
OUTPUT_TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
ON_PREM_TIME = OnPremAlertsApi.TIME_FIELD
CLOUD_TIME = CloudAlertsApi.TIME_FIELD


def load_test_data(filename: str) -> Any:
    """Load a JSON file from the test_data directory."""
    with open(os.path.join(TEST_DATA_DIR, filename)) as file:
        return json.load(file)


SAMPLE_ALERTS: list[dict[str, Any]] = load_test_data("sample_alerts.json")
SAMPLE_CLOUD_RESPONSE: dict[str, Any] = load_test_data("sample_cloud_response.json")
SAMPLE_CLOUD_ALERTS: list[dict[str, Any]] = SAMPLE_CLOUD_RESPONSE["value"]


def make_alert(alert_id: int, timestamp: str, time_field: str = ON_PREM_TIME) -> dict[str, Any]:
    """Build a minimal alert."""
    return {Config.ALERT_ID_FIELD: alert_id, time_field: timestamp}


def make_page(start_id: int, count: int, timestamp: str | None = None) -> list[dict[str, Any]]:
    """Build a page of on-prem alerts, each with its own timestamp unless one is given."""
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
def mock_runtime():
    """Prevent ContentClient from calling the XSOAR runtime during client creation."""
    with (
        patch("ContentClientApiModule.support_multithreading"),
        patch.object(demisto, "getIntegrationContext", return_value={}),
    ):
        yield


@pytest.fixture
def sample_alerts() -> list[dict[str, Any]]:
    """Deep copy of the on-prem sample alerts, for test isolation."""
    return copy.deepcopy(SAMPLE_ALERTS)


@pytest.fixture
def sample_cloud_alerts() -> list[dict[str, Any]]:
    """Deep copy of the Cloud Edition sample alerts, for test isolation."""
    return copy.deepcopy(SAMPLE_CLOUD_ALERTS)


@pytest.fixture
def mock_params() -> dict[str, Any]:
    """Raw on-prem integration params, as returned by demisto.params()."""
    return {
        "edition": Edition.ON_PREM,
        "url": SERVER_URL,
        "credentials": {"identifier": "test_user", "password": "test_password"},
        "insecure": False,
        "proxy": False,
        "max_fetch": str(Config.DEFAULT_MAX_FETCH),
    }


@pytest.fixture
def cloud_params() -> dict[str, Any]:
    """Raw Cloud Edition integration params, as returned by demisto.params()."""
    return {
        "edition": Edition.CLOUD,
        "url": CLOUD_SERVICE_URL,
        "token_url": CLOUD_TOKEN_BASE,
        "credentials": {"identifier": "client-id", "password": "client-secret"},
        "insecure": False,
        "proxy": False,
    }


@pytest.fixture
def client(mock_params: dict[str, Any]) -> SAPETDClient:
    """An on-prem SAPETDClient."""
    return SAPETDClient(parse_integration_params(mock_params))


@pytest.fixture
def cloud_client(cloud_params: dict[str, Any]) -> SAPETDClient:
    """A Cloud Edition SAPETDClient."""
    return SAPETDClient(parse_integration_params(cloud_params))


# endregion

# region Helpers
# =================================
# Helpers
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
        assert format_timestamp(value) == expected


class TestTruncateToMilliseconds:
    @pytest.mark.parametrize(
        "timestamp, expected",
        [
            pytest.param("2026-01-15T15:00:01.1234567Z", "2026-01-15T15:00:01.123Z", id="cloud_7_digits"),
            pytest.param("2026-01-15T15:00:01.123456Z", "2026-01-15T15:00:01.123Z", id="6_digits"),
            pytest.param("2026-01-15T15:00:01.123Z", "2026-01-15T15:00:01.123Z", id="already_ms"),
            pytest.param("2026-01-15T15:00:01.12Z", "2026-01-15T15:00:01.12Z", id="2_digits_kept"),
            pytest.param("2026-01-15T15:00:01Z", "2026-01-15T15:00:01Z", id="no_fraction"),
        ],
    )
    def test_truncate(self, timestamp: str, expected: str) -> None:
        assert truncate_to_milliseconds(timestamp) == expected


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
        before = datetime.now(tz=UTC).replace(microsecond=0)
        with patch("SAPETD.arg_to_datetime", side_effect=side_effect, return_value=None):
            result = parse_date_to_iso(date_input)
        parsed = datetime.strptime(result, OUTPUT_TIMESTAMP_FORMAT).replace(tzinfo=UTC)
        assert before <= parsed <= datetime.now(tz=UTC)


class TestBuildTokenUrl:
    @pytest.mark.parametrize(
        "raw, expected",
        [
            pytest.param(CLOUD_TOKEN_BASE, f"{CLOUD_TOKEN_BASE}/oauth/token", id="base_url"),
            pytest.param(f"{CLOUD_TOKEN_BASE}/", f"{CLOUD_TOKEN_BASE}/oauth/token", id="trailing_slash"),
            pytest.param(f"{CLOUD_TOKEN_BASE}/oauth/token", f"{CLOUD_TOKEN_BASE}/oauth/token", id="full_url"),
            pytest.param(f" {CLOUD_TOKEN_BASE}/oauth/token/ ", f"{CLOUD_TOKEN_BASE}/oauth/token", id="whitespace"),
        ],
    )
    def test_build_token_url(self, raw: str, expected: str) -> None:
        assert build_token_url(raw) == expected


class TestAddTimeToEvents:
    @pytest.mark.parametrize(
        "event, time_field, expected_time",
        [
            pytest.param(
                make_alert(1, "2022-04-29T14:20:29.682Z"), ON_PREM_TIME, "2022-04-29T14:20:29.682000+00:00", id="on_prem"
            ),
            pytest.param(
                make_alert(1, "2026-01-15T15:00:01.1234567Z", CLOUD_TIME),
                CLOUD_TIME,
                "2026-01-15T15:00:01.123000+00:00",
                id="cloud_7_digits",
            ),
            pytest.param({Config.ALERT_ID_FIELD: 2}, ON_PREM_TIME, None, id="missing_timestamp"),
            pytest.param(make_alert(3, ""), ON_PREM_TIME, None, id="empty_timestamp"),
            pytest.param({ON_PREM_TIME: ""}, ON_PREM_TIME, None, id="missing_id_and_timestamp"),
        ],
    )
    def test_sets_time_field(self, event: dict[str, Any], time_field: str, expected_time: str | None) -> None:
        add_time_to_events([event], time_field)
        assert event.get(Config.XSIAM_TIME_FIELD) == expected_time

    def test_unparsable_timestamp_is_kept_as_is(self) -> None:
        event = make_alert(1, "garbage")
        with patch("SAPETD.arg_to_datetime", return_value=None):
            add_time_to_events([event], ON_PREM_TIME)
        assert event[Config.XSIAM_TIME_FIELD] == "garbage"


class TestDeduplicateEvents:
    @pytest.mark.parametrize(
        "events, last_ids, expected_ids",
        [
            pytest.param([], [1], [], id="no_events"),
            pytest.param([make_alert(1, "t")], [], [1], id="no_previous_ids"),
            pytest.param([make_alert(1, "t"), make_alert(2, "t")], [1], [2], id="one_duplicate"),
            pytest.param([make_alert(1, "t"), make_alert(2, "t")], [1, 2], [], id="all_duplicates"),
            pytest.param([make_alert(1, "t"), make_alert(2, "t")], [3], [1, 2], id="no_duplicates"),
            pytest.param([{ON_PREM_TIME: "t"}], [1], [None], id="alert_without_id_kept"),
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
            pytest.param([{ON_PREM_TIME: "t"}, make_alert(5, "t")], set(), [None, 5], {5}, id="missing_id_not_tracked"),
        ],
    )
    def test_filter(self, batch: list[dict], seen: set, expected_ids: list, expected_seen: set) -> None:
        result = filter_new_alerts(batch, seen)
        assert [alert.get(Config.ALERT_ID_FIELD) for alert in result] == expected_ids
        assert seen == expected_seen


class TestBuildNextLastRun:
    @pytest.mark.parametrize(
        "events, time_field, expected",
        [
            pytest.param(
                [make_alert(1, "t1"), make_alert(2, "t2"), make_alert(3, "t2")],
                ON_PREM_TIME,
                {Config.LAST_RUN_TIMESTAMP_KEY: "t2", Config.LAST_RUN_IDS_KEY: [2, 3]},
                id="ids_at_high_water_mark",
            ),
            pytest.param(
                [make_alert(1, "t1", CLOUD_TIME), make_alert(2, "t1", CLOUD_TIME)],
                CLOUD_TIME,
                {Config.LAST_RUN_TIMESTAMP_KEY: "t1", Config.LAST_RUN_IDS_KEY: [1, 2]},
                id="cloud_time_field",
            ),
            pytest.param(
                [make_alert(1, "t1"), {ON_PREM_TIME: "t1"}],
                ON_PREM_TIME,
                {Config.LAST_RUN_TIMESTAMP_KEY: "t1", Config.LAST_RUN_IDS_KEY: [1]},
                id="alert_without_id_ignored",
            ),
            pytest.param([make_alert(1, "t1"), {Config.ALERT_ID_FIELD: 2}], ON_PREM_TIME, None, id="last_without_timestamp"),
        ],
    )
    def test_build(self, events: list[dict], time_field: str, expected: dict | None) -> None:
        assert build_next_last_run(events, time_field) == expected


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

# region Edition APIs
# =================================
# Edition APIs
# =================================


class TestOnPremAlertsApi:
    def test_build_request(self) -> None:
        params, raw_query = OnPremAlertsApi().build_request(FROM_TIMESTAMP, 500)
        assert params == {
            "$query": f"{ON_PREM_TIME} ge {FROM_TIMESTAMP}",
            "$format": OnPremAlertsApi.RESPONSE_FORMAT,
            "$batchSize": "500",
            "$includeEvents": OnPremAlertsApi.INCLUDE_EVENTS,
        }
        assert raw_query == ""

    def test_extract_alerts(self) -> None:
        assert OnPremAlertsApi().extract_alerts(SAMPLE_ALERTS) == SAMPLE_ALERTS

    @pytest.mark.parametrize("response", [{"value": []}, "<html>login</html>", None])
    def test_extract_alerts_non_list_raises(self, response: Any) -> None:
        with pytest.raises(DemistoException, match="JSON array"):
            OnPremAlertsApi().extract_alerts(response)


class TestCloudAlertsApi:
    @pytest.mark.parametrize(
        "from_timestamp, expected_filter_time",
        [
            pytest.param("2026-01-15T15:00:01.1234567Z", "2026-01-15T15:00:01.123Z", id="cloud_cursor_truncated"),
            pytest.param(FROM_TIMESTAMP, FROM_TIMESTAMP, id="ms_timestamp"),
        ],
    )
    def test_build_request(self, from_timestamp: str, expected_filter_time: str) -> None:
        """Spaces are sent as %20 (the server rejects '+') and the timestamp has at most 3 fractional digits."""
        params, raw_query = CloudAlertsApi().build_request(from_timestamp, 10)
        assert params == {}
        assert raw_query == (
            f"$filter=CreationTimestamp%20ge%20{expected_filter_time}&$orderby=CreationTimestamp%20asc,AlertId%20asc&$top=10"
        )
        assert "+" not in raw_query

    def test_extract_alerts(self) -> None:
        assert CloudAlertsApi().extract_alerts(SAMPLE_CLOUD_RESPONSE) == SAMPLE_CLOUD_ALERTS

    @pytest.mark.parametrize(
        "response",
        [
            pytest.param(SAMPLE_CLOUD_ALERTS, id="bare_list"),
            pytest.param({"error": {"code": "400"}}, id="missing_value"),
            pytest.param({"value": "x"}, id="value_not_list"),
            pytest.param("<html>login</html>", id="string"),
        ],
    )
    def test_extract_alerts_invalid_raises(self, response: Any) -> None:
        with pytest.raises(DemistoException, match="'value' list"):
            CloudAlertsApi().extract_alerts(response)


class TestCloudOAuth2Handler:
    @pytest.mark.parametrize(
        "raw_query, expected_url",
        [
            pytest.param(
                "$filter=A%20ge%20B&$top=1", f"{CLOUD_SERVICE_URL}/alerts/v1/Alerts?$filter=A%20ge%20B&$top=1", id="set"
            ),
            pytest.param("", f"{CLOUD_SERVICE_URL}/alerts/v1/Alerts", id="empty_unchanged"),
        ],
    )
    def test_on_request_sets_raw_query(self, cloud_client: SAPETDClient, raw_query: str, expected_url: str) -> None:
        handler = cloud_client._cloud_auth
        assert isinstance(handler, CloudOAuth2Handler)
        handler.raw_query = raw_query
        request = httpx.Request("GET", f"{CLOUD_SERVICE_URL}/alerts/v1/Alerts", params={})
        with patch.object(OAuth2ClientCredentialsHandler, "on_request", new=AsyncMock()) as mock_super:
            asyncio.run(handler.on_request(cloud_client, request))
        mock_super.assert_awaited_once()
        assert str(request.url) == expected_url


# endregion

# region Params
# =================================
# Params
# =================================


class TestParseIntegrationParams:
    def test_on_prem(self, mock_params: dict[str, Any]) -> None:
        assert parse_integration_params(mock_params) == {
            "edition": Edition.ON_PREM,
            "base_url": SERVER_URL,
            "username": "test_user",
            "password": "test_password",
            "token_url": "",
            "verify": True,
            "proxy": False,
            "max_fetch": Config.DEFAULT_MAX_FETCH,
        }

    def test_cloud(self, cloud_params: dict[str, Any]) -> None:
        config = parse_integration_params(cloud_params)
        assert config["edition"] == Edition.CLOUD
        assert config["token_url"] == f"{CLOUD_TOKEN_BASE}/oauth/token"
        assert (config["username"], config["password"]) == ("client-id", "client-secret")

    @pytest.mark.parametrize("edition", [None, ""])
    def test_missing_edition_defaults_to_on_prem(self, mock_params: dict[str, Any], edition: str | None) -> None:
        assert parse_integration_params(mock_params | {"edition": edition})["edition"] == Edition.ON_PREM

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
            pytest.param({"token_url": CLOUD_TOKEN_BASE}, "token_url", "", id="token_url_ignored_on_prem"),
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
            pytest.param({"edition": "SaaS"}, "Invalid edition 'SaaS'", id="invalid_edition"),
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

    @pytest.mark.parametrize("token_url", [None, "", "   "])
    def test_cloud_requires_token_url(self, cloud_params: dict[str, Any], token_url: str | None) -> None:
        params = cloud_params | {"token_url": token_url}
        if token_url is None:
            params.pop("token_url")
        with pytest.raises(DemistoException, match=re.escape(Messages.MISSING_TOKEN_URL)):
            parse_integration_params(params)

    @pytest.mark.parametrize("missing_key", ["url", "credentials"])
    def test_missing_keys(self, mock_params: dict[str, Any], missing_key: str) -> None:
        mock_params.pop(missing_key)
        with pytest.raises(DemistoException):
            parse_integration_params(mock_params)

    @pytest.mark.parametrize("params_fixture", ["mock_params", "cloud_params"])
    def test_secrets_not_logged(self, request: pytest.FixtureRequest, params_fixture: str) -> None:
        params = request.getfixturevalue(params_fixture)
        with patch.object(demisto, "debug") as mock_debug:
            parse_integration_params(params)
        logged = str(mock_debug.call_args_list)
        assert params["credentials"]["password"] not in logged


# endregion

# region Client
# =================================
# Client
# =================================


class TestClient:
    """ContentClient uses httpx, so client.get() is mocked directly."""

    @pytest.mark.parametrize(
        "client_fixture, api_type, has_cloud_auth",
        [
            pytest.param("client", OnPremAlertsApi, False, id="on_prem"),
            pytest.param("cloud_client", CloudAlertsApi, True, id="cloud"),
        ],
    )
    def test_init_selects_edition(
        self, request: pytest.FixtureRequest, client_fixture: str, api_type: type, has_cloud_auth: bool
    ) -> None:
        sap_client = request.getfixturevalue(client_fixture)
        assert isinstance(sap_client.api, api_type)
        assert isinstance(sap_client._cloud_auth, CloudOAuth2Handler) is has_cloud_auth

    def test_editions_map(self) -> None:
        assert ALERTS_APIS == {Edition.ON_PREM: OnPremAlertsApi, Edition.CLOUD: CloudAlertsApi}

    def test_on_prem_get_alerts(self, client: SAPETDClient, sample_alerts: list[dict]) -> None:
        with patch.object(client, "get", return_value=sample_alerts) as mock_get:
            result = client.get_alerts(from_timestamp=FROM_TIMESTAMP, batch_size=500)
        assert result == sample_alerts
        kwargs = mock_get.call_args.kwargs
        assert kwargs["url_suffix"] == OnPremAlertsApi.ENDPOINT
        assert kwargs["resp_type"] == "json"
        assert kwargs["params"]["$batchSize"] == "500"

    def test_on_prem_default_batch_size(self, client: SAPETDClient) -> None:
        with patch.object(client, "get", return_value=[]) as mock_get:
            client.get_alerts(from_timestamp=FROM_TIMESTAMP)
        assert mock_get.call_args.kwargs["params"]["$batchSize"] == str(Config.MAX_PAGE_SIZE)

    def test_cloud_get_alerts_sets_and_clears_raw_query(self, cloud_client: SAPETDClient) -> None:
        """The raw query is set on the auth handler only for the duration of the request."""
        handler = cloud_client._cloud_auth
        assert handler is not None
        seen_queries: list[str] = []

        def fake_get(**kwargs: Any) -> dict:
            seen_queries.append(handler.raw_query)
            return SAMPLE_CLOUD_RESPONSE

        with patch.object(cloud_client, "get", side_effect=fake_get) as mock_get:
            result = cloud_client.get_alerts(from_timestamp=FROM_TIMESTAMP, batch_size=10)
        assert result == SAMPLE_CLOUD_ALERTS
        assert mock_get.call_args.kwargs["url_suffix"] == CloudAlertsApi.ENDPOINT
        assert mock_get.call_args.kwargs["params"] == {}
        assert seen_queries[0].startswith("$filter=CreationTimestamp%20ge%20")
        assert handler.raw_query == ""

    def test_cloud_raw_query_cleared_on_error(self, cloud_client: SAPETDClient) -> None:
        with patch.object(cloud_client, "get", side_effect=DemistoException("boom")), pytest.raises(DemistoException):
            cloud_client.get_alerts(from_timestamp=FROM_TIMESTAMP)
        assert cloud_client._cloud_auth is not None
        assert cloud_client._cloud_auth.raw_query == ""

    @pytest.mark.parametrize(
        "client_fixture, response, match",
        [
            pytest.param("client", {"error": "x"}, "JSON array", id="on_prem_dict"),
            pytest.param("cloud_client", [], "'value' list", id="cloud_bare_list"),
        ],
    )
    def test_get_alerts_invalid_response_raises(
        self, request: pytest.FixtureRequest, client_fixture: str, response: Any, match: str
    ) -> None:
        sap_client = request.getfixturevalue(client_fixture)
        with patch.object(sap_client, "get", return_value=response), pytest.raises(DemistoException, match=match):
            sap_client.get_alerts(from_timestamp=FROM_TIMESTAMP)

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

    def test_cloud_uses_cloud_time_field(self, cloud_client: SAPETDClient, sample_cloud_alerts: list[dict]) -> None:
        with patch.object(cloud_client, "get_alerts", return_value=list(reversed(sample_cloud_alerts))):
            result = fetch_alerts_with_pagination(cloud_client, FROM_TIMESTAMP, max_alerts=10)
        assert [alert[Config.ALERT_ID_FIELD] for alert in result] == [7101, 7102]

    @pytest.mark.parametrize(
        "pages, max_alerts, expected_count, expected_batch_sizes",
        [
            pytest.param([[]], 10, 0, [10], id="empty"),
            pytest.param([make_page(1, 3)], 10, 3, [10], id="single_partial_page"),
            pytest.param([make_page(1, 1000), make_page(1001, 500)], 1500, 1500, [1000, 500], id="two_full_pages"),
            pytest.param([make_page(1, 1000), []], 2000, 1000, [1000, 1000], id="stops_on_empty_page"),
            pytest.param([make_page(1, 800)], 2000, 800, [1000], id="stops_on_partial_page"),
        ],
    )
    def test_pagination(
        self, client: SAPETDClient, pages: list, max_alerts: int, expected_count: int, expected_batch_sizes: list[int]
    ) -> None:
        with patch.object(client, "get_alerts", side_effect=pages) as mock_get:
            result = fetch_alerts_with_pagination(client, FROM_TIMESTAMP, max_alerts=max_alerts)
        assert len(result) == expected_count
        assert [call.kwargs["batch_size"] for call in mock_get.call_args_list] == expected_batch_sizes

    def test_cursor_moves_to_last_alert_timestamp(self, client: SAPETDClient) -> None:
        first_page = make_page(1, 1000)
        with patch.object(client, "get_alerts", side_effect=[first_page, make_page(1001, 10)]) as mock_get:
            fetch_alerts_with_pagination(client, FROM_TIMESTAMP, max_alerts=1500)
        assert mock_get.call_args_list[1].kwargs["from_timestamp"] == first_page[-1][ON_PREM_TIME]

    def test_boundary_alerts_not_duplicated(self, client: SAPETDClient) -> None:
        boundary = "2022-04-29T15:00:00.000Z"
        first_page = make_page(1, 998) + [make_alert(9001, boundary), make_alert(9002, boundary)]
        second_page = [make_alert(9001, boundary), make_alert(9002, boundary), make_alert(9003, "2022-04-29T16:00:00.000Z")]
        with patch.object(client, "get_alerts", side_effect=[first_page, second_page]):
            result = fetch_alerts_with_pagination(client, FROM_TIMESTAMP, max_alerts=1500)
        ids = [alert[Config.ALERT_ID_FIELD] for alert in result]
        assert len(ids) == len(set(ids)) == 1001

    def test_stops_when_cursor_does_not_advance(self, client: SAPETDClient) -> None:
        uniform_page = make_page(1, Config.MAX_PAGE_SIZE, timestamp="2022-04-29T14:00:00.000Z")
        with patch.object(client, "get_alerts", return_value=uniform_page) as mock_get:
            result = fetch_alerts_with_pagination(client, FROM_TIMESTAMP, max_alerts=Config.DEFAULT_MAX_FETCH)
        assert len(result) == Config.MAX_PAGE_SIZE
        assert mock_get.call_count == 2

    def test_stops_when_last_alert_has_no_timestamp(self, client: SAPETDClient) -> None:
        page = make_page(1, Config.MAX_PAGE_SIZE)
        page[-1].pop(ON_PREM_TIME)
        with patch.object(client, "get_alerts", return_value=page) as mock_get:
            fetch_alerts_with_pagination(client, FROM_TIMESTAMP, max_alerts=2000)
        assert mock_get.call_count == 1

    def test_truncates_when_server_ignores_batch_size(self, client: SAPETDClient) -> None:
        with patch.object(client, "get_alerts", return_value=make_page(1, 5)):
            assert len(fetch_alerts_with_pagination(client, FROM_TIMESTAMP, max_alerts=2)) == 2


# endregion

# region test-module
# =================================
# test-module
# =================================


class TestTestModule:
    @pytest.mark.parametrize("client_fixture", ["client", "cloud_client"])
    def test_success(self, request: pytest.FixtureRequest, client_fixture: str) -> None:
        sap_client = request.getfixturevalue(client_fixture)
        with patch.object(sap_client, "get_alerts", return_value=[]) as mock_get:
            assert run_test_module(sap_client) == "ok"
        assert mock_get.call_args.kwargs["batch_size"] == Config.TEST_MODULE_MAX_EVENTS

    @pytest.mark.parametrize(
        "client_fixture, api_type, status_code",
        [
            pytest.param("client", OnPremAlertsApi, HTTPStatus.UNAUTHORIZED, id="on_prem_401"),
            pytest.param("client", OnPremAlertsApi, HTTPStatus.FORBIDDEN, id="on_prem_403"),
            pytest.param("client", OnPremAlertsApi, HTTPStatus.NOT_FOUND, id="on_prem_404"),
            pytest.param("cloud_client", CloudAlertsApi, HTTPStatus.UNAUTHORIZED, id="cloud_401"),
            pytest.param("cloud_client", CloudAlertsApi, HTTPStatus.FORBIDDEN, id="cloud_403"),
            pytest.param("cloud_client", CloudAlertsApi, HTTPStatus.NOT_FOUND, id="cloud_404"),
        ],
    )
    def test_http_errors_use_edition_messages(
        self, request: pytest.FixtureRequest, client_fixture: str, api_type: Any, status_code: HTTPStatus
    ) -> None:
        sap_client = request.getfixturevalue(client_fixture)
        with patch.object(sap_client, "get_alerts", side_effect=http_error(int(status_code))):
            assert run_test_module(sap_client) == api_type.HTTP_ERRORS[status_code]

    def test_404_body_with_401_is_not_auth_error(self, client: SAPETDClient) -> None:
        error = http_error(HTTPStatus.NOT_FOUND, "Page not found. lastModification=1791401531072")
        with patch.object(client, "get_alerts", side_effect=error):
            assert run_test_module(client) == OnPremAlertsApi.HTTP_ERRORS[HTTPStatus.NOT_FOUND]

    def test_token_failure(self, cloud_client: SAPETDClient) -> None:
        """A failed OAuth2 token request (no HTTP response attached) gets a clear credentials message."""
        with patch.object(cloud_client, "get_alerts", side_effect=ContentClientAuthenticationError("Token refresh failed")):
            assert run_test_module(cloud_client) == Messages.TOKEN_ERROR

    def test_non_json_response(self, client: SAPETDClient) -> None:
        with patch.object(client, "get_alerts", side_effect=json.JSONDecodeError("Expecting value", "<html>", 0)):
            assert run_test_module(client) == Messages.NON_JSON_RESPONSE

    @pytest.mark.parametrize(
        "error",
        [
            pytest.param(Exception("401 Unauthorized"), id="auth_text_without_status"),
            pytest.param(http_error(HTTPStatus.INTERNAL_SERVER_ERROR), id="500"),
            pytest.param(ConnectionError("timeout"), id="connection_error"),
        ],
    )
    def test_other_errors_are_raised(self, client: SAPETDClient, error: Exception) -> None:
        with patch.object(client, "get_alerts", side_effect=error), pytest.raises(type(error)):
            run_test_module(client)

    def test_error_body_not_logged(self, client: SAPETDClient) -> None:
        error = http_error(HTTPStatus.UNAUTHORIZED, "secret-response-body")
        with patch.object(client, "get_alerts", side_effect=error), patch.object(demisto, "debug") as mock_debug:
            run_test_module(client)
        assert "secret-response-body" not in str(mock_debug.call_args_list)


# endregion

# region get-events
# =================================
# get-events
# =================================


class TestGetEventsCommand:
    @pytest.mark.parametrize(
        "client_fixture, alerts, api_type",
        [
            pytest.param("client", SAMPLE_ALERTS, OnPremAlertsApi, id="on_prem"),
            pytest.param("cloud_client", SAMPLE_CLOUD_ALERTS, CloudAlertsApi, id="cloud"),
        ],
    )
    def test_returns_command_results(
        self, request: pytest.FixtureRequest, client_fixture: str, alerts: list[dict], api_type: Any
    ) -> None:
        sap_client = request.getfixturevalue(client_fixture)
        with patch.object(sap_client, "get_alerts", return_value=copy.deepcopy(alerts)):
            result = get_events_command(sap_client, {"limit": "50"})
        assert isinstance(result, CommandResults)
        assert result.outputs_prefix == Config.OUTPUTS_PREFIX
        assert result.outputs_key_field == Config.ALERT_ID_FIELD
        assert len(result.outputs) == len(alerts)  # type: ignore[arg-type]
        for header in api_type.TABLE_HEADERS:
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

    @pytest.mark.parametrize(
        "client_fixture, alerts",
        [
            pytest.param("client", SAMPLE_ALERTS, id="on_prem"),
            pytest.param("cloud_client", SAMPLE_CLOUD_ALERTS, id="cloud"),
        ],
    )
    def test_push_events(self, request: pytest.FixtureRequest, client_fixture: str, alerts: list[dict]) -> None:
        sap_client = request.getfixturevalue(client_fixture)
        with (
            patch.object(sap_client, "get_alerts", return_value=copy.deepcopy(alerts)),
            patch("SAPETD.send_events_to_xsiam") as mock_send,
        ):
            result = get_events_command(sap_client, {"should_push_events": "true"})
        assert result == Messages.PUSHED_EVENTS.format(count=len(alerts))
        assert all(Config.XSIAM_TIME_FIELD in event for event in mock_send.call_args.kwargs["events"])

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
    @pytest.mark.parametrize(
        "client_fixture, alerts, time_field",
        [
            pytest.param("client", SAMPLE_ALERTS, ON_PREM_TIME, id="on_prem"),
            pytest.param("cloud_client", SAMPLE_CLOUD_ALERTS, CLOUD_TIME, id="cloud"),
        ],
    )
    def test_first_run(self, request: pytest.FixtureRequest, client_fixture: str, alerts: list[dict], time_field: str) -> None:
        sap_client = request.getfixturevalue(client_fixture)
        with (
            patch.object(demisto, "getLastRun", return_value={}),
            patch.object(demisto, "setLastRun") as mock_set,
            patch("SAPETD.parse_date_to_iso", return_value=FROM_TIMESTAMP) as mock_parse,
            patch.object(sap_client, "get_alerts", return_value=copy.deepcopy(alerts)),
            patch("SAPETD.send_events_to_xsiam") as mock_send,
        ):
            fetch_events_command(sap_client, max_fetch=100)
        mock_parse.assert_called_once_with(Config.DEFAULT_FIRST_FETCH)
        assert len(mock_send.call_args.kwargs["events"]) == len(alerts)
        assert mock_set.call_args.args[0][Config.LAST_RUN_TIMESTAMP_KEY] == alerts[-1][time_field]

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
        assert 6101 not in [event[Config.ALERT_ID_FIELD] for event in mock_send.call_args.kwargs["events"]]

    def test_all_duplicates_still_advance_last_run(self, client: SAPETDClient) -> None:
        alert = make_alert(1, "2022-04-29T14:00:00.000Z")
        last_run = {Config.LAST_RUN_TIMESTAMP_KEY: alert[ON_PREM_TIME], Config.LAST_RUN_IDS_KEY: [1]}
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
    @pytest.mark.parametrize("params_fixture", ["mock_params", "cloud_params"])
    def test_routes_commands_with_results(
        self, request: pytest.FixtureRequest, params_fixture: str, command: str, handler: str
    ) -> None:
        with (
            patch.object(demisto, "command", return_value=command),
            patch.object(demisto, "params", return_value=request.getfixturevalue(params_fixture)),
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
            pytest.param(Commands.TEST_MODULE, {"edition": Edition.CLOUD}, Messages.MISSING_TOKEN_URL, id="cloud_no_token_url"),
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
        assert OnPremAlertsApi.ENDPOINT == "/sap/secmon/services/Alerts.xsjs"
        assert CloudAlertsApi.ENDPOINT == "/alerts/v1/Alerts"
        assert Edition.ALL == (Edition.ON_PREM, Edition.CLOUD)
        assert Config.DEFAULT_FIRST_FETCH == "5 minutes ago"
        assert Config.MAX_PAGE_SIZE <= Config.DEFAULT_MAX_FETCH


# endregion
