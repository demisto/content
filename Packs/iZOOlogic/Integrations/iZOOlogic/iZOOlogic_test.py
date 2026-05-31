import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
import demistomock as demisto
from CommonServerPython import *  # noqa
from pytest_mock import MockerFixture

from iZOOlogic import (
    Client,
    COMMAND_MAP,
    IZOOlogicAuthHandler,
    _validate_api_response,
    date_to_unix_timestamp,
    get_current_unix_timestamp,
    snap_to_day_boundary_utc,
    parse_date,
    add_time_to_events,
    create_events,
    filter_by_ids,
    validate_date_range,
    resolve_type_codes,
    parse_integration_params,
    _fetch_all_pages,
    _filter_and_dedup,
    _compute_new_state,
    _fetch_for_type,
    test_module as izoologic_test_module,
    get_events_command,
    fetch_events_command,
    main,
)


# region Test Data Loading
TEST_DATA_DIR = Path(__file__).parent / "test_data"


def load_test_data(filename: str) -> dict:
    """Load test data from a JSON file in the test_data directory."""
    with open(TEST_DATA_DIR / filename) as f:
        return json.load(f)


# endregion

# region Fixtures


@pytest.fixture(autouse=True)
def mock_support_multithreading(mocker: MockerFixture):
    """ContentClient calls support_multithreading() on init — mock it."""
    mocker.patch("ContentClientApiModule.support_multithreading")


@pytest.fixture
def events_result() -> dict:
    """The 'result' object from the API response."""
    return load_test_data("events_response.json")["result"]


@pytest.fixture
def events_result_with_pagination() -> dict:
    """The 'result' object with pagination token."""
    return load_test_data("events_response_with_pagination.json")["result"]


@pytest.fixture
def empty_result() -> dict:
    """The 'result' object with no events."""
    return load_test_data("empty_response.json")["result"]


@pytest.fixture
def mock_client(mocker: MockerFixture) -> Client:
    """Create a mock Client with auth handler's _authenticate mocked."""
    client = Client(
        base_url="https://api.test.izoologic.com",
        api_key="test-api-key",
        secret_key="test-secret-key",
        verify=False,
        proxy=False,
    )
    # Mock the auth handler's _authenticate to avoid real API calls
    mocker.patch.object(client._auth_handler, "_authenticate", new_callable=AsyncMock)
    return client


@pytest.fixture
def valid_params() -> dict:
    return {
        "url": "https://api.izoologic.com/",
        "api_key": {"password": "test-key"},
        "secret_key": {"password": "test-secret"},
        "events_types_filter": ["phishing", "malware"],
        "max_fetch": "5000",
    }


# endregion

# region Auth Handler Tests


class TestIZOOlogicAuthHandler:
    """Tests for the IZOOlogicAuthHandler two-step token auth."""

    def test_initial_state(self):
        """Verify handler initializes with no token, not authenticating, and has a lock."""
        handler = IZOOlogicAuthHandler(api_key="key", secret_key="secret")
        assert handler._token is None
        assert handler._authenticating is False
        assert hasattr(handler, "_auth_lock")

    def test_on_request_authenticates_when_no_token(self):
        """on_request should call _authenticate when no token is set."""
        handler = IZOOlogicAuthHandler(api_key="key", secret_key="secret")
        mock_client = AsyncMock()
        mock_request = AsyncMock()
        mock_request.headers = {}

        handler._authenticate = AsyncMock()
        handler._authenticate.side_effect = lambda client: setattr(handler, "_token", "new-token")

        asyncio.get_event_loop().run_until_complete(handler.on_request(mock_client, mock_request))

        handler._authenticate.assert_called_once_with(mock_client)
        assert mock_request.headers["Authorization"] == "Bearer new-token"

    def test_on_request_skips_auth_when_token_exists(self):
        """on_request should skip _authenticate when token is already set."""
        handler = IZOOlogicAuthHandler(api_key="key", secret_key="secret")
        handler._token = "existing-token"
        mock_client = AsyncMock()
        mock_request = AsyncMock()
        mock_request.headers = {}

        handler._authenticate = AsyncMock()

        asyncio.get_event_loop().run_until_complete(handler.on_request(mock_client, mock_request))

        handler._authenticate.assert_not_called()
        assert mock_request.headers["Authorization"] == "Bearer existing-token"

    def test_on_request_skips_during_authentication(self):
        """on_request should not add auth header when _authenticating is True (prevents recursion)."""
        handler = IZOOlogicAuthHandler(api_key="key", secret_key="secret")
        handler._authenticating = True
        mock_client = AsyncMock()
        mock_request = AsyncMock()
        mock_request.headers = {}

        asyncio.get_event_loop().run_until_complete(handler.on_request(mock_client, mock_request))

        assert "Authorization" not in mock_request.headers

    def test_on_auth_failure_re_authenticates(self):
        """on_auth_failure should clear token, call _authenticate, and return True to retry."""
        handler = IZOOlogicAuthHandler(api_key="key", secret_key="secret")
        handler._token = "expired-token"
        mock_client = AsyncMock()
        mock_response = AsyncMock()

        handler._authenticate = AsyncMock()

        result = asyncio.get_event_loop().run_until_complete(handler.on_auth_failure(mock_client, mock_response))

        handler._authenticate.assert_called_once_with(mock_client)
        assert result is True

    def test_authenticate_skips_when_token_exists(self):
        """_authenticate should skip API call when token is already set (double-check pattern)."""
        handler = IZOOlogicAuthHandler(api_key="key", secret_key="secret")
        handler._token = "existing-token"
        mock_client = AsyncMock()
        mock_client._request = AsyncMock()

        asyncio.get_event_loop().run_until_complete(handler._authenticate(mock_client))

        mock_client._request.assert_not_called()
        assert handler._token == "existing-token"

    def test_authenticate_success(self):
        """_authenticate should store the token on successful API response."""
        handler = IZOOlogicAuthHandler(api_key="key", secret_key="secret")
        mock_client = AsyncMock()

        mock_raw_response = MagicMock()
        mock_raw_response.json.return_value = {
            "success": True,
            "result": {"accessToken": "test-token-123"},
            "message": "",
            "errorCode": "",
        }
        mock_client._request = AsyncMock(return_value=mock_raw_response)

        asyncio.get_event_loop().run_until_complete(handler._authenticate(mock_client))

        assert handler._token == "test-token-123"
        assert handler._authenticating is False

    def test_authenticate_api_error(self):
        """_authenticate should raise DemistoException on API error response."""
        handler = IZOOlogicAuthHandler(api_key="key", secret_key="secret")
        mock_client = AsyncMock()

        mock_raw_response = MagicMock()
        mock_raw_response.json.return_value = {
            "success": False,
            "result": None,
            "message": "Invalid credentials",
            "errorCode": "AUTH_FAILED",
        }
        mock_client._request = AsyncMock(return_value=mock_raw_response)

        with pytest.raises(DemistoException, match="Authentication failed"):
            asyncio.get_event_loop().run_until_complete(handler._authenticate(mock_client))

        assert handler._authenticating is False

    def test_authenticate_no_token_in_response(self):
        """_authenticate should raise DemistoException when no token is returned."""
        handler = IZOOlogicAuthHandler(api_key="key", secret_key="secret")
        mock_client = AsyncMock()

        mock_raw_response = MagicMock()
        mock_raw_response.json.return_value = {
            "success": True,
            "result": {},
            "message": "",
            "errorCode": "",
        }
        mock_client._request = AsyncMock(return_value=mock_raw_response)

        with pytest.raises(DemistoException, match="No token received"):
            asyncio.get_event_loop().run_until_complete(handler._authenticate(mock_client))

        assert handler._authenticating is False

    def test_authenticating_flag_reset_on_exception(self):
        """_authenticating flag should be reset even if _request raises."""
        handler = IZOOlogicAuthHandler(api_key="key", secret_key="secret")
        mock_client = AsyncMock()
        mock_client._request = AsyncMock(side_effect=Exception("Network error"))

        with pytest.raises(Exception, match="Network error"):
            asyncio.get_event_loop().run_until_complete(handler._authenticate(mock_client))

        assert handler._authenticating is False


# endregion

# region Date Helper Tests


class TestDateHelpers:
    @pytest.mark.parametrize(
        "date_input, expected",
        [
            ("2024-01-01T00:00:00Z", "1704067200"),
            ("2023-06-15T12:00:00Z", "1686830400"),
        ],
    )
    def test_date_to_unix_timestamp_iso(self, date_input: str, expected: str):
        assert date_to_unix_timestamp(date_input) == expected

    def test_date_to_unix_timestamp_relative(self):
        result = date_to_unix_timestamp("1 hour ago")
        assert result.isdigit()

    def test_parse_date_valid(self):
        result = parse_date("2024-01-01T00:00:00Z")
        assert result.year == 2024

    def test_parse_date_invalid_raises(self):
        with pytest.raises(ValueError):
            parse_date("not-a-date")

    def test_get_current_unix_timestamp(self):
        result = get_current_unix_timestamp()
        assert result.isdigit()


# endregion

# region Snap to Day Boundary Tests


class TestSnapToDayBoundaryUtc:
    @pytest.mark.parametrize(
        "input_ts, boundary, expected",
        [
            # Start boundary (midnight)
            ("1738063023", "start", "1738022400"),  # 2025-01-28T11:37:03Z -> 00:00:00
            ("1738022400", "start", "1738022400"),  # Already at midnight
            ("1704153599", "start", "1704067200"),  # 2024-01-01T23:59:59Z -> 00:00:00
            ("1704067201", "start", "1704067200"),  # 2024-01-01T00:00:01Z -> 00:00:00
            # End boundary (23:59:59)
            ("1704067200", "end", "1704153599"),  # 2024-01-01T00:00:00Z -> 23:59:59
            ("1704153599", "end", "1704153599"),  # Already at 23:59:59
            ("1704100000", "end", "1704153599"),  # Mid-day -> 23:59:59
        ],
    )
    def test_snap(self, input_ts: str, boundary: str, expected: str):
        assert snap_to_day_boundary_utc(input_ts, boundary) == expected


# endregion

# region Add Time To Events / Create Events Tests


class TestAddTimeToEvents:
    def test_adds_time_and_source_log_type(self):
        events = [{"incidentID": "abc", "incidentType": "Phishing", "createdOn": "100"}]
        add_time_to_events(events)
        assert events[0]["_time"] == "1970-01-01T00:01:40Z"
        assert events[0]["source_log_type"] == "Phishing"

    def test_missing_created_on(self):
        events = [{"incidentID": "1"}]
        add_time_to_events(events)
        assert "_time" not in events[0]
        assert events[0]["source_log_type"] == "Unknown"

    def test_empty_list(self):
        events: list[dict] = []
        add_time_to_events(events)
        assert events == []

    def test_multiple_events(self):
        events = [
            {"incidentID": "1", "incidentType": "Phishing", "createdOn": "100"},
            {"incidentID": "2", "incidentType": "Malware", "createdOn": "200"},
        ]
        add_time_to_events(events)
        assert events[0]["_time"] == "1970-01-01T00:01:40Z"
        assert events[0]["source_log_type"] == "Phishing"
        assert events[1]["_time"] == "1970-01-01T00:03:20Z"
        assert events[1]["source_log_type"] == "Malware"


class TestCreateEvents:
    def test_create_events_calls_send_events_to_xsiam(self, mocker: MockerFixture):
        mock_send = mocker.patch("iZOOlogic.send_events_to_xsiam")
        events = [{"incidentID": "abc", "incidentType": "Phishing", "createdOn": "100"}]
        create_events(events)
        mock_send.assert_called_once()
        sent_events = mock_send.call_args[1]["events"]
        assert len(sent_events) == 1
        assert sent_events[0]["_time"] == "1970-01-01T00:01:40Z"
        assert sent_events[0]["source_log_type"] == "Phishing"


# endregion

# region Filter By IDs Tests


class TestFilterByIds:
    @pytest.mark.parametrize(
        "raw, ids_to_skip, expected_count",
        [
            ([{"incidentID": "1"}, {"incidentID": "2"}], ["3"], 2),  # No match
            ([{"incidentID": "1"}, {"incidentID": "2"}], ["1"], 1),  # One match
            ([{"incidentID": "1"}, {"incidentID": "2"}], ["1", "2"], 0),  # All match
            ([{"incidentID": "1"}], [], 1),  # Empty skip list
            ([], ["1"], 0),  # Empty incidents
        ],
    )
    def test_filter(self, raw: list, ids_to_skip: list, expected_count: int):
        assert len(filter_by_ids(raw, ids_to_skip)) == expected_count


# endregion

# region Validate API Response Tests


class TestValidateApiResponse:
    def test_success_response(self):
        """Successful response returns the 'result' object."""
        response = load_test_data("events_response.json")
        result = _validate_api_response(response)
        assert "incidents" in result
        assert len(result["incidents"]) == 3

    def test_no_data_found_returns_empty(self):
        """Known 'no data found' error code returns empty dict (not an error)."""
        response = {"success": False, "errorCode": "iZOO2011", "message": "No data found"}
        result = _validate_api_response(response)
        assert result == {}

    def test_real_api_error_raises(self):
        """Unknown API error raises DemistoException."""
        response = {"success": False, "errorCode": "iZOO5000", "message": "Server error"}
        with pytest.raises(DemistoException, match="API error: Server error"):
            _validate_api_response(response)

    def test_missing_success_key_treated_as_success(self):
        """Response without 'success' key defaults to True."""
        response = {"result": {"incidents": []}}
        result = _validate_api_response(response)
        assert result == {"incidents": []}


# endregion

# region Validate Date Range Tests


class TestValidateDateRange:
    @pytest.mark.parametrize(
        "days_offset, should_raise, match",
        [
            (1, False, None),  # 1 day — valid
            (31, False, None),  # 31 days — valid (boundary)
            (32, True, "Date range exceeds"),  # 32 days — exceeds max
        ],
    )
    def test_max_range(self, days_offset: int, should_raise: bool, match: str | None):
        from_ts = "1700000000"
        to_ts = str(int(from_ts) + days_offset * 86400)
        if should_raise:
            with pytest.raises(DemistoException, match=match):
                validate_date_range(from_ts, to_ts)
        else:
            validate_date_range(from_ts, to_ts)

    def test_inverted_date_range_raises(self):
        """to_date on an earlier day than from_date should raise."""
        from_ts = "1700100000"  # 2023-11-16
        to_ts = "1700000000"  # 2023-11-15
        with pytest.raises(DemistoException, match="is before"):
            validate_date_range(from_ts, to_ts)

    def test_same_day_does_not_raise(self):
        """Same-day range (to_date == from_date after midnight snap) should not raise."""
        from_ts = "1700092800"  # 2023-11-16T00:00:00Z
        to_ts = "1700100000"  # 2023-11-16T02:00:00Z
        validate_date_range(from_ts, to_ts)  # Should not raise


# endregion

# region Resolve Type Codes Tests


class TestResolveTypeCodes:
    @pytest.mark.parametrize(
        "type_names, expected_codes",
        [
            (["phishing"], [2]),
            (["phishing", "malware"], [2, 3]),
            (["PHISHING"], [2]),  # Case-insensitive
            ([" phishing "], [2]),  # Whitespace trimmed
            (["brand abuse", "email"], [1, 23]),
        ],
    )
    def test_valid_types(self, type_names: list[str], expected_codes: list[int]):
        assert resolve_type_codes(type_names) == expected_codes

    @pytest.mark.parametrize(
        "type_names",
        [
            (["invalid_type"]),
            (["phishing", "nonexistent"]),
        ],
    )
    def test_invalid_type_raises(self, type_names: list[str]):
        with pytest.raises(DemistoException, match="Invalid event type"):
            resolve_type_codes(type_names)


# endregion

# region Parse Integration Params Tests


class TestParseIntegrationParams:
    def test_valid_params(self, valid_params: dict):
        config = parse_integration_params(valid_params)
        assert config["base_url"] == "https://api.izoologic.com"
        assert config["event_type_codes"] == [2, 3]
        assert config["max_fetch"] == 5000

    @pytest.mark.parametrize(
        "override, error_match",
        [
            ({"url": ""}, "Server URL is required"),
            ({"api_key": {"password": ""}}, "API Key is required"),
            ({"secret_key": {"password": ""}}, "Secret Key is required"),
            ({"max_fetch": "-1"}, "Invalid max_fetch value"),
        ],
    )
    def test_invalid_params(self, valid_params: dict, override: dict, error_match: str):
        with pytest.raises(DemistoException, match=error_match):
            parse_integration_params({**valid_params, **override})

    def test_no_filter_defaults_to_all(self, valid_params: dict):
        del valid_params["events_types_filter"]
        config = parse_integration_params(valid_params)
        assert len(config["event_type_codes"]) == 10

    def test_trailing_slash_stripped(self, valid_params: dict):
        valid_params["url"] = "https://api.izoologic.com///"
        config = parse_integration_params(valid_params)
        assert config["base_url"] == "https://api.izoologic.com"

    def test_verify_and_proxy_defaults(self, valid_params: dict):
        config = parse_integration_params(valid_params)
        assert config["verify"] is True  # insecure not set -> verify=True
        assert config["proxy"] is False

    def test_insecure_flag(self, valid_params: dict):
        valid_params["insecure"] = True
        config = parse_integration_params(valid_params)
        assert config["verify"] is False


# endregion

# region Client Tests


class TestClient:
    def test_fetch_events_page_full_body(self, mocker: MockerFixture, mock_client: Client):
        """Test that fetch_events_page sends correct body with all params."""
        full_resp = load_test_data("events_response.json")
        mock_req = mocker.patch.object(mock_client, "_http_request", return_value=full_resp)
        mock_client.fetch_events_page("1700000000", "1700100000", event_type=2, page_token="tok")
        body = mock_req.call_args.kwargs["json_data"]
        assert body == {"fromdate": "1700000000", "todate": "1700100000", "incidenttype": 2, "token": "tok"}

    def test_fetch_events_page_minimal_body(self, mocker: MockerFixture, mock_client: Client):
        """Without events_type and page_token, body only has dates."""
        full_resp = load_test_data("events_response.json")
        mock_req = mocker.patch.object(mock_client, "_http_request", return_value=full_resp)
        mock_client.fetch_events_page("1700000000", "1700100000")
        body = mock_req.call_args.kwargs["json_data"]
        assert body == {"fromdate": "1700000000", "todate": "1700100000"}

    def test_fetch_events_page_returns_result(self, mocker: MockerFixture, mock_client: Client):
        mocker.patch.object(mock_client, "_http_request", return_value=load_test_data("events_response.json"))
        result = mock_client.fetch_events_page("1700000000", "1700100000")
        assert "incidents" in result
        assert "success" not in result  # _validate_api_response strips the wrapper


# endregion

# region Test Module Tests


class TestTestModule:
    def test_success(self, mocker: MockerFixture, mock_client: Client, events_result: dict):
        mocker.patch.object(mock_client, "fetch_events_page", return_value=events_result)
        assert izoologic_test_module(mock_client) == "ok"

    def test_success_empty_response(self, mocker: MockerFixture, mock_client: Client, empty_result: dict):
        """Empty result still proves connectivity — test passes."""
        mocker.patch.object(mock_client, "fetch_events_page", return_value=empty_result)
        assert izoologic_test_module(mock_client) == "ok"

    @pytest.mark.parametrize("error_msg", ["401 Unauthorized", "403 Forbidden", "unauthorized"])
    def test_auth_failure(self, mocker: MockerFixture, mock_client: Client, error_msg: str):
        mocker.patch.object(mock_client, "fetch_events_page", side_effect=DemistoException(error_msg))
        assert "Authorization Error" in izoologic_test_module(mock_client)

    def test_other_error_raises(self, mocker: MockerFixture, mock_client: Client):
        mocker.patch.object(mock_client, "fetch_events_page", side_effect=DemistoException("timeout"))
        with pytest.raises(DemistoException, match="timeout"):
            izoologic_test_module(mock_client)


# endregion

# region Fetch All Pages Tests


class TestFetchAllPages:
    def test_single_page(self, mocker: MockerFixture, mock_client: Client, events_result: dict):
        mocker.patch.object(mock_client, "fetch_events_page", return_value=events_result)
        results = _fetch_all_pages(mock_client, "1700000000", "1700100000", event_type=2)
        assert len(results) == 3

    def test_multi_page(
        self,
        mocker: MockerFixture,
        mock_client: Client,
        events_result_with_pagination: dict,
        events_result: dict,
    ):
        """Exhausts all pages until nextPage is null."""
        mocker.patch.object(
            mock_client,
            "fetch_events_page",
            side_effect=[events_result_with_pagination, events_result],
        )
        results = _fetch_all_pages(mock_client, "1700000000", "1700100000", event_type=2)
        # Page 1: 2 events (with pagination), Page 2: 3 events (no pagination)
        assert len(results) == 5

    def test_empty_response(self, mocker: MockerFixture, mock_client: Client, empty_result: dict):
        mocker.patch.object(mock_client, "fetch_events_page", return_value=empty_result)
        results = _fetch_all_pages(mock_client, "1700000000", "1700100000", event_type=2)
        assert results == []

    def test_no_event_type(self, mocker: MockerFixture, mock_client: Client, events_result: dict):
        """Works without event_type filter."""
        mocker.patch.object(mock_client, "fetch_events_page", return_value=events_result)
        results = _fetch_all_pages(mock_client, "1700000000", "1700100000")
        assert len(results) == 3


# endregion

# region Filter and Dedup Tests


class TestFilterAndDedup:
    @pytest.mark.parametrize(
        "last_created_on, last_ids, expected_ids",
        [
            # First run — no filtering
            (None, [], ["a", "b", "c"]),
            # Time filter only — discard before threshold
            ("200", [], ["b", "c"]),
            # Time filter + dedup — discard before threshold and matching IDs
            ("200", ["b"], ["c"]),
            # All deduped out
            ("200", ["b", "c"], []),
            # Dedup at boundary with no time filter effect
            ("100", ["a"], ["b", "c"]),
        ],
    )
    def test_filter_and_dedup(
        self,
        last_created_on: str | None,
        last_ids: list[str],
        expected_ids: list[str],
    ):
        raw = [
            {"incidentID": "a", "createdOn": "100"},
            {"incidentID": "b", "createdOn": "200"},
            {"incidentID": "c", "createdOn": "300"},
        ]
        result = _filter_and_dedup(raw, last_created_on, last_ids, type_key="1")
        assert [inc["incidentID"] for inc in result] == expected_ids


# endregion

# region Compute New State Tests


class TestComputeNewState:
    @pytest.mark.parametrize(
        "consumed, expected_created_on, expected_ids",
        [
            # Single event at max
            (
                [{"incidentID": "a", "createdOn": "100"}, {"incidentID": "b", "createdOn": "200"}],
                "200",
                ["b"],
            ),
            # Multiple events at max timestamp
            (
                [
                    {"incidentID": "a", "createdOn": "100"},
                    {"incidentID": "b", "createdOn": "200"},
                    {"incidentID": "c", "createdOn": "200"},
                ],
                "200",
                ["b", "c"],
            ),
            # Single event
            (
                [{"incidentID": "x", "createdOn": "500"}],
                "500",
                ["x"],
            ),
        ],
    )
    def test_compute_new_state(
        self,
        consumed: list[dict],
        expected_created_on: str,
        expected_ids: list[str],
    ):
        state = _compute_new_state(consumed, type_key="1")
        assert state["last_created_on"] == expected_created_on
        assert set(state["last_ids"]) == set(expected_ids)


# endregion

# region Fetch For Type Tests


class TestFetchForType:
    def test_first_fetch(self, mocker: MockerFixture, mock_client: Client, events_result: dict):
        """First fetch with empty state — all events consumed, sorted ascending."""
        mocker.patch.object(mock_client, "fetch_events_page", return_value=events_result)

        type_key, cortex_events, state = _fetch_for_type(mock_client, 2, {}, 10000)

        assert type_key == "2"
        assert len(cortex_events) == 3
        # State should have last_created_on = max createdOn (ascending sort, last consumed)
        assert state["last_created_on"] == "1700000200"
        # Only the event at max createdOn should be in last_ids
        assert state["last_ids"] == ["abc123"]

    def test_ascending_sort(self, mocker: MockerFixture, mock_client: Client, events_result: dict):
        """Verify events are returned sorted ascending by createdOn."""
        mocker.patch.object(mock_client, "fetch_events_page", return_value=events_result)

        _, consumed_events, _ = _fetch_for_type(mock_client, 2, {}, 10000)

        created_ons = [e["createdOn"] for e in consumed_events]
        assert created_ons == ["1700000000", "1700000100", "1700000200"]

    def test_slice_to_max_fetch(self, mocker: MockerFixture, mock_client: Client, events_result: dict):
        """When max_fetch < total events, slice to max_fetch (oldest first)."""
        mocker.patch.object(mock_client, "fetch_events_page", return_value=events_result)

        _, consumed_events, state = _fetch_for_type(mock_client, 2, {}, 2)

        assert len(consumed_events) == 2
        # Should consume the 2 oldest (ascending sort)
        ids = [e["incidentID"] for e in consumed_events]
        assert ids == ["ghi789", "def456"]
        # last_created_on = createdOn of the last consumed (def456 = 1700000100)
        assert state["last_created_on"] == "1700000100"
        assert state["last_ids"] == ["def456"]

    def test_time_filter(self, mocker: MockerFixture, mock_client: Client, events_result: dict):
        """Events with createdOn < last_created_on are discarded."""
        mocker.patch.object(mock_client, "fetch_events_page", return_value=events_result)
        mocker.patch("iZOOlogic.get_current_unix_timestamp", return_value="1700100000")

        type_state = {"last_created_on": "1700000100", "last_ids": []}
        _, consumed_events, state = _fetch_for_type(mock_client, 2, type_state, 10000)

        # ghi789 (createdOn=1700000000) should be filtered out
        ids = [e["incidentID"] for e in consumed_events]
        assert "ghi789" not in ids
        assert len(consumed_events) == 2

    def test_dedup_at_boundary(self, mocker: MockerFixture, mock_client: Client, events_result: dict):
        """Events with createdOn == last_created_on and matching IDs are removed."""
        mocker.patch.object(mock_client, "fetch_events_page", return_value=events_result)
        mocker.patch("iZOOlogic.get_current_unix_timestamp", return_value="1700100000")

        type_state = {"last_created_on": "1700000100", "last_ids": ["def456"]}
        _, consumed_events, _ = _fetch_for_type(mock_client, 2, type_state, 10000)

        ids = [e["incidentID"] for e in consumed_events]
        assert "def456" not in ids
        assert "ghi789" not in ids  # Filtered by time
        assert ids == ["abc123"]

    def test_empty_response_advances_cursor(self, mocker: MockerFixture, mock_client: Client, empty_result: dict):
        """When no events are returned, cursor advances to to_date."""
        mocker.patch.object(mock_client, "fetch_events_page", return_value=empty_result)
        mocker.patch("iZOOlogic.get_current_unix_timestamp", return_value="1700100000")
        # Mock date_to_unix_timestamp so DEFAULT_FROM_TIME doesn't resolve to "now"
        mocker.patch("iZOOlogic.date_to_unix_timestamp", return_value="1700000000")

        type_key, cortex_events, state = _fetch_for_type(mock_client, 2, {}, 10000)

        assert cortex_events == []
        assert state["last_created_on"] == "1700100000"
        assert state["last_ids"] == []

    def test_all_filtered_out_advances_cursor(self, mocker: MockerFixture, mock_client: Client, events_result: dict):
        """When all events are filtered/deduped out, cursor advances to to_date."""
        mocker.patch.object(mock_client, "fetch_events_page", return_value=events_result)
        mocker.patch("iZOOlogic.get_current_unix_timestamp", return_value="1700100000")

        type_state = {"last_created_on": "1700000200", "last_ids": ["abc123"]}
        _, cortex_events, state = _fetch_for_type(mock_client, 2, type_state, 10000)

        assert cortex_events == []
        assert state["last_created_on"] == "1700100000"
        assert state["last_ids"] == []

    def test_state_update_with_multiple_same_timestamp(self, mocker: MockerFixture, mock_client: Client):
        """When multiple events share the max createdOn, all their IDs are in last_ids."""
        mocker.patch("iZOOlogic.get_current_unix_timestamp", return_value="1000")
        # Mock date_to_unix_timestamp so DEFAULT_FROM_TIME doesn't resolve to "now"
        mocker.patch("iZOOlogic.date_to_unix_timestamp", return_value="100")
        result = {
            "incidents": [
                {"incidentID": "a", "createdOn": "200", "incidentType": "Phishing"},
                {"incidentID": "b", "createdOn": "200", "incidentType": "Phishing"},
                {"incidentID": "c", "createdOn": "100", "incidentType": "Phishing"},
            ],
            "nextPage": None,
        }
        mocker.patch.object(mock_client, "fetch_events_page", return_value=result)

        _, _, state = _fetch_for_type(mock_client, 2, {}, 10000)

        assert state["last_created_on"] == "200"
        assert set(state["last_ids"]) == {"a", "b"}

    def test_large_date_range_raises(self, mocker: MockerFixture, mock_client: Client, empty_result: dict):
        """When date range exceeds 31 days, validate_date_range raises."""
        mocker.patch("iZOOlogic.get_current_unix_timestamp", return_value="1703000000")
        mocker.patch.object(mock_client, "fetch_events_page", return_value=empty_result)

        # last_created_on is >31 days before to_date → should raise
        type_state = {"last_created_on": "1700000000", "last_ids": ["old"]}
        with pytest.raises(DemistoException, match="exceeds the maximum"):
            _fetch_for_type(mock_client, 2, type_state, 10000)


# endregion

# region Get Events Command Tests


class TestGetEventsCommand:
    def test_basic(self, mocker: MockerFixture, mock_client: Client, events_result: dict):
        mocker.patch.object(mock_client, "fetch_events_page", return_value=events_result)
        result = get_events_command(mock_client, {"limit": "10"}, [2])
        assert isinstance(result, CommandResults)
        assert result.outputs_prefix == "iZOOlogic.Incident"

    def test_slices_to_limit(self, mocker: MockerFixture, mock_client: Client, events_result: dict):
        """Test that get-events slices results to the limit per type."""
        mocker.patch.object(mock_client, "fetch_events_page", return_value=events_result)
        result = get_events_command(mock_client, {"limit": "2"}, [2])
        assert len(result.outputs) <= 2  # type: ignore[arg-type]

    def test_invalid_limit(self, mocker: MockerFixture, mock_client: Client):
        with pytest.raises(DemistoException, match="Invalid limit value"):
            get_events_command(mock_client, {"limit": "-5"}, [2])

    def test_inverted_date_range_raises(self, mocker: MockerFixture, mock_client: Client):
        """end_time before start_time (different days) should raise."""
        with pytest.raises(DemistoException, match="is before"):
            get_events_command(
                mock_client,
                {
                    "limit": "10",
                    "start_time": "2024-01-15T00:00:00Z",
                    "end_time": "2024-01-10T00:00:00Z",
                },
                [2],
            )

    def test_date_range_exceeds_31_days_raises(self, mocker: MockerFixture, mock_client: Client):
        """get_events_command should reject date ranges exceeding 31 days."""
        with pytest.raises(DemistoException, match="exceeds the maximum"):
            get_events_command(
                mock_client,
                {
                    "limit": "10",
                    "start_time": "2024-01-01T00:00:00Z",
                    "end_time": "2024-03-01T00:00:00Z",
                },
                [2],
            )

    def test_event_type_arg_overrides_default(self, mocker: MockerFixture, mock_client: Client, events_result: dict):
        """When event_type is provided in args, it overrides default_type_codes."""
        mock_fetch = mocker.patch.object(mock_client, "fetch_events_page", return_value=events_result)
        get_events_command(mock_client, {"limit": "10", "event_type": "malware"}, [2])
        # Should call with type_code=3 (malware), not 2 (phishing)
        call_body = mock_fetch.call_args.kwargs
        assert call_body.get("event_type") == 3

    def test_multiple_types(self, mocker: MockerFixture, mock_client: Client, events_result: dict):
        """Fetches events for each type code — API called once per type."""
        mock_fetch = mocker.patch.object(mock_client, "fetch_events_page", return_value=events_result)
        result = get_events_command(mock_client, {"limit": "10"}, [2, 3])
        # Verify fetch_events_page was called for each type
        called_types = [call.kwargs["event_type"] for call in mock_fetch.call_args_list]
        assert 2 in called_types
        assert 3 in called_types
        assert isinstance(result.outputs, list)

    def test_outputs_key_field(self, mocker: MockerFixture, mock_client: Client, events_result: dict):
        """Verify outputs_key_field is set correctly."""
        mocker.patch.object(mock_client, "fetch_events_page", return_value=events_result)
        result = get_events_command(mock_client, {"limit": "10"}, [2])
        assert result.outputs_key_field == "incidentID"


# endregion

# region Fetch Events Command Tests (async)


class TestFetchEventsCommand:
    def test_first_fetch(self, mocker: MockerFixture, mock_client: Client, events_result: dict):
        mocker.patch.object(mock_client, "fetch_events_page", return_value=events_result)
        mocker.patch.object(demisto, "getLastRun", return_value={})
        mock_send = mocker.patch("iZOOlogic.send_events_to_xsiam")
        mock_set = mocker.patch.object(demisto, "setLastRun")

        asyncio.run(fetch_events_command(mock_client, 10000, [2]))

        mock_send.assert_called_once()
        sent_events = mock_send.call_args[1]["events"]
        assert len(sent_events) == 3
        last_run = mock_set.call_args[0][0]
        assert "2" in last_run
        assert last_run["2"]["last_created_on"] == "1700000200"
        assert last_run["2"]["last_ids"] == ["abc123"]

    def test_multiple_types_concurrent(
        self,
        mocker: MockerFixture,
        mock_client: Client,
        events_result: dict,
        empty_result: dict,
    ):
        """Test that multiple types are fetched (concurrently via asyncio.to_thread)."""
        mocker.patch.object(mock_client, "fetch_events_page", side_effect=[events_result, empty_result])
        mocker.patch.object(demisto, "getLastRun", return_value={})
        mock_send = mocker.patch("iZOOlogic.send_events_to_xsiam")
        mock_set = mocker.patch.object(demisto, "setLastRun")

        asyncio.run(fetch_events_command(mock_client, 10000, [2, 3]))

        mock_send.assert_called_once()
        sent_events = mock_send.call_args[1]["events"]
        assert len(sent_events) == 3
        last_run = mock_set.call_args[0][0]
        assert "2" in last_run
        assert "3" in last_run

    def test_empty_response(self, mocker: MockerFixture, mock_client: Client, empty_result: dict):
        mocker.patch.object(mock_client, "fetch_events_page", return_value=empty_result)
        mocker.patch.object(demisto, "getLastRun", return_value={})
        mock_send = mocker.patch("iZOOlogic.send_events_to_xsiam")
        mocker.patch.object(demisto, "setLastRun")

        asyncio.run(fetch_events_command(mock_client, 10000, [2]))
        mock_send.assert_not_called()

    def test_exception_in_one_type_does_not_block_others(
        self,
        mocker: MockerFixture,
        mock_client: Client,
        events_result: dict,
    ):
        """If one type raises an exception, other types still succeed."""

        def side_effect(client, type_code, type_state, max_fetch):
            if type_code == 3:
                raise DemistoException("API error for type 3")
            return _fetch_for_type(client, type_code, type_state, max_fetch)

        mocker.patch.object(mock_client, "fetch_events_page", return_value=events_result)
        mocker.patch.object(demisto, "getLastRun", return_value={})
        mocker.patch("iZOOlogic._fetch_for_type", side_effect=side_effect)
        mocker.patch("iZOOlogic.send_events_to_xsiam")
        mock_set = mocker.patch.object(demisto, "setLastRun")
        mocker.patch.object(demisto, "error")

        asyncio.run(fetch_events_command(mock_client, 10000, [2, 3]))

        # Type 2 should still succeed, type 3 error is logged
        last_run = mock_set.call_args[0][0]
        assert "2" in last_run

    def test_preserves_existing_last_run_keys(self, mocker: MockerFixture, mock_client: Client, events_result: dict):
        """Existing last_run keys for other types are preserved."""
        existing_last_run = {"5": {"last_created_on": "999", "last_ids": ["old"]}}
        mocker.patch.object(mock_client, "fetch_events_page", return_value=events_result)
        mocker.patch.object(demisto, "getLastRun", return_value=existing_last_run)
        mocker.patch("iZOOlogic.send_events_to_xsiam")
        mock_set = mocker.patch.object(demisto, "setLastRun")

        asyncio.run(fetch_events_command(mock_client, 10000, [2]))

        last_run = mock_set.call_args[0][0]
        assert "5" in last_run  # Preserved
        assert "2" in last_run  # New


# endregion

# region Main Tests


class TestMain:
    @pytest.mark.parametrize("command", ["test-module", "fetch-events", "izoologic-get-events"])
    def test_main_dispatches(self, mocker: MockerFixture, command: str):
        mocker.patch("ContentClientApiModule.support_multithreading")
        mocker.patch.object(demisto, "command", return_value=command)
        mocker.patch.object(
            demisto,
            "params",
            return_value={
                "url": "https://api.izoologic.com",
                "api_key": {"password": "k"},
                "secret_key": {"password": "s"},
                "max_fetch": "1000",
                "event_types_filter": ["phishing"],
            },
        )
        mocker.patch.object(demisto, "args", return_value={"limit": "10"})
        mock_func = mocker.MagicMock(return_value="ok")
        COMMAND_MAP[command] = mock_func
        mocker.patch("iZOOlogic.return_results")
        if command == "fetch-events":
            # fetch_events_command is async, mock asyncio.run
            mocker.patch("iZOOlogic.asyncio.run")
        main()
        if command != "fetch-events":
            mock_func.assert_called_once()

    def test_main_unknown_command(self, mocker: MockerFixture):
        mocker.patch("ContentClientApiModule.support_multithreading")
        mocker.patch.object(demisto, "command", return_value="unknown")
        mocker.patch.object(
            demisto,
            "params",
            return_value={
                "url": "https://x.com",
                "api_key": {"password": "k"},
                "secret_key": {"password": "s"},
            },
        )
        mocker.patch.object(demisto, "args", return_value={})
        mocker.patch.object(demisto, "error")
        mock_err = mocker.patch("iZOOlogic.return_error")
        main()
        mock_err.assert_called_once()

    def test_main_error_handling(self, mocker: MockerFixture):
        """Exceptions in command execution are caught and return_error is called."""
        mocker.patch("ContentClientApiModule.support_multithreading")
        mocker.patch.object(demisto, "command", return_value="test-module")
        mocker.patch.object(
            demisto,
            "params",
            return_value={
                "url": "https://api.izoologic.com",
                "api_key": {"password": "k"},
                "secret_key": {"password": "s"},
            },
        )
        mocker.patch.object(demisto, "args", return_value={})
        mocker.patch.object(demisto, "error")
        # Patch COMMAND_MAP directly since main() reads from it, not from the module-level name
        error_func = mocker.MagicMock(side_effect=DemistoException("Connection refused"))
        COMMAND_MAP["test-module"] = error_func
        mock_err = mocker.patch("iZOOlogic.return_error")
        main()
        mock_err.assert_called_once()
        assert "Connection refused" in mock_err.call_args[0][0]


# endregion

# endregion
