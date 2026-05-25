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
    ApiCodes,
    COMMAND_MAP,
    IZOOlogicAuthHandler,
    _validate_api_response,
    date_to_unix_timestamp,
    get_current_unix_timestamp,
    snap_to_day_boundary_utc,
    parse_date,
    create_incidents,
    filter_by_ids,
    validate_date_range,
    resolve_type_codes,
    parse_integration_params,
    _fetch_all_pages,
    _filter_and_dedup,
    _compute_new_state,
    _fetch_for_type,
    _resolve_code_by_name,
    _validate_incident_creation_args,
    _fetch_single_window,
    _generate_windows,
    test_module as izoologic_test_module,
    get_incidents_command,
    fetch_incidents_command,
    create_incident_command,
    incident_fetch_command,
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
def incidents_result() -> dict:
    """The 'result' object from the API response."""
    return load_test_data("incidents_response.json")["result"]


@pytest.fixture
def incidents_result_with_pagination() -> dict:
    """The 'result' object with pagination token."""
    return load_test_data("incidents_response_with_pagination.json")["result"]


@pytest.fixture
def empty_result() -> dict:
    """The 'result' object with no incidents."""
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
        "incident_types_filter": ["phishing", "malware"],
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

# region Create Incidents Tests


class TestCreateIncidents:
    @pytest.mark.parametrize(
        "raw, expected_name, expected_occurred",
        [
            (
                [{"incidentID": "abc", "incidentType": "Phishing", "createdOn": "100"}],
                "iZOOlogic - Phishing - abc",
                "1970-01-01T00:01:40+00:00",
            ),
            (
                [{"incidentID": "1"}],
                "iZOOlogic - Unknown - 1",
                "",
            ),
        ],
    )
    def test_create_incidents(self, raw: list, expected_name: str, expected_occurred: str):
        incidents = create_incidents(raw)
        assert len(incidents) == 1
        assert incidents[0]["name"] == expected_name
        assert incidents[0]["occurred"] == expected_occurred

    def test_empty(self):
        assert create_incidents([]) == []

    def test_rawjson_contains_original_data(self):
        raw = [{"incidentID": "abc", "incidentType": "Phishing", "createdOn": "100", "extra": "data"}]
        incidents = create_incidents(raw)
        parsed = json.loads(incidents[0]["rawJSON"])
        assert parsed["incidentID"] == "abc"
        assert parsed["extra"] == "data"


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
        response = load_test_data("incidents_response.json")
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
        with pytest.raises(DemistoException, match="Invalid incident type"):
            resolve_type_codes(type_names)


# endregion

# region Parse Integration Params Tests


class TestParseIntegrationParams:
    def test_valid_params(self, valid_params: dict):
        config = parse_integration_params(valid_params)
        assert config["base_url"] == "https://api.izoologic.com"
        assert config["incident_type_codes"] == [2, 3]
        assert config["max_fetch"] == 5000
        assert "first_fetch_ts" in config

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
        del valid_params["incident_types_filter"]
        config = parse_integration_params(valid_params)
        assert len(config["incident_type_codes"]) == 11

    def test_first_fetch_default(self, valid_params: dict):
        """first_fetch_ts should be set from default when not provided."""
        config = parse_integration_params(valid_params)
        assert config["first_fetch_ts"]  # Should be a non-empty Unix timestamp string

    def test_first_fetch_custom(self, valid_params: dict):
        """first_fetch_ts should be set from the provided first_fetch param."""
        valid_params["first_fetch"] = "3 days"
        config = parse_integration_params(valid_params)
        assert config["first_fetch_ts"]  # Should be a non-empty Unix timestamp string

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
    def test_fetch_incidents_page_full_body(self, mocker: MockerFixture, mock_client: Client):
        """Test that fetch_incidents_page sends correct body with all params."""
        full_resp = load_test_data("incidents_response.json")
        mock_req = mocker.patch.object(mock_client, "_http_request", return_value=full_resp)
        mock_client.fetch_incidents_page("1700000000", "1700100000", incident_type=2, page_token="tok")
        body = mock_req.call_args.kwargs["json_data"]
        assert body == {"fromdate": "1700000000", "todate": "1700100000", "incidenttype": 2, "token": "tok"}

    def test_fetch_incidents_page_minimal_body(self, mocker: MockerFixture, mock_client: Client):
        """Without incident_type and page_token, body only has dates."""
        full_resp = load_test_data("incidents_response.json")
        mock_req = mocker.patch.object(mock_client, "_http_request", return_value=full_resp)
        mock_client.fetch_incidents_page("1700000000", "1700100000")
        body = mock_req.call_args.kwargs["json_data"]
        assert body == {"fromdate": "1700000000", "todate": "1700100000"}

    def test_fetch_incidents_page_returns_result(self, mocker: MockerFixture, mock_client: Client):
        mocker.patch.object(mock_client, "_http_request", return_value=load_test_data("incidents_response.json"))
        result = mock_client.fetch_incidents_page("1700000000", "1700100000")
        assert "incidents" in result
        assert "success" not in result  # _validate_api_response strips the wrapper


# endregion

# region Test Module Tests


class TestTestModule:
    def test_success(self, mocker: MockerFixture, mock_client: Client, incidents_result: dict):
        mocker.patch.object(mock_client, "fetch_incidents_page", return_value=incidents_result)
        assert izoologic_test_module(mock_client) == "ok"

    def test_success_empty_response(self, mocker: MockerFixture, mock_client: Client, empty_result: dict):
        """Empty result still proves connectivity — test passes."""
        mocker.patch.object(mock_client, "fetch_incidents_page", return_value=empty_result)
        assert izoologic_test_module(mock_client) == "ok"

    @pytest.mark.parametrize("error_msg", ["401 Unauthorized", "403 Forbidden", "unauthorized"])
    def test_auth_failure(self, mocker: MockerFixture, mock_client: Client, error_msg: str):
        mocker.patch.object(mock_client, "fetch_incidents_page", side_effect=DemistoException(error_msg))
        assert "Authorization Error" in izoologic_test_module(mock_client)

    def test_other_error_raises(self, mocker: MockerFixture, mock_client: Client):
        mocker.patch.object(mock_client, "fetch_incidents_page", side_effect=DemistoException("timeout"))
        with pytest.raises(DemistoException, match="timeout"):
            izoologic_test_module(mock_client)


# endregion

# region Fetch All Pages Tests


class TestFetchAllPages:
    def test_single_page(self, mocker: MockerFixture, mock_client: Client, incidents_result: dict):
        mocker.patch.object(mock_client, "fetch_incidents_page", return_value=incidents_result)
        results = _fetch_all_pages(mock_client, "1700000000", "1700100000", incident_type=2)
        assert len(results) == 3

    def test_multi_page(
        self,
        mocker: MockerFixture,
        mock_client: Client,
        incidents_result_with_pagination: dict,
        incidents_result: dict,
    ):
        """Exhausts all pages until nextPage is null."""
        mocker.patch.object(
            mock_client,
            "fetch_incidents_page",
            side_effect=[incidents_result_with_pagination, incidents_result],
        )
        results = _fetch_all_pages(mock_client, "1700000000", "1700100000", incident_type=2)
        # Page 1: 2 incidents (with pagination), Page 2: 3 incidents (no pagination)
        assert len(results) == 5

    def test_empty_response(self, mocker: MockerFixture, mock_client: Client, empty_result: dict):
        mocker.patch.object(mock_client, "fetch_incidents_page", return_value=empty_result)
        results = _fetch_all_pages(mock_client, "1700000000", "1700100000", incident_type=2)
        assert results == []

    def test_no_incident_type(self, mocker: MockerFixture, mock_client: Client, incidents_result: dict):
        """Works without incident_type filter."""
        mocker.patch.object(mock_client, "fetch_incidents_page", return_value=incidents_result)
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
            # Single incident at max
            (
                [{"incidentID": "a", "createdOn": "100"}, {"incidentID": "b", "createdOn": "200"}],
                "200",
                ["b"],
            ),
            # Multiple incidents at max timestamp
            (
                [
                    {"incidentID": "a", "createdOn": "100"},
                    {"incidentID": "b", "createdOn": "200"},
                    {"incidentID": "c", "createdOn": "200"},
                ],
                "200",
                ["b", "c"],
            ),
            # Single incident
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
    def test_first_fetch(self, mocker: MockerFixture, mock_client: Client, incidents_result: dict):
        """First fetch with empty state — all incidents consumed, sorted ascending."""
        mocker.patch.object(mock_client, "fetch_incidents_page", return_value=incidents_result)

        type_key, cortex_incidents, state = _fetch_for_type(mock_client, 2, {}, 10000)

        assert type_key == "2"
        assert len(cortex_incidents) == 3
        # State should have last_created_on = max createdOn (ascending sort, last consumed)
        assert state["last_created_on"] == "1700000200"
        # Only the incident at max createdOn should be in last_ids
        assert state["last_ids"] == ["abc123"]

    def test_ascending_sort(self, mocker: MockerFixture, mock_client: Client, incidents_result: dict):
        """Verify incidents are returned sorted ascending by createdOn."""
        mocker.patch.object(mock_client, "fetch_incidents_page", return_value=incidents_result)

        _, cortex_incidents, _ = _fetch_for_type(mock_client, 2, {}, 10000)

        created_ons = [json.loads(i["rawJSON"])["createdOn"] for i in cortex_incidents]
        assert created_ons == ["1700000000", "1700000100", "1700000200"]

    def test_slice_to_max_fetch(self, mocker: MockerFixture, mock_client: Client, incidents_result: dict):
        """When max_fetch < total incidents, slice to max_fetch (oldest first)."""
        mocker.patch.object(mock_client, "fetch_incidents_page", return_value=incidents_result)

        _, cortex_incidents, state = _fetch_for_type(mock_client, 2, {}, 2)

        assert len(cortex_incidents) == 2
        # Should consume the 2 oldest (ascending sort)
        ids = [json.loads(i["rawJSON"])["incidentID"] for i in cortex_incidents]
        assert ids == ["ghi789", "def456"]
        # last_created_on = createdOn of the last consumed (def456 = 1700000100)
        assert state["last_created_on"] == "1700000100"
        assert state["last_ids"] == ["def456"]

    def test_time_filter(self, mocker: MockerFixture, mock_client: Client, incidents_result: dict):
        """Incidents with createdOn < last_created_on are discarded."""
        mocker.patch.object(mock_client, "fetch_incidents_page", return_value=incidents_result)
        mocker.patch("iZOOlogic.get_current_unix_timestamp", return_value="1700100000")

        type_state = {"last_created_on": "1700000100", "last_ids": []}
        _, cortex_incidents, state = _fetch_for_type(mock_client, 2, type_state, 10000)

        # ghi789 (createdOn=1700000000) should be filtered out
        ids = [json.loads(i["rawJSON"])["incidentID"] for i in cortex_incidents]
        assert "ghi789" not in ids
        assert len(cortex_incidents) == 2

    def test_dedup_at_boundary(self, mocker: MockerFixture, mock_client: Client, incidents_result: dict):
        """Incidents with createdOn == last_created_on and matching IDs are removed."""
        mocker.patch.object(mock_client, "fetch_incidents_page", return_value=incidents_result)
        mocker.patch("iZOOlogic.get_current_unix_timestamp", return_value="1700100000")

        type_state = {"last_created_on": "1700000100", "last_ids": ["def456"]}
        _, cortex_incidents, _ = _fetch_for_type(mock_client, 2, type_state, 10000)

        ids = [json.loads(i["rawJSON"])["incidentID"] for i in cortex_incidents]
        assert "def456" not in ids
        assert "ghi789" not in ids  # Filtered by time
        assert ids == ["abc123"]

    def test_empty_response_advances_cursor(self, mocker: MockerFixture, mock_client: Client, empty_result: dict):
        """When no incidents are returned, cursor advances to to_date."""
        mocker.patch.object(mock_client, "fetch_incidents_page", return_value=empty_result)
        mocker.patch("iZOOlogic.get_current_unix_timestamp", return_value="1700100000")
        # Mock date_to_unix_timestamp so DEFAULT_FROM_TIME doesn't resolve to "now"
        mocker.patch("iZOOlogic.date_to_unix_timestamp", return_value="1700000000")

        type_key, cortex_incidents, state = _fetch_for_type(mock_client, 2, {}, 10000)

        assert cortex_incidents == []
        assert state["last_created_on"] == "1700100000"
        assert state["last_ids"] == []

    def test_all_filtered_out_advances_cursor(self, mocker: MockerFixture, mock_client: Client, incidents_result: dict):
        """When all incidents are filtered/deduped out, cursor advances to to_date."""
        mocker.patch.object(mock_client, "fetch_incidents_page", return_value=incidents_result)
        mocker.patch("iZOOlogic.get_current_unix_timestamp", return_value="1700100000")

        type_state = {"last_created_on": "1700000200", "last_ids": ["abc123"]}
        _, cortex_incidents, state = _fetch_for_type(mock_client, 2, type_state, 10000)

        assert cortex_incidents == []
        assert state["last_created_on"] == "1700100000"
        assert state["last_ids"] == []

    def test_state_update_with_multiple_same_timestamp(self, mocker: MockerFixture, mock_client: Client):
        """When multiple incidents share the max createdOn, all their IDs are in last_ids."""
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
        mocker.patch.object(mock_client, "fetch_incidents_page", return_value=result)

        _, _, state = _fetch_for_type(mock_client, 2, {}, 10000)

        assert state["last_created_on"] == "200"
        assert set(state["last_ids"]) == {"a", "b"}

    def test_large_date_range_splits_into_windows(self, mocker: MockerFixture, mock_client: Client, empty_result: dict):
        """When date range exceeds 31 days, it is split into multiple windows."""
        mocker.patch("iZOOlogic.get_current_unix_timestamp", return_value="1703000000")
        mocker.patch.object(mock_client, "fetch_incidents_page", return_value=empty_result)

        # last_created_on is >31 days before to_date → should split into 2 windows
        type_state = {"last_created_on": "1700000000", "last_ids": ["old"]}
        type_key, cortex_incidents, state = _fetch_for_type(mock_client, 2, type_state, 10000)

        assert cortex_incidents == []
        # State should be advanced to to_date (cursor moved forward through empty windows)
        assert state["last_created_on"] == "1703000000"


# endregion

# region Get Incidents Command Tests


class TestGetIncidentsCommand:
    def test_basic(self, mocker: MockerFixture, mock_client: Client, incidents_result: dict):
        mocker.patch.object(mock_client, "fetch_incidents_page", return_value=incidents_result)
        result = get_incidents_command(mock_client, {"limit": "10"}, [2])
        assert isinstance(result, CommandResults)
        assert result.outputs_prefix == "iZOOlogic.Incident"

    def test_slices_to_limit(self, mocker: MockerFixture, mock_client: Client, incidents_result: dict):
        """Test that get-incidents slices results to the limit per type."""
        mocker.patch.object(mock_client, "fetch_incidents_page", return_value=incidents_result)
        result = get_incidents_command(mock_client, {"limit": "2"}, [2])
        assert len(result.outputs) <= 2  # type: ignore[arg-type]

    def test_invalid_limit(self, mocker: MockerFixture, mock_client: Client):
        with pytest.raises(DemistoException, match="Invalid limit value"):
            get_incidents_command(mock_client, {"limit": "-5"}, [2])

    def test_inverted_date_range_raises(self, mocker: MockerFixture, mock_client: Client):
        """end_time before start_time (different days) should raise."""
        with pytest.raises(DemistoException, match="is before"):
            get_incidents_command(
                mock_client,
                {
                    "limit": "10",
                    "start_time": "2024-01-15T00:00:00Z",
                    "end_time": "2024-01-10T00:00:00Z",
                },
                [2],
            )

    def test_date_range_exceeds_31_days_raises(self, mocker: MockerFixture, mock_client: Client):
        """get_incidents_command should reject date ranges exceeding 31 days."""
        with pytest.raises(DemistoException, match="exceeds the maximum"):
            get_incidents_command(
                mock_client,
                {
                    "limit": "10",
                    "start_time": "2024-01-01T00:00:00Z",
                    "end_time": "2024-03-01T00:00:00Z",
                },
                [2],
            )

    def test_incident_type_arg_overrides_default(self, mocker: MockerFixture, mock_client: Client, incidents_result: dict):
        """When incident_type is provided in args, it overrides default_type_codes."""
        mock_fetch = mocker.patch.object(mock_client, "fetch_incidents_page", return_value=incidents_result)
        get_incidents_command(mock_client, {"limit": "10", "incident_type": "malware"}, [2])
        # Should call with type_code=3 (malware), not 2 (phishing)
        call_body = mock_fetch.call_args.kwargs
        assert call_body.get("incident_type") == 3

    def test_multiple_types(self, mocker: MockerFixture, mock_client: Client, incidents_result: dict):
        """Fetches incidents for each type code — API called once per type."""
        mock_fetch = mocker.patch.object(mock_client, "fetch_incidents_page", return_value=incidents_result)
        result = get_incidents_command(mock_client, {"limit": "10"}, [2, 3])
        # Verify fetch_incidents_page was called for each type
        called_types = [call.kwargs["incident_type"] for call in mock_fetch.call_args_list]
        assert 2 in called_types
        assert 3 in called_types
        assert isinstance(result.outputs, list)

    def test_outputs_key_field(self, mocker: MockerFixture, mock_client: Client, incidents_result: dict):
        """Verify outputs_key_field is set correctly."""
        mocker.patch.object(mock_client, "fetch_incidents_page", return_value=incidents_result)
        result = get_incidents_command(mock_client, {"limit": "10"}, [2])
        assert result.outputs_key_field == "incidentID"


# endregion

# region Fetch Incidents Command Tests (async)


class TestFetchIncidentsCommand:
    def test_first_fetch(self, mocker: MockerFixture, mock_client: Client, incidents_result: dict):
        mocker.patch.object(mock_client, "fetch_incidents_page", return_value=incidents_result)
        mocker.patch.object(demisto, "getLastRun", return_value={})
        mock_incidents = mocker.patch.object(demisto, "incidents")
        mock_set = mocker.patch.object(demisto, "setLastRun")

        asyncio.run(fetch_incidents_command(mock_client, 10000, [2]))

        created = mock_incidents.call_args[0][0]
        assert len(created) == 3
        last_run = mock_set.call_args[0][0]
        assert "2" in last_run
        assert last_run["2"]["last_created_on"] == "1700000200"
        assert last_run["2"]["last_ids"] == ["abc123"]

    def test_multiple_types_concurrent(
        self,
        mocker: MockerFixture,
        mock_client: Client,
        incidents_result: dict,
        empty_result: dict,
    ):
        """Test that multiple types are fetched (concurrently via asyncio.to_thread)."""
        mocker.patch.object(mock_client, "fetch_incidents_page", side_effect=[incidents_result, empty_result])
        mocker.patch.object(demisto, "getLastRun", return_value={})
        mock_incidents = mocker.patch.object(demisto, "incidents")
        mock_set = mocker.patch.object(demisto, "setLastRun")

        asyncio.run(fetch_incidents_command(mock_client, 10000, [2, 3]))

        created = mock_incidents.call_args[0][0]
        assert len(created) == 3
        last_run = mock_set.call_args[0][0]
        assert "2" in last_run
        assert "3" in last_run

    def test_empty_response(self, mocker: MockerFixture, mock_client: Client, empty_result: dict):
        mocker.patch.object(mock_client, "fetch_incidents_page", return_value=empty_result)
        mocker.patch.object(demisto, "getLastRun", return_value={})
        mock_incidents = mocker.patch.object(demisto, "incidents")
        mocker.patch.object(demisto, "setLastRun")

        asyncio.run(fetch_incidents_command(mock_client, 10000, [2]))
        mock_incidents.assert_called_once_with([])

    def test_exception_in_one_type_does_not_block_others(
        self,
        mocker: MockerFixture,
        mock_client: Client,
        incidents_result: dict,
    ):
        """If one type raises an exception, other types still succeed."""

        def side_effect(client, type_code, type_state, max_fetch, first_fetch_ts=""):
            if type_code == 3:
                raise DemistoException("API error for type 3")
            return _fetch_for_type(client, type_code, type_state, max_fetch, first_fetch_ts)

        mocker.patch.object(mock_client, "fetch_incidents_page", return_value=incidents_result)
        mocker.patch.object(demisto, "getLastRun", return_value={})
        mocker.patch("iZOOlogic._fetch_for_type", side_effect=side_effect)
        mocker.patch.object(demisto, "incidents")
        mock_set = mocker.patch.object(demisto, "setLastRun")
        mocker.patch.object(demisto, "error")

        asyncio.run(fetch_incidents_command(mock_client, 10000, [2, 3]))

        # Type 2 should still succeed, type 3 error is logged
        last_run = mock_set.call_args[0][0]
        assert "2" in last_run

    def test_preserves_existing_last_run_keys(self, mocker: MockerFixture, mock_client: Client, incidents_result: dict):
        """Existing last_run keys for other types are preserved."""
        existing_last_run = {"5": {"last_created_on": "999", "last_ids": ["old"]}}
        mocker.patch.object(mock_client, "fetch_incidents_page", return_value=incidents_result)
        mocker.patch.object(demisto, "getLastRun", return_value=existing_last_run)
        mocker.patch.object(demisto, "incidents")
        mock_set = mocker.patch.object(demisto, "setLastRun")

        asyncio.run(fetch_incidents_command(mock_client, 10000, [2]))

        last_run = mock_set.call_args[0][0]
        assert "5" in last_run  # Preserved
        assert "2" in last_run  # New


# endregion

# region Main Tests


class TestMain:
    @pytest.mark.parametrize(
        "command",
        ["test-module", "fetch-incidents", "izoologic-get-incidents", "izoolabs-incident-create", "izoolabs-incident-fetch"],
    )
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
                "incident_types_filter": ["phishing"],
            },
        )
        mocker.patch.object(demisto, "args", return_value={"limit": "10"})
        mock_func = mocker.MagicMock(return_value="ok")
        COMMAND_MAP[command] = mock_func
        mocker.patch("iZOOlogic.return_results")
        if command == "fetch-incidents":
            # fetch_incidents_command is async, mock asyncio.run
            mocker.patch("iZOOlogic.asyncio.run")
        main()
        if command != "fetch-incidents":
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

# region Resolve Code By Name Tests


class TestResolveCodeByName:
    @pytest.mark.parametrize(
        "raw_value, code_map, expected",
        [
            ("phishing", ApiCodes.INCIDENT_TYPE, 2),
            ("PHISHING", ApiCodes.INCIDENT_TYPE, 2),
            (" phishing ", ApiCodes.INCIDENT_TYPE, 2),
            ("low threat", ApiCodes.THREAT_TYPE, 10),
            ("critical threat", ApiCodes.THREAT_TYPE, 14),
            ("incident", ApiCodes.CASE_TYPE, 6),
            ("domain monitoring", ApiCodes.CASE_TYPE, 1),
        ],
    )
    def test_valid_names(self, raw_value: str, code_map: dict, expected: int):
        assert _resolve_code_by_name(raw_value, code_map, "test_field") == expected

    @pytest.mark.parametrize(
        "raw_value, code_map",
        [
            ("nonexistent", ApiCodes.INCIDENT_TYPE),
            ("999", ApiCodes.INCIDENT_TYPE),
            ("2", ApiCodes.INCIDENT_TYPE),  # Integer strings not accepted
            ("invalid", ApiCodes.THREAT_TYPE),
        ],
    )
    def test_invalid_names_raise(self, raw_value: str, code_map: dict):
        with pytest.raises(DemistoException, match="Invalid 'test_field'"):
            _resolve_code_by_name(raw_value, code_map, "test_field")


# endregion

# region Validate Incident Creation Args Tests


class TestValidateIncidentCreationArgs:
    @pytest.fixture
    def valid_create_args(self) -> dict:
        return {
            "incident_url": "https://malicious-site.example.com",
            "incident_type": "phishing",
            "brand_code": "BRAND001",
        }

    def test_valid_required_only(self, valid_create_args: dict):
        result = _validate_incident_creation_args(valid_create_args)
        assert result["incident_url"] == "https://malicious-site.example.com"
        assert result["incident_type"] == 2
        assert result["brand_code"] == "BRAND001"
        assert result["threat_type"] is None
        assert result["case_type"] is None
        assert result["comment"] is None
        assert result["executive_name"] is None
        assert result["client_code"] is None

    def test_valid_all_args(self, valid_create_args: dict):
        valid_create_args.update(
            {
                "threat_type": "critical threat",
                "case_type": "incident",
                "comment": "Test comment",
                "executive_name": "John Doe",
                "client_code": "CLIENT001",
            }
        )
        result = _validate_incident_creation_args(valid_create_args)
        assert result["incident_type"] == 2
        assert result["threat_type"] == 14
        assert result["case_type"] == 6
        assert result["comment"] == "Test comment"
        assert result["executive_name"] == "John Doe"
        assert result["client_code"] == "CLIENT001"

    @pytest.mark.parametrize(
        "missing_field",
        ["incident_url", "incident_type", "brand_code"],
    )
    def test_missing_required_raises(self, valid_create_args: dict, missing_field: str):
        valid_create_args[missing_field] = ""
        with pytest.raises(DemistoException, match=f"'{missing_field}' is a required argument"):
            _validate_incident_creation_args(valid_create_args)

    def test_invalid_incident_type_raises(self, valid_create_args: dict):
        valid_create_args["incident_type"] = "nonexistent"
        with pytest.raises(DemistoException, match="Invalid 'incident_type'"):
            _validate_incident_creation_args(valid_create_args)

    def test_invalid_threat_type_raises(self, valid_create_args: dict):
        valid_create_args["threat_type"] = "invalid"
        with pytest.raises(DemistoException, match="Invalid 'threat_type'"):
            _validate_incident_creation_args(valid_create_args)

    def test_invalid_case_type_raises(self, valid_create_args: dict):
        valid_create_args["case_type"] = "invalid"
        with pytest.raises(DemistoException, match="Invalid 'case_type'"):
            _validate_incident_creation_args(valid_create_args)

    def test_case_insensitive_incident_type(self, valid_create_args: dict):
        valid_create_args["incident_type"] = "PHISHING"
        result = _validate_incident_creation_args(valid_create_args)
        assert result["incident_type"] == 2

    def test_executive_type(self, valid_create_args: dict):
        valid_create_args["incident_type"] = "executive"
        result = _validate_incident_creation_args(valid_create_args)
        assert result["incident_type"] == 56


# endregion

# region Client Report New Incident Tests


class TestClientReportNewIncident:
    def test_report_new_incident_full_body(self, mocker: MockerFixture, mock_client: Client):
        """Test that report_new_incident sends correct body with all params."""
        api_response = load_test_data("create_incident_response.json")
        mock_req = mocker.patch.object(mock_client, "_http_request", return_value=api_response)

        mock_client.report_new_incident(
            incident_url="https://malicious.example.com",
            incident_type=2,
            brand_code="BRAND001",
            threat_type=14,
            case_type=6,
            comment="Test comment",
            executive_name="John Doe",
            client_code="CLIENT001",
        )

        body = mock_req.call_args.kwargs["json_data"]
        assert body["incidenturl"] == "https://malicious.example.com"
        assert body["incidenttype"] == 2
        assert body["brandcode"] == "BRAND001"
        assert body["threattype"] == 14
        assert body["casetype"] == 6
        assert body["comment"] == "Test comment"
        assert body["executivename"] == "John Doe"
        assert body["clientcode"] == "CLIENT001"

    def test_report_new_incident_minimal_body(self, mocker: MockerFixture, mock_client: Client):
        """Without optional params, body only has required fields."""
        api_response = load_test_data("create_incident_response.json")
        mock_req = mocker.patch.object(mock_client, "_http_request", return_value=api_response)

        mock_client.report_new_incident(
            incident_url="https://malicious.example.com",
            incident_type=2,
            brand_code="BRAND001",
        )

        body = mock_req.call_args.kwargs["json_data"]
        assert body == {
            "incidenturl": "https://malicious.example.com",
            "incidenttype": 2,
            "brandcode": "BRAND001",
        }
        # Optional fields should not be present (assign_params removes None values)
        assert "threattype" not in body
        assert "casetype" not in body
        assert "comment" not in body
        assert "executivename" not in body
        assert "clientcode" not in body


# endregion

# region Create Incident Command Tests


class TestCreateIncidentCommand:
    def test_success(self, mocker: MockerFixture, mock_client: Client):
        api_response = load_test_data("create_incident_response.json")
        mocker.patch.object(mock_client, "_http_request", return_value=api_response)

        args = {
            "incident_url": "https://malicious.example.com",
            "incident_type": "phishing",
            "brand_code": "BRAND001",
        }
        result = create_incident_command(mock_client, args)

        assert isinstance(result, CommandResults)
        assert result.outputs_prefix == "iZOOlabs.Incident"
        assert result.outputs_key_field == "reportedincidentid"
        assert result.outputs["reportedincidentid"] == "RPT-12345"
        assert result.outputs["statuscode"] == 1
        assert result.outputs["success"] is True

    def test_api_error_raises(self, mocker: MockerFixture, mock_client: Client):
        error_response = {
            "success": False,
            "message": "Invalid brand code",
            "errorCode": "iZOO4001",
            "result": None,
        }
        mocker.patch.object(mock_client, "_http_request", return_value=error_response)

        args = {
            "incident_url": "https://malicious.example.com",
            "incident_type": "phishing",
            "brand_code": "INVALID",
        }
        with pytest.raises(DemistoException, match="Failed to create incident"):
            create_incident_command(mock_client, args)

    def test_with_all_optional_args(self, mocker: MockerFixture, mock_client: Client):
        api_response = load_test_data("create_incident_response.json")
        mocker.patch.object(mock_client, "_http_request", return_value=api_response)

        args = {
            "incident_url": "https://malicious.example.com",
            "incident_type": "executive",
            "brand_code": "BRAND001",
            "threat_type": "critical threat",
            "case_type": "executive monitoring",
            "comment": "Executive impersonation detected",
            "executive_name": "Jane Smith",
            "client_code": "CLIENT001",
        }
        result = create_incident_command(mock_client, args)

        assert isinstance(result, CommandResults)
        assert result.outputs["reportedincidentid"] == "RPT-12345"

    def test_readable_output(self, mocker: MockerFixture, mock_client: Client):
        api_response = load_test_data("create_incident_response.json")
        mocker.patch.object(mock_client, "_http_request", return_value=api_response)

        args = {
            "incident_url": "https://malicious.example.com",
            "incident_type": "phishing",
            "brand_code": "BRAND001",
        }
        result = create_incident_command(mock_client, args)

        assert "New Incident Created" in result.readable_output
        assert "RPT-12345" in result.readable_output


# endregion

# region Incident Fetch Command Tests


class TestIncidentFetchCommand:
    def test_basic_no_args(self, mocker: MockerFixture, mock_client: Client, incidents_result: dict):
        """Fetch with default args (no filters) returns incidents."""
        mocker.patch.object(mock_client, "fetch_incidents_page", return_value=incidents_result)
        result = incident_fetch_command(mock_client, {})

        assert isinstance(result, CommandResults)
        assert result.outputs_prefix == "iZOOlabs.Incident"
        assert result.outputs_key_field == "incidentID"
        assert len(result.outputs) == 3  # type: ignore[arg-type]

    def test_with_all_filters(self, mocker: MockerFixture, mock_client: Client, incidents_result: dict):
        """Fetch with all filters passes them to the API."""
        mock_fetch = mocker.patch.object(mock_client, "fetch_incidents_page", return_value=incidents_result)

        args = {
            "from_date": "2024-01-01T00:00:00Z",
            "to_date": "2024-01-02T00:00:00Z",
            "incident_type": "phishing",
            "threat_type": "critical threat",
            "brand_code": "BRAND001",
            "executive_name": "John Doe",
            "client_ref_id": "REF123",
            "client_code": "CLIENT001",
        }
        result = incident_fetch_command(mock_client, args)

        assert isinstance(result, CommandResults)
        # Verify the API was called with the correct filters
        call_kwargs = mock_fetch.call_args.kwargs
        assert call_kwargs["incident_type"] == 2  # phishing
        assert call_kwargs["threat_type"] == 14  # critical threat
        assert call_kwargs["brand_code"] == "BRAND001"
        assert call_kwargs["executive_name"] == "John Doe"
        assert call_kwargs["client_ref_id"] == "REF123"
        assert call_kwargs["client_code"] == "CLIENT001"

    def test_invalid_incident_type_raises(self, mocker: MockerFixture, mock_client: Client):
        with pytest.raises(DemistoException, match="Invalid 'incident_type'"):
            incident_fetch_command(mock_client, {"incident_type": "nonexistent"})

    def test_invalid_threat_type_raises(self, mocker: MockerFixture, mock_client: Client):
        with pytest.raises(DemistoException, match="Invalid 'threat_type'"):
            incident_fetch_command(mock_client, {"threat_type": "invalid"})

    def test_inverted_date_range_raises(self, mocker: MockerFixture, mock_client: Client):
        with pytest.raises(DemistoException, match="is before"):
            incident_fetch_command(
                mock_client,
                {
                    "from_date": "2024-01-15T00:00:00Z",
                    "to_date": "2024-01-10T00:00:00Z",
                },
            )

    def test_empty_response(self, mocker: MockerFixture, mock_client: Client, empty_result: dict):
        mocker.patch.object(mock_client, "fetch_incidents_page", return_value=empty_result)
        result = incident_fetch_command(mock_client, {})

        assert isinstance(result, CommandResults)
        assert result.outputs == []

    def test_readable_output_has_headers(self, mocker: MockerFixture, mock_client: Client, incidents_result: dict):
        mocker.patch.object(mock_client, "fetch_incidents_page", return_value=incidents_result)
        result = incident_fetch_command(mock_client, {})

        assert "iZOOlogic Incidents" in result.readable_output
        assert "incidentID" in result.readable_output

    def test_existing_commands_dont_pass_new_params(self, mocker: MockerFixture, mock_client: Client, incidents_result: dict):
        """Verify that _fetch_all_pages called from get_incidents_command does NOT pass new filter params."""
        mock_fetch_all = mocker.patch("iZOOlogic._fetch_all_pages", return_value=[])
        mocker.patch.object(mock_client, "fetch_incidents_page", return_value=incidents_result)

        get_incidents_command(mock_client, {"limit": "10"}, [2])

        # _fetch_all_pages should be called without the new params
        call_kwargs = mock_fetch_all.call_args.kwargs
        assert "threat_type" not in call_kwargs
        assert "brand_code" not in call_kwargs
        assert "executive_name" not in call_kwargs
        assert "client_ref_id" not in call_kwargs
        assert "client_code" not in call_kwargs
# region Window Splitting Tests


class TestGenerateWindows:
    """Tests for _generate_windows — splitting date ranges into ≤31-day windows."""

    def test_single_window_within_31_days(self):
        """Range ≤31 days should produce a single window."""
        from_ts = 1700000000  # ~Nov 14, 2023
        to_ts = from_ts + (30 * 86400)  # 30 days later
        windows = _generate_windows(from_ts, to_ts)
        assert len(windows) == 1
        assert windows[0] == (str(from_ts), str(to_ts))

    def test_exactly_31_days(self):
        """Range of exactly 31 days should produce a single window."""
        from_ts = 1700000000
        to_ts = from_ts + (31 * 86400)
        windows = _generate_windows(from_ts, to_ts)
        assert len(windows) == 1
        assert windows[0] == (str(from_ts), str(to_ts))

    def test_two_windows_for_45_days(self):
        """45-day range should produce 2 windows: 31 days + 14 days."""
        from_ts = 1700000000
        to_ts = from_ts + (45 * 86400)
        windows = _generate_windows(from_ts, to_ts)
        assert len(windows) == 2
        mid = from_ts + (31 * 86400)
        assert windows[0] == (str(from_ts), str(mid))
        assert windows[1] == (str(mid), str(to_ts))

    def test_three_windows_for_90_days(self):
        """90-day range should produce 3 windows."""
        from_ts = 1700000000
        to_ts = from_ts + (90 * 86400)
        windows = _generate_windows(from_ts, to_ts)
        assert len(windows) == 3

    def test_empty_range(self):
        """from_ts == to_ts should produce no windows."""
        windows = _generate_windows(1700000000, 1700000000)
        assert len(windows) == 0


class TestFetchSingleWindow:
    """Tests for _fetch_single_window — fetching within a single ≤31-day window."""

    def test_returns_incidents_and_state(self, mocker: MockerFixture, mock_client: Client, incidents_result: dict):
        """Should return incidents and updated state for a window with data."""
        mocker.patch.object(mock_client, "fetch_incidents_page", return_value=incidents_result)

        cortex_incidents, state = _fetch_single_window(
            mock_client,
            2,
            "1700000000",
            "1700100000",
            None,
            [],
            10000,
        )

        assert len(cortex_incidents) == 3
        assert state["last_created_on"] == "1700000200"

    def test_empty_window_advances_cursor(self, mocker: MockerFixture, mock_client: Client, empty_result: dict):
        """Empty window should advance cursor to window end."""
        mocker.patch.object(mock_client, "fetch_incidents_page", return_value=empty_result)

        cortex_incidents, state = _fetch_single_window(
            mock_client,
            2,
            "1700000000",
            "1700100000",
            None,
            [],
            10000,
        )

        assert len(cortex_incidents) == 0
        assert state["last_created_on"] == "1700100000"


class TestMultiWindowFetch:
    """Tests for _fetch_for_type with multi-window (>31 day) date ranges."""

    def test_multi_window_persists_per_window_and_returns_empty(
        self,
        mocker: MockerFixture,
        mock_client: Client,
    ):
        """Multi-window fetch should persist incidents/state per window and return empty lists."""
        window1_incidents = load_test_data("incidents_response_window1.json")["result"]["incidents"]
        window2_incidents = load_test_data("incidents_response_window2.json")["result"]["incidents"]

        # Mock _fetch_all_pages directly to return different incidents per window
        mocker.patch(
            "iZOOlogic._fetch_all_pages",
            side_effect=[window1_incidents, window2_incidents],
        )

        # Fix "now" to Dec 19, 2023 so the test data timestamps fall within the windows:
        # Window 1 data: createdOn=1700000100 (~Nov 14, 2023)
        # Window 2 data: createdOn=1702678400 (~Dec 15, 2023)
        fixed_now = 1703000000  # ~Dec 19, 2023
        mocker.patch("iZOOlogic.get_current_unix_timestamp", return_value=str(fixed_now))
        first_fetch_ts = str(fixed_now - (45 * 86400))  # ~Nov 4, 2023

        mock_incidents = mocker.patch.object(demisto, "incidents")
        mocker.patch.object(demisto, "getLastRun", return_value={})
        mock_set_lr = mocker.patch.object(demisto, "setLastRun")

        type_key, cortex_incidents, state = _fetch_for_type(
            mock_client,
            2,
            {},
            10000,
            first_fetch_ts,
        )

        # Multi-window: returns empty incidents (already persisted per-window)
        assert type_key == "2"
        assert cortex_incidents == []
        # State should be updated to the latest window's state
        assert "last_created_on" in state

        # 45 days = 2 windows, both with unique data → 2 calls each
        assert mock_incidents.call_count == 2
        assert mock_set_lr.call_count == 2
        # Verify setLastRun was called with the type key
        for call in mock_set_lr.call_args_list:
            last_run_arg = call[0][0]
            assert "2" in last_run_arg

    def test_single_window_returns_incidents_normally(self, mocker: MockerFixture, mock_client: Client, incidents_result: dict):
        """Single-window fetch should return incidents normally without per-window persistence."""
        mocker.patch.object(mock_client, "fetch_incidents_page", return_value=incidents_result)

        mock_incidents = mocker.patch.object(demisto, "incidents")
        mock_set_lr = mocker.patch.object(demisto, "setLastRun")

        type_key, cortex_incidents, state = _fetch_for_type(
            mock_client,
            2,
            {},
            10000,
        )

        # Single window: incidents returned normally for fetch_incidents_command to handle
        assert len(cortex_incidents) == 3
        assert state["last_created_on"] == "1700000200"
        # demisto.incidents/setLastRun should NOT have been called inside _fetch_for_type
        mock_incidents.assert_not_called()
        mock_set_lr.assert_not_called()


# endregion
