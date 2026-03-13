"""Tests for SAP Enterprise Threat Detection integration."""

import copy
import json
import os
from typing import Any
from unittest.mock import MagicMock, patch

import demistomock as demisto  # noqa: F401
import pytest
from CommonServerPython import *  # noqa: F401


@pytest.fixture(autouse=True)
def mock_support_multithreading():
    """Mock support_multithreading to prevent demistomock attribute errors.

    This fixture automatically runs before each test to mock the support_multithreading
    function which is called during ContentClient initialization. Without this mock,
    tests fail because demistomock doesn't have the _Demisto__do attribute.
    """
    with patch("ContentClientApiModule.support_multithreading"):
        yield


from SAPETD import (
    INTEGRATION_NAME,
    Config,
    SAPETDClient,
    add_time_to_events,
    deduplicate_events,
    fetch_alerts_with_pagination,
    fetch_events_command,
    get_events_command,
    main,
    parse_date_to_iso,
    parse_integration_params,
    test_module as _test_module,
)

# region Test data helpers
# =================================
# Test data helpers
# =================================

TEST_DATA_DIR = os.path.join(os.path.dirname(__file__), "test_data")


def load_test_data(filename: str) -> Any:
    """Load test data from a JSON file in the test_data directory.

    Args:
        filename: Name of the JSON file to load.

    Returns:
        Parsed JSON data.
    """
    filepath = os.path.join(TEST_DATA_DIR, filename)
    with open(filepath) as f:
        return json.load(f)


SAMPLE_ALERTS: list[dict[str, Any]] = load_test_data("sample_alerts.json")

# endregion

# region Fixtures
# =================================
# Fixtures
# =================================


@pytest.fixture
def sample_alerts() -> list[dict[str, Any]]:
    """Return a deep copy of sample alerts for test isolation."""
    return copy.deepcopy(SAMPLE_ALERTS)


@pytest.fixture
def mock_config() -> dict[str, Any]:
    """Return a valid mock configuration dict."""
    return {
        "base_url": "https://etd.example.com:4300",
        "username": "test_user",
        "password": "test_password",
        "verify": False,
        "proxy": False,
        "max_fetch": Config.DEFAULT_MAX_FETCH,
    }


@pytest.fixture
def mock_params() -> dict[str, Any]:
    """Return valid raw integration params as from demisto.params()."""
    return {
        "url": "https://etd.example.com:4300",
        "credentials": {"identifier": "test_user", "password": "test_password"},
        "insecure": False,
        "proxy": False,
        "max_fetch": str(Config.DEFAULT_MAX_FETCH),
    }


@pytest.fixture
def client(mock_config: dict[str, Any]) -> SAPETDClient:
    """Create a SAPETDClient instance for testing."""
    return SAPETDClient(mock_config)


# endregion

# region parse_date_to_iso tests
# =================================
# parse_date_to_iso tests
# =================================


class TestParseDateToIso:
    """Tests for the parse_date_to_iso helper function."""

    @pytest.mark.parametrize(
        "date_input, expected_pattern",
        [
            pytest.param(
                "3 days ago",
                r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z",
                id="relative_date",
            ),
            pytest.param(
                "2026-01-15T15:00:00Z",
                r"2026-01-15T15:00:00\.000000Z",
                id="absolute_date",
            ),
            pytest.param(
                None,
                r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z",
                id="none_input_uses_current_utc",
            ),
            pytest.param(
                "not_a_real_date_xyz",
                r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z",
                id="invalid_string_fallback_to_current_utc",
            ),
        ],
    )
    def test_parse_date_to_iso(self, date_input: str | None, expected_pattern: str) -> None:
        """Test that parse_date_to_iso returns a valid ISO 8601 timestamp."""
        import re

        result = parse_date_to_iso(date_input)
        assert re.match(expected_pattern, result), f"Result '{result}' did not match pattern '{expected_pattern}'"

    def test_relative_date_is_in_past(self) -> None:
        """Test that a relative date like '3 days ago' produces a timestamp in the past."""
        result = parse_date_to_iso("3 days ago")
        parsed = datetime.strptime(result, Config.DATE_FORMAT).replace(tzinfo=timezone.utc)
        now = datetime.now(tz=timezone.utc)
        assert parsed < now, "Parsed '3 days ago' should be in the past"

    def test_none_returns_recent_timestamp(self) -> None:
        """Test that None input returns a timestamp close to current UTC time."""
        before = datetime.now(tz=timezone.utc)
        result = parse_date_to_iso(None)
        after = datetime.now(tz=timezone.utc)

        parsed = datetime.strptime(result, Config.DATE_FORMAT).replace(tzinfo=timezone.utc)
        assert before <= parsed <= after, "None input should return current UTC time"

    def test_absolute_date_exact_value(self) -> None:
        """Test that an absolute ISO date is parsed to the expected exact value."""
        result = parse_date_to_iso("2026-01-15T15:00:00Z")
        assert result == "2026-01-15T15:00:00.000000Z"


# endregion

# region parse_integration_params tests
# =================================
# parse_integration_params tests
# =================================


class TestParseIntegrationParams:
    """Tests for the parse_integration_params function."""

    def test_valid_params(self, mock_params: dict[str, Any]) -> None:
        """Test parsing valid parameters returns correct config."""
        config = parse_integration_params(mock_params)

        assert config["base_url"] == "https://etd.example.com:4300"
        assert config["username"] == "test_user"
        assert config["password"] == "test_password"
        assert config["verify"] is True  # insecure=False means verify=True
        assert config["proxy"] is False
        assert config["max_fetch"] == Config.DEFAULT_MAX_FETCH

    def test_url_trailing_slash_stripped(self) -> None:
        """Test that trailing slashes are stripped from the URL."""
        params = {
            "url": "https://etd.example.com:4300///",
            "credentials": {"identifier": "dummy_user", "password": "dummy_pass"},
        }
        config = parse_integration_params(params)
        assert config["base_url"] == "https://etd.example.com:4300"

    @pytest.mark.parametrize(
        "params, expected_error",
        [
            pytest.param(
                {"url": "", "credentials": {"identifier": "dummy_user", "password": "dummy_pass"}},
                "Server URL is required",
                id="missing_url",
            ),
            pytest.param(
                {"url": "https://example.com", "credentials": {"identifier": "", "password": "dummy_pass"}},
                "Username and Password are required",
                id="missing_username",
            ),
            pytest.param(
                {"url": "https://example.com", "credentials": {"identifier": "dummy_user", "password": ""}},
                "Username and Password are required",
                id="missing_password",
            ),
            pytest.param(
                {"url": "https://example.com", "credentials": {}},
                "Username and Password are required",
                id="empty_credentials",
            ),
            pytest.param(
                {"url": "https://example.com"},
                "Username and Password are required",
                id="no_credentials_key",
            ),
        ],
    )
    def test_missing_required_params(self, params: dict, expected_error: str) -> None:
        """Test that missing required parameters raise DemistoException."""
        with pytest.raises(DemistoException, match=expected_error):
            parse_integration_params(params)

    def test_default_max_fetch(self) -> None:
        """Test that max_fetch defaults to Config.DEFAULT_MAX_FETCH when not provided."""
        params = {
            "url": "https://example.com",
            "credentials": {"identifier": "dummy_user", "password": "dummy_pass"},
        }
        config = parse_integration_params(params)
        assert config["max_fetch"] == Config.DEFAULT_MAX_FETCH


# endregion

# region add_time_to_events tests
# =================================
# add_time_to_events tests
# =================================


class TestAddTimeToEvents:
    """Tests for the add_time_to_events helper function."""

    @pytest.mark.parametrize(
        "events, expected_time_keys",
        [
            pytest.param(
                [
                    {"AlertId": 1, "AlertCreationTimestamp": "2022-04-29T14:20:29.682Z"},
                    {"AlertId": 2, "AlertCreationTimestamp": "2022-04-29T15:30:00.000Z"},
                ],
                {1: "2022-04-29T14:20:29.682000+00:00", 2: "2022-04-29T15:30:00+00:00"},
                id="with_timestamps",
            ),
            pytest.param(
                [{"AlertId": 1}],
                {1: None},
                id="without_timestamp",
            ),
            pytest.param(
                [],
                {},
                id="empty_list",
            ),
            pytest.param(
                [
                    {"AlertId": 1},
                    {"AlertId": 2, "AlertCreationTimestamp": "2022-04-29T15:30:00.000Z"},
                    {"AlertId": 3, "AlertCreationTimestamp": "2022-04-29T16:00:00.000Z"},
                    {"AlertId": 4},
                ],
                {1: None, 2: "2022-04-29T15:30:00+00:00", 3: "2022-04-29T16:00:00+00:00", 4: None},
                id="mixed_events",
            ),
        ],
    )
    def test_adds_time_field(self, events: list[dict], expected_time_keys: dict[int, str | None]) -> None:
        """Test that _time is set from AlertCreationTimestamp when present."""
        add_time_to_events(events)
        for event in events:
            alert_id = event["AlertId"]
            expected = expected_time_keys[alert_id]
            if expected is None:
                assert "_time" not in event, f"AlertId {alert_id} should not have _time"
            else:
                assert event["_time"] == expected, f"AlertId {alert_id} _time mismatch"


# endregion

# region deduplicate_events tests
# =================================
# deduplicate_events tests
# =================================


class TestDeduplicateEvents:
    """Tests for the deduplicate_events helper function."""

    @pytest.mark.parametrize(
        "events, last_ids, expected_count, expected_ids",
        [
            pytest.param(
                [
                    {"AlertId": 6101, "AlertCreationTimestamp": "2022-04-29T14:20:29.682Z"},
                    {"AlertId": 6102, "AlertCreationTimestamp": "2022-04-29T15:30:00.000Z"},
                    {"AlertId": 6103, "AlertCreationTimestamp": "2022-04-29T15:30:00.000Z"},
                ],
                [6101, 6102],
                1,
                [6103],
                id="removes_duplicates",
            ),
            pytest.param(
                [{"AlertId": 6104, "AlertCreationTimestamp": "2022-04-30T10:00:00.000Z"}],
                [6101, 6102],
                1,
                [6104],
                id="no_duplicates",
            ),
            pytest.param(
                [{"AlertId": 6101, "AlertCreationTimestamp": "2022-04-29T14:20:29.682Z"}],
                [],
                1,
                [6101],
                id="first_run_no_previous_ids",
            ),
            pytest.param(
                [],
                [6101],
                0,
                [],
                id="empty_events",
            ),
            pytest.param(
                [
                    {"AlertId": 6101, "AlertCreationTimestamp": "2022-04-29T14:20:29.682Z"},
                    {"AlertId": 6102, "AlertCreationTimestamp": "2022-04-29T15:30:00.000Z"},
                ],
                [6101, 6102],
                0,
                [],
                id="all_duplicates",
            ),
        ],
    )
    def test_deduplication(
        self,
        events: list[dict],
        last_ids: list[int],
        expected_count: int,
        expected_ids: list[int],
    ) -> None:
        """Test deduplication with various scenarios."""
        result = deduplicate_events(events, last_ids)
        assert len(result) == expected_count
        assert [e["AlertId"] for e in result] == expected_ids


# endregion

# region fetch_alerts_with_pagination tests
# =================================
# fetch_alerts_with_pagination tests
# =================================


class TestFetchAlertsWithPagination:
    """Tests for the shared fetch_alerts_with_pagination function with pagination."""

    def test_returns_sorted_alerts(self, client: SAPETDClient) -> None:
        """Test that alerts are returned sorted by AlertCreationTimestamp ascending."""
        unsorted_alerts = [
            {"AlertId": 2, "AlertCreationTimestamp": "2022-04-29T15:30:00.000Z"},
            {"AlertId": 1, "AlertCreationTimestamp": "2022-04-29T14:20:29.682Z"},
            {"AlertId": 3, "AlertCreationTimestamp": "2022-04-29T16:00:00.000Z"},
        ]
        client.get_alerts = MagicMock(return_value=unsorted_alerts)

        result = fetch_alerts_with_pagination(client, from_timestamp="2022-04-29T14:00:00.000000Z", max_alerts=10)

        assert len(result) == 3
        assert result[0]["AlertId"] == 1
        assert result[1]["AlertId"] == 2
        assert result[2]["AlertId"] == 3

    def test_slices_to_max_alerts(self, client: SAPETDClient, sample_alerts: list[dict]) -> None:
        """Test that results are sliced to max_alerts limit."""
        client.get_alerts = MagicMock(return_value=sample_alerts)

        result = fetch_alerts_with_pagination(client, from_timestamp="2022-04-29T14:00:00.000000Z", max_alerts=2)

        assert len(result) == 2
        # Should keep the first 2 after sorting (oldest first)
        assert result[0]["AlertId"] == 6101
        assert result[1]["AlertId"] == 6102

    def test_empty_response(self, client: SAPETDClient) -> None:
        """Test that empty API response returns empty list."""
        client.get_alerts = MagicMock(return_value=[])

        result = fetch_alerts_with_pagination(client, from_timestamp="2022-04-29T14:00:00.000000Z", max_alerts=10)

        assert result == []

    def test_single_alert(self, client: SAPETDClient) -> None:
        """Test with a single alert returned."""
        single_alert = [{"AlertId": 1, "AlertCreationTimestamp": "2022-04-29T14:20:29.682Z"}]
        client.get_alerts = MagicMock(return_value=single_alert)

        result = fetch_alerts_with_pagination(client, from_timestamp="2022-04-29T14:00:00.000000Z", max_alerts=1)

        assert len(result) == 1
        assert result[0]["AlertId"] == 1

    def test_no_slicing_when_under_limit(self, client: SAPETDClient) -> None:
        """Test that no slicing occurs when results are under the limit."""
        alerts = [
            {"AlertId": 1, "AlertCreationTimestamp": "2022-04-29T14:20:29.682Z"},
            {"AlertId": 2, "AlertCreationTimestamp": "2022-04-29T15:30:00.000Z"},
        ]
        client.get_alerts = MagicMock(return_value=alerts)

        result = fetch_alerts_with_pagination(client, from_timestamp="2022-04-29T14:00:00.000000Z", max_alerts=10)

        assert len(result) == 2

    def test_propagates_client_exception(self, client: SAPETDClient) -> None:
        """Test that exceptions from client.get_alerts are propagated."""
        client.get_alerts = MagicMock(side_effect=Exception("API Error"))

        with pytest.raises(Exception, match="API Error"):
            fetch_alerts_with_pagination(client, from_timestamp="2022-04-29T14:00:00.000000Z", max_alerts=10)

    def test_pagination_multiple_batches(self, client: SAPETDClient) -> None:
        """Test that pagination fetches multiple batches until max_alerts is reached."""
        batch1 = [{"AlertId": i, "AlertCreationTimestamp": f"2022-04-29T14:{i:02d}:00.000Z"} for i in range(1, 1001)]
        batch2 = [{"AlertId": i, "AlertCreationTimestamp": f"2022-04-29T15:{(i - 1000):02d}:00.000Z"} for i in range(1001, 1501)]

        client.get_alerts = MagicMock(side_effect=[batch1, batch2])

        result = fetch_alerts_with_pagination(client, from_timestamp="2022-04-29T14:00:00.000000Z", max_alerts=1500)

        assert len(result) == 1500
        assert client.get_alerts.call_count == 2
        # First call should request MAX_PAGE_SIZE (1000)
        assert client.get_alerts.call_args_list[0].kwargs["batch_size"] == Config.MAX_PAGE_SIZE
        # Second call should request remaining 500
        assert client.get_alerts.call_args_list[1].kwargs["batch_size"] == 500

    def test_pagination_stops_on_empty_batch(self, client: SAPETDClient) -> None:
        """Test that pagination stops when an empty batch is returned."""
        # batch1 must have exactly MAX_PAGE_SIZE items so pagination continues to batch2
        batch1 = [{"AlertId": i, "AlertCreationTimestamp": f"2022-04-29T14:{(i % 60):02d}:00.000Z"} for i in range(1, 1001)]

        client.get_alerts = MagicMock(side_effect=[batch1, []])

        result = fetch_alerts_with_pagination(client, from_timestamp="2022-04-29T14:00:00.000000Z", max_alerts=2000)

        assert len(result) == 1000
        assert client.get_alerts.call_count == 2

    def test_pagination_stops_when_batch_smaller_than_requested(self, client: SAPETDClient) -> None:
        """Test that pagination stops when batch returns fewer alerts than requested."""
        # Request 2000 alerts, but only 800 exist
        batch1 = [{"AlertId": i, "AlertCreationTimestamp": f"2022-04-29T14:{i:02d}:00.000Z"} for i in range(1, 801)]

        client.get_alerts = MagicMock(return_value=batch1)

        result = fetch_alerts_with_pagination(client, from_timestamp="2022-04-29T14:00:00.000000Z", max_alerts=2000)

        assert len(result) == 800
        # Should only call once since 800 < 1000 (MAX_PAGE_SIZE)
        assert client.get_alerts.call_count == 1

    def test_pagination_updates_from_timestamp(self, client: SAPETDClient) -> None:
        """Test that from_timestamp is updated to last alert's timestamp between pages."""
        batch1 = [
            {"AlertId": 1, "AlertCreationTimestamp": "2022-04-29T14:00:00.000Z"},
            {"AlertId": 2, "AlertCreationTimestamp": "2022-04-29T14:30:00.000Z"},
        ]
        batch2 = [
            {"AlertId": 3, "AlertCreationTimestamp": "2022-04-29T15:00:00.000Z"},
        ]

        client.get_alerts = MagicMock(side_effect=[batch1, batch2])

        # Request max_alerts=3 with MAX_PAGE_SIZE=1000, but batch1 has only 2 (< 1000)
        # so it stops after first batch. To test timestamp update, we need batch1 to be full.
        # Let's use a different approach: set max_alerts=2 per page via smaller batches.
        # Actually, since batch1 has 2 items < 1000 (MAX_PAGE_SIZE), pagination stops.
        # We need to make batch1 exactly MAX_PAGE_SIZE to continue.
        batch1_full = [
            {"AlertId": i, "AlertCreationTimestamp": f"2022-04-29T14:{(i % 60):02d}:00.000Z"}
            for i in range(1, Config.MAX_PAGE_SIZE + 1)
        ]
        last_ts = batch1_full[-1]["AlertCreationTimestamp"]

        batch2_partial = [
            {"AlertId": Config.MAX_PAGE_SIZE + 1, "AlertCreationTimestamp": "2022-04-29T15:00:00.000Z"},
        ]

        client.get_alerts = MagicMock(side_effect=[batch1_full, batch2_partial])

        fetch_alerts_with_pagination(client, from_timestamp="2022-04-29T14:00:00.000000Z", max_alerts=1500)

        assert client.get_alerts.call_count == 2
        # Second call should use the last alert's timestamp from batch1
        second_call_kwargs = client.get_alerts.call_args_list[1].kwargs
        assert second_call_kwargs["from_timestamp"] == last_ts

    def test_pagination_three_full_batches(self, client: SAPETDClient) -> None:
        """Test pagination across three full batches."""

        def make_batch(start_id: int, count: int, hour: int) -> list[dict]:
            return [
                {"AlertId": start_id + i, "AlertCreationTimestamp": f"2022-04-29T{hour:02d}:{(i % 60):02d}:00.000Z"}
                for i in range(count)
            ]

        batch1 = make_batch(1, Config.MAX_PAGE_SIZE, 14)
        batch2 = make_batch(1001, Config.MAX_PAGE_SIZE, 15)
        batch3 = make_batch(2001, Config.MAX_PAGE_SIZE, 16)

        client.get_alerts = MagicMock(side_effect=[batch1, batch2, batch3])

        result = fetch_alerts_with_pagination(client, from_timestamp="2022-04-29T14:00:00.000000Z", max_alerts=3000)

        assert len(result) == 3000
        assert client.get_alerts.call_count == 3

    def test_pagination_respects_max_page_size(self, client: SAPETDClient) -> None:
        """Test that individual batch requests never exceed MAX_PAGE_SIZE."""
        batch1 = [
            {"AlertId": i, "AlertCreationTimestamp": f"2022-04-29T14:{(i % 60):02d}:00.000Z"}
            for i in range(1, Config.MAX_PAGE_SIZE + 1)
        ]
        batch2 = [
            {"AlertId": i, "AlertCreationTimestamp": f"2022-04-29T15:{(i % 60):02d}:00.000Z"}
            for i in range(Config.MAX_PAGE_SIZE + 1, Config.MAX_PAGE_SIZE + 501)
        ]

        client.get_alerts = MagicMock(side_effect=[batch1, batch2])

        fetch_alerts_with_pagination(client, from_timestamp="2022-04-29T14:00:00.000000Z", max_alerts=1500)

        # First call: min(1000, 1500) = 1000
        assert client.get_alerts.call_args_list[0].kwargs["batch_size"] == Config.MAX_PAGE_SIZE
        # Second call: min(1000, 500) = 500
        assert client.get_alerts.call_args_list[1].kwargs["batch_size"] == 500

    def test_pagination_small_max_alerts(self, client: SAPETDClient) -> None:
        """Test pagination when max_alerts is smaller than MAX_PAGE_SIZE."""
        alerts = [{"AlertId": i, "AlertCreationTimestamp": f"2022-04-29T14:{i:02d}:00.000Z"} for i in range(1, 51)]
        client.get_alerts = MagicMock(return_value=alerts)

        result = fetch_alerts_with_pagination(client, from_timestamp="2022-04-29T14:00:00.000000Z", max_alerts=50)

        assert len(result) == 50
        # batch_size should be min(1000, 50) = 50
        assert client.get_alerts.call_args_list[0].kwargs["batch_size"] == 50
        assert client.get_alerts.call_count == 1


# endregion

# region test_module tests
# =================================
# test_module tests
# =================================


class TestTestModule:
    """Tests for the test_module command."""

    def test_success(self, client: SAPETDClient) -> None:
        """Test successful connectivity check."""
        client.get_alerts = MagicMock(return_value=[SAMPLE_ALERTS[0]])

        result = _test_module(client)

        assert result == "ok"
        client.get_alerts.assert_called_once()

    def test_empty_response_success(self, client: SAPETDClient) -> None:
        """Test that empty response is still considered successful."""
        client.get_alerts = MagicMock(return_value=[])

        result = _test_module(client)

        assert result == "ok"

    @pytest.mark.parametrize(
        "error_message, expected_substring",
        [
            pytest.param("401 Unauthorized", "Authorization Error", id="401_error"),
            pytest.param("403 Forbidden", "Authorization Error", id="403_error"),
            pytest.param("HTTP 401", "Authorization Error", id="http_401"),
            pytest.param("unauthorized access", "Authorization Error", id="unauthorized_lowercase"),
        ],
    )
    def test_auth_error(self, client: SAPETDClient, error_message: str, expected_substring: str) -> None:
        """Test authentication error handling returns user-friendly message."""
        client.get_alerts = MagicMock(side_effect=Exception(error_message))

        result = _test_module(client)

        assert expected_substring in result

    def test_unexpected_error(self, client: SAPETDClient) -> None:
        """Test that unexpected errors are re-raised."""
        client.get_alerts = MagicMock(side_effect=Exception("Connection timeout"))

        with pytest.raises(Exception, match="Connection timeout"):
            _test_module(client)


# endregion

# region get_events_command tests
# =================================
# get_events_command tests
# =================================


class TestGetEventsCommand:
    """Tests for the get_events_command (sap-etd-get-events)."""

    def test_returns_command_results(self, client: SAPETDClient, sample_alerts: list[dict]) -> None:
        """Test that command returns CommandResults with alert data."""
        client.get_alerts = MagicMock(return_value=sample_alerts)

        args = {"from_date": "3 days ago", "limit": "50", "should_push_events": "false"}
        result = get_events_command(client, args)

        assert isinstance(result, CommandResults)
        assert result.outputs_prefix == "SAPETD.Alert"
        assert result.outputs_key_field == "AlertId"
        assert len(result.outputs) == 3

    def test_with_limit(self, client: SAPETDClient, sample_alerts: list[dict]) -> None:
        """Test that limit is applied correctly."""
        client.get_alerts = MagicMock(return_value=sample_alerts)

        args = {"from_date": "3 days ago", "limit": "1", "should_push_events": "false"}
        result = get_events_command(client, args)

        assert isinstance(result, CommandResults)
        assert len(result.outputs) == 1

    @patch("SAPETD.send_events_to_xsiam")
    def test_push_events(self, mock_send: MagicMock, client: SAPETDClient, sample_alerts: list[dict]) -> None:
        """Test that events are pushed to XSIAM when should_push_events is true."""
        client.get_alerts = MagicMock(return_value=sample_alerts)

        args = {"from_date": "3 days ago", "limit": "50", "should_push_events": "true"}
        result = get_events_command(client, args)

        assert isinstance(result, str)
        assert "3" in result
        # send_events_to_xsiam is called internally by client.send_events
        mock_send.assert_called_once()
        call_kwargs = mock_send.call_args
        assert call_kwargs.kwargs["vendor"] == Config.VENDOR
        assert call_kwargs.kwargs["product"] == Config.PRODUCT

    def test_empty_response(self, client: SAPETDClient) -> None:
        """Test handling of empty API response."""
        client.get_alerts = MagicMock(return_value=[])

        args = {"from_date": "3 days ago", "limit": "50", "should_push_events": "false"}
        result = get_events_command(client, args)

        assert isinstance(result, CommandResults)
        assert result.outputs == []

    @patch("SAPETD.send_events_to_xsiam")
    def test_push_events_empty_no_send(self, mock_send: MagicMock, client: SAPETDClient) -> None:
        """Test that empty events are not pushed to XSIAM."""
        client.get_alerts = MagicMock(return_value=[])

        args = {"from_date": "3 days ago", "limit": "50", "should_push_events": "true"}
        result = get_events_command(client, args)

        # Empty events should return CommandResults, not push
        assert isinstance(result, CommandResults)
        mock_send.assert_not_called()

    def test_events_sorted_ascending(self, client: SAPETDClient) -> None:
        """Test that events are sorted by AlertCreationTimestamp ascending."""
        unsorted_alerts = [
            {"AlertId": 2, "AlertCreationTimestamp": "2022-04-29T15:30:00.000Z"},
            {"AlertId": 1, "AlertCreationTimestamp": "2022-04-29T14:20:29.682Z"},
        ]
        client.get_alerts = MagicMock(return_value=unsorted_alerts)

        args = {"from_date": "3 days ago", "limit": "50", "should_push_events": "false"}
        result = get_events_command(client, args)

        assert isinstance(result, CommandResults)
        assert result.outputs[0]["AlertId"] == 1
        assert result.outputs[1]["AlertId"] == 2


# endregion

# region fetch_events_command tests
# =================================
# fetch_events_command tests
# =================================


class TestFetchEventsCommand:
    """Tests for the fetch_events_command (fetch-events)."""

    @patch("SAPETD.send_events_to_xsiam")
    def test_first_run(self, mock_send: MagicMock, client: SAPETDClient, sample_alerts: list[dict]) -> None:
        """Test first run with no last_run state."""
        client.get_alerts = MagicMock(return_value=sample_alerts)

        mock_last_run: dict = {}

        with (
            patch.object(demisto, "getLastRun", return_value=mock_last_run),
            patch.object(demisto, "setLastRun") as mock_set_last_run,
        ):
            fetch_events_command(client, max_fetch=Config.DEFAULT_MAX_FETCH)

        # Verify events were sent
        mock_send.assert_called_once()
        sent_events = mock_send.call_args.kwargs["events"]
        assert len(sent_events) == 3

        # Verify last run was updated
        mock_set_last_run.assert_called_once()
        new_last_run = mock_set_last_run.call_args[0][0]
        assert new_last_run["last_fetch"] == "2022-04-29T15:30:00.000Z"
        # AlertIds 6102 and 6103 share the same HWM timestamp
        assert set(new_last_run["last_fetched_alert_ids"]) == {6102, 6103}

    @patch("SAPETD.send_events_to_xsiam")
    def test_subsequent_run_with_dedup(self, mock_send: MagicMock, client: SAPETDClient, sample_alerts: list[dict]) -> None:
        """Test subsequent run with deduplication of previously fetched alerts."""
        client.get_alerts = MagicMock(return_value=sample_alerts)

        mock_last_run = {
            "last_fetch": "2022-04-29T14:20:29.682Z",
            "last_fetched_alert_ids": [6101],
        }

        with (
            patch.object(demisto, "getLastRun", return_value=mock_last_run),
            patch.object(demisto, "setLastRun") as mock_set_last_run,
        ):
            fetch_events_command(client, max_fetch=Config.DEFAULT_MAX_FETCH)

        # Verify only new events were sent (6101 should be deduped)
        mock_send.assert_called_once()
        sent_events = mock_send.call_args.kwargs["events"]
        assert len(sent_events) == 2
        sent_ids = [e["AlertId"] for e in sent_events]
        assert 6101 not in sent_ids
        assert 6102 in sent_ids
        assert 6103 in sent_ids

        # Verify last run was updated with new HWM
        new_last_run = mock_set_last_run.call_args[0][0]
        assert new_last_run["last_fetch"] == "2022-04-29T15:30:00.000Z"

    @patch("SAPETD.send_events_to_xsiam")
    def test_no_events(self, mock_send: MagicMock, client: SAPETDClient) -> None:
        """Test fetch when no events are returned."""
        client.get_alerts = MagicMock(return_value=[])

        mock_last_run: dict = {}

        with (
            patch.object(demisto, "getLastRun", return_value=mock_last_run),
            patch.object(demisto, "setLastRun") as mock_set_last_run,
        ):
            fetch_events_command(client, max_fetch=Config.DEFAULT_MAX_FETCH)

        # No events should be sent and last run should not be updated
        mock_send.assert_not_called()
        mock_set_last_run.assert_not_called()

    @patch("SAPETD.send_events_to_xsiam")
    def test_all_duplicates(self, mock_send: MagicMock, client: SAPETDClient) -> None:
        """Test fetch when all events are duplicates."""
        single_alert = [copy.deepcopy(SAMPLE_ALERTS[0])]
        client.get_alerts = MagicMock(return_value=single_alert)

        mock_last_run = {
            "last_fetch": "2022-04-29T14:20:29.682Z",
            "last_fetched_alert_ids": [6101],
        }

        with (
            patch.object(demisto, "getLastRun", return_value=mock_last_run),
            patch.object(demisto, "setLastRun") as mock_set_last_run,
        ):
            fetch_events_command(client, max_fetch=Config.DEFAULT_MAX_FETCH)

        # No events should be sent (all duplicates)
        mock_send.assert_not_called()

        # But last run should still be updated (HWM advances)
        mock_set_last_run.assert_called_once()

    @patch("SAPETD.send_events_to_xsiam")
    def test_hwm_update_with_ids_at_timestamp(
        self, mock_send: MagicMock, client: SAPETDClient, sample_alerts: list[dict]
    ) -> None:
        """Test that HWM correctly tracks AlertIds at the latest timestamp."""
        client.get_alerts = MagicMock(return_value=sample_alerts)

        with (
            patch.object(demisto, "getLastRun", return_value={}),
            patch.object(demisto, "setLastRun") as mock_set_last_run,
        ):
            fetch_events_command(client, max_fetch=Config.DEFAULT_MAX_FETCH)

        new_last_run = mock_set_last_run.call_args[0][0]
        # Alerts 6102 and 6103 both have timestamp "2022-04-29T15:30:00.000Z"
        assert new_last_run["last_fetch"] == "2022-04-29T15:30:00.000Z"
        assert set(new_last_run["last_fetched_alert_ids"]) == {6102, 6103}


# endregion

# region Client tests
# =================================
# Client tests
# =================================


class TestClient:
    """Tests for the SAPETDClient class.

    Note: ContentClient uses httpx internally, so requests_mock won't work.
    We mock client.get() directly instead.
    """

    @pytest.mark.parametrize(
        "api_response, expected_count, expected_first_id",
        [
            pytest.param(SAMPLE_ALERTS, 3, 6101, id="success_multiple_alerts"),
            pytest.param([SAMPLE_ALERTS[0]], 1, 6101, id="success_single_alert"),
            pytest.param([], 0, None, id="empty_response"),
        ],
    )
    def test_get_alerts_responses(
        self,
        client: SAPETDClient,
        api_response: list,
        expected_count: int,
        expected_first_id: int | None,
    ) -> None:
        """Test get_alerts with various API response types."""
        client.get = MagicMock(return_value=api_response)  # type: ignore[method-assign]

        result = client.get_alerts(
            from_timestamp="2022-04-29T14:00:00.000000Z",
            batch_size=100,
        )

        assert len(result) == expected_count
        if expected_first_id is not None:
            assert result[0]["AlertId"] == expected_first_id
        client.get.assert_called_once()

    def test_get_alerts_query_params(self, client: SAPETDClient) -> None:
        """Test that correct query parameters are sent."""
        client.get = MagicMock(return_value=[])  # type: ignore[method-assign]

        client.get_alerts(
            from_timestamp="2022-04-29T14:00:00.000000Z",
            batch_size=500,
        )

        call_kwargs = client.get.call_args
        params = call_kwargs.kwargs.get("params") or call_kwargs[1].get("params")
        assert params["$query"] == "AlertCreationTimestamp ge 2022-04-29T14:00:00.000000Z"
        assert params["$format"] == "JSON"
        assert params["$batchSize"] == "500"
        assert params["$includeEvents"] == "true"

    @pytest.mark.parametrize(
        "api_response, expected_result",
        [
            pytest.param({"error": "unexpected"}, [], id="dict_response"),
            pytest.param({"results": []}, [], id="dict_with_results_key"),
            pytest.param("not_a_list", [], id="string_response"),
        ],
    )
    def test_get_alerts_unexpected_response(self, client: SAPETDClient, api_response: Any, expected_result: list) -> None:
        """Test handling of unexpected (non-list) response formats."""
        client.get = MagicMock(return_value=api_response)  # type: ignore[method-assign]

        result = client.get_alerts(
            from_timestamp="2022-04-29T14:00:00.000000Z",
        )

        assert result == expected_result

    @pytest.mark.parametrize(
        "error_type, error_msg",
        [
            pytest.param(Exception, "Internal Server Error", id="generic_exception"),
            pytest.param(DemistoException, "API Error 500", id="demisto_exception"),
            pytest.param(ConnectionError, "Connection refused", id="connection_error"),
        ],
    )
    def test_get_alerts_error_propagation(self, client: SAPETDClient, error_type: type, error_msg: str) -> None:
        """Test that various HTTP errors are properly propagated."""
        client.get = MagicMock(side_effect=error_type(error_msg))  # type: ignore[method-assign]

        with pytest.raises(error_type, match=error_msg):
            client.get_alerts(from_timestamp="2022-04-29T14:00:00.000000Z")


# endregion

# region Config class tests
# =================================
# Config class tests
# =================================


class TestConfig:
    """Tests for the Config class constants."""

    def test_vendor_and_product(self) -> None:
        """Test that VENDOR and PRODUCT are set correctly."""
        assert Config.VENDOR == "SAP"
        assert Config.PRODUCT == "Threat Detection"

    def test_default_values(self) -> None:
        """Test that default configuration values are correct."""
        assert Config.DEFAULT_MAX_FETCH == 10000
        assert Config.MAX_PAGE_SIZE == 1000
        assert Config.DEFAULT_LIMIT == 50
        assert Config.DEFAULT_FIRST_FETCH == "3 days ago"

    def test_date_format(self) -> None:
        """Test that DATE_FORMAT is a valid strftime format."""
        assert Config.DATE_FORMAT == "%Y-%m-%dT%H:%M:%S.%fZ"

    def test_test_module_settings(self) -> None:
        """Test that test module settings are correct."""
        assert Config.TEST_MODULE_LOOKBACK_MINUTES == 1
        assert Config.TEST_MODULE_MAX_EVENTS == 1

    def test_max_page_size_less_than_max_fetch(self) -> None:
        """Test that MAX_PAGE_SIZE is less than or equal to DEFAULT_MAX_FETCH."""
        assert Config.MAX_PAGE_SIZE <= Config.DEFAULT_MAX_FETCH


# endregion

# region main() tests
# =================================
# main() tests
# =================================


class TestMain:
    """Tests for the main() entry point and command routing."""

    @patch("SAPETD.return_results")
    @patch("SAPETD.SAPETDClient")
    @patch("SAPETD.parse_integration_params")
    def test_test_module_command(
        self,
        mock_parse: MagicMock,
        mock_client_cls: MagicMock,
        mock_return_results: MagicMock,
        mock_params: dict[str, Any],
    ) -> None:
        """Test main() routes test-module command correctly."""
        mock_parse.return_value = {
            "base_url": "https://etd.example.com:4300",
            "username": "test_user",
            "password": "test_password",
            "verify": False,
            "proxy": False,
            "max_fetch": 10000,
        }
        mock_client = MagicMock()
        mock_client.get_alerts.return_value = []
        mock_client_cls.return_value = mock_client

        with (
            patch.object(demisto, "command", return_value="test-module"),
            patch.object(demisto, "params", return_value=mock_params),
        ):
            main()

        mock_return_results.assert_called_once()

    @patch("SAPETD.fetch_events_command")
    @patch("SAPETD.SAPETDClient")
    @patch("SAPETD.parse_integration_params")
    def test_fetch_events_command_routing(
        self,
        mock_parse: MagicMock,
        mock_client_cls: MagicMock,
        mock_fetch: MagicMock,
        mock_params: dict[str, Any],
    ) -> None:
        """Test main() routes fetch-events command correctly."""
        mock_parse.return_value = {
            "base_url": "https://etd.example.com:4300",
            "username": "test_user",
            "password": "test_password",
            "verify": False,
            "proxy": False,
            "max_fetch": 10000,
        }
        mock_client_cls.return_value = MagicMock()

        with (
            patch.object(demisto, "command", return_value="fetch-events"),
            patch.object(demisto, "params", return_value=mock_params),
        ):
            main()

        mock_fetch.assert_called_once()

    @patch("SAPETD.return_results")
    @patch("SAPETD.SAPETDClient")
    @patch("SAPETD.parse_integration_params")
    def test_get_events_command_routing(
        self,
        mock_parse: MagicMock,
        mock_client_cls: MagicMock,
        mock_return_results: MagicMock,
        mock_params: dict[str, Any],
    ) -> None:
        """Test main() routes sap-etd-get-events command correctly."""
        mock_parse.return_value = {
            "base_url": "https://etd.example.com:4300",
            "username": "test_user",
            "password": "test_password",
            "verify": False,
            "proxy": False,
            "max_fetch": 10000,
        }
        mock_client = MagicMock()
        mock_client.get_alerts.return_value = []
        mock_client_cls.return_value = mock_client

        with (
            patch.object(demisto, "command", return_value="sap-etd-get-events"),
            patch.object(demisto, "params", return_value=mock_params),
            patch.object(demisto, "args", return_value={"from_date": "3 days ago", "limit": "10", "should_push_events": "false"}),
        ):
            main()

        mock_return_results.assert_called_once()

    @patch("SAPETD.return_error")
    @patch("SAPETD.parse_integration_params")
    def test_unknown_command(
        self,
        mock_parse: MagicMock,
        mock_return_error: MagicMock,
        mock_params: dict[str, Any],
    ) -> None:
        """Test main() handles unknown command with return_error."""
        mock_parse.return_value = {
            "base_url": "https://etd.example.com:4300",
            "username": "test_user",
            "password": "test_password",
            "verify": False,
            "proxy": False,
            "max_fetch": 10000,
        }

        with (
            patch.object(demisto, "command", return_value="unknown-command"),
            patch.object(demisto, "params", return_value=mock_params),
            patch.object(demisto, "error"),
        ):
            main()

        mock_return_error.assert_called_once()
        error_msg = mock_return_error.call_args[0][0]
        assert "unknown-command" in error_msg

    @patch("SAPETD.return_error")
    def test_exception_handling(
        self,
        mock_return_error: MagicMock,
        mock_params: dict[str, Any],
    ) -> None:
        """Test main() catches exceptions and calls return_error."""
        with (
            patch.object(demisto, "command", return_value="test-module"),
            patch.object(demisto, "params", return_value={"url": ""}),
            patch.object(demisto, "error"),
        ):
            main()

        mock_return_error.assert_called_once()
        error_msg = mock_return_error.call_args[0][0]
        assert "Server URL is required" in error_msg

    @patch("SAPETD.return_error")
    def test_missing_credentials_error(
        self,
        mock_return_error: MagicMock,
    ) -> None:
        """Test main() handles missing credentials gracefully."""
        with (
            patch.object(demisto, "command", return_value="test-module"),
            patch.object(demisto, "params", return_value={"url": "https://example.com", "credentials": {}}),
            patch.object(demisto, "error"),
        ):
            main()

        mock_return_error.assert_called_once()
        error_msg = mock_return_error.call_args[0][0]
        assert "Username and Password" in error_msg


# endregion

# region Additional edge case tests
# =================================
# Additional edge case tests
# =================================


class TestEdgeCases:
    """Tests for edge cases to improve coverage."""

    @patch("SAPETD.send_events_to_xsiam")
    def test_fetch_events_missing_timestamp_in_last_event(self, mock_send: MagicMock, client: SAPETDClient) -> None:
        """Test fetch_events_command when last event has no AlertCreationTimestamp."""
        alert_no_timestamp = [{"AlertId": 9999}]
        client.get_alerts = MagicMock(return_value=alert_no_timestamp)

        with (
            patch.object(demisto, "getLastRun", return_value={}),
            patch.object(demisto, "setLastRun") as mock_set_last_run,
        ):
            fetch_events_command(client, max_fetch=Config.DEFAULT_MAX_FETCH)

        # Last run should NOT be updated since AlertCreationTimestamp is missing
        mock_set_last_run.assert_not_called()

    def test_pagination_stops_when_last_alert_missing_timestamp(self, client: SAPETDClient) -> None:
        """Test that pagination stops when last alert in batch has no AlertCreationTimestamp."""
        batch1 = [{"AlertId": i} for i in range(1, Config.MAX_PAGE_SIZE + 1)]  # No timestamps

        client.get_alerts = MagicMock(return_value=batch1)

        result = fetch_alerts_with_pagination(client, from_timestamp="2022-04-29T14:00:00.000000Z", max_alerts=2000)

        # Should stop after first batch since last alert has no timestamp
        assert len(result) == Config.MAX_PAGE_SIZE
        assert client.get_alerts.call_count == 1

    @pytest.mark.parametrize(
        "error_message, expected_substring",
        [
            pytest.param("403 Forbidden", "User lacks required application privileges", id="403_forbidden"),
            pytest.param("forbidden access denied", "User lacks required application privileges", id="forbidden_lowercase"),
        ],
    )
    def test_test_module_403_errors(self, client: SAPETDClient, error_message: str, expected_substring: str) -> None:
        """Test that 403/Forbidden errors return specific privilege error message."""
        client.get_alerts = MagicMock(side_effect=Exception(error_message))

        result = _test_module(client)

        assert expected_substring in result

    @pytest.mark.parametrize(
        "param_overrides, config_key, expected_value",
        [
            pytest.param({"insecure": True}, "verify", False, id="insecure_true_sets_verify_false"),
            pytest.param({"insecure": False}, "verify", True, id="insecure_false_sets_verify_true"),
            pytest.param({"proxy": True}, "proxy", True, id="proxy_true"),
            pytest.param({"proxy": False}, "proxy", False, id="proxy_false"),
            pytest.param({"max_fetch": "5000"}, "max_fetch", 5000, id="custom_max_fetch"),
            pytest.param({"max_fetch": "100"}, "max_fetch", 100, id="small_max_fetch"),
            pytest.param({}, "max_fetch", Config.DEFAULT_MAX_FETCH, id="default_max_fetch"),
        ],
    )
    def test_parse_integration_params_options(self, param_overrides: dict, config_key: str, expected_value: Any) -> None:
        """Test various parse_integration_params configuration options."""
        base_params: dict[str, Any] = {
            "url": "https://example.com",
            "credentials": {"identifier": "dummy_user", "password": "dummy_pass"},
        }
        base_params.update(param_overrides)
        config = parse_integration_params(base_params)
        assert config[config_key] == expected_value

    def test_integration_name_constant(self) -> None:
        """Test that INTEGRATION_NAME is set correctly."""
        assert INTEGRATION_NAME == "SAP Enterprise Threat Detection"

    @patch("SAPETD.send_events_to_xsiam")
    def test_fetch_events_subsequent_run_uses_last_fetch(self, mock_send: MagicMock, client: SAPETDClient) -> None:
        """Test that subsequent run uses last_fetch timestamp from last_run."""
        alerts = [copy.deepcopy(SAMPLE_ALERTS[0])]
        client.get_alerts = MagicMock(return_value=alerts)

        mock_last_run = {
            "last_fetch": "2022-04-29T14:20:29.682Z",
            "last_fetched_alert_ids": [],
        }

        with (
            patch.object(demisto, "getLastRun", return_value=mock_last_run),
            patch.object(demisto, "setLastRun"),
        ):
            fetch_events_command(client, max_fetch=Config.DEFAULT_MAX_FETCH)

        # Verify the client was called with the last_fetch timestamp
        call_kwargs = client.get_alerts.call_args_list[0].kwargs
        assert call_kwargs["from_timestamp"] == "2022-04-29T14:20:29.682Z"

    @patch("SAPETD.send_events_to_xsiam")
    def test_fetch_events_raw_ids_not_list(self, mock_send: MagicMock, client: SAPETDClient) -> None:
        """Test that non-list last_fetched_alert_ids is handled gracefully."""
        alerts = [copy.deepcopy(SAMPLE_ALERTS[0])]
        client.get_alerts = MagicMock(return_value=alerts)

        mock_last_run = {
            "last_fetch": "2022-04-29T14:00:00.000Z",
            "last_fetched_alert_ids": "not_a_list",  # Invalid type
        }

        with (
            patch.object(demisto, "getLastRun", return_value=mock_last_run),
            patch.object(demisto, "setLastRun"),
        ):
            # Should not raise - treats invalid type as empty list
            fetch_events_command(client, max_fetch=Config.DEFAULT_MAX_FETCH)

        mock_send.assert_called_once()

    def test_get_events_command_default_args(self, client: SAPETDClient) -> None:
        """Test get_events_command with minimal/default arguments."""
        client.get_alerts = MagicMock(return_value=[])

        result = get_events_command(client, {})

        assert isinstance(result, CommandResults)

    def test_get_events_command_readable_output_headers(self, client: SAPETDClient, sample_alerts: list[dict]) -> None:
        """Test that readable output contains expected table headers."""
        client.get_alerts = MagicMock(return_value=sample_alerts)

        args = {"from_date": "3 days ago", "limit": "50", "should_push_events": "false"}
        result = get_events_command(client, args)

        assert isinstance(result, CommandResults)
        assert "AlertId" in result.readable_output
        assert "AlertSeverity" in result.readable_output
        assert INTEGRATION_NAME in result.readable_output

    @patch("SAPETD.send_events_to_xsiam")
    def test_send_events_method(self, mock_send: MagicMock, client: SAPETDClient) -> None:
        """Test that client.send_events calls send_events_to_xsiam with correct vendor/product."""
        events = [{"AlertId": 1, "AlertCreationTimestamp": "2022-04-29T14:20:29.682Z"}]

        client.send_events(events)

        mock_send.assert_called_once_with(events=events, vendor=Config.VENDOR, product=Config.PRODUCT)

    @patch("SAPETD.send_events_to_xsiam")
    def test_send_events_empty_list(self, mock_send: MagicMock, client: SAPETDClient) -> None:
        """Test that client.send_events works with empty list."""
        client.send_events([])

        mock_send.assert_called_once_with(events=[], vendor=Config.VENDOR, product=Config.PRODUCT)

    @patch("SAPETD.SAPETDClient")
    @patch("SAPETD.parse_integration_params")
    def test_main_finally_diagnostic_report(
        self,
        mock_parse: MagicMock,
        mock_client_cls: MagicMock,
        mock_params: dict[str, Any],
    ) -> None:
        """Test that main() generates diagnostic report in finally block."""
        mock_parse.return_value = {
            "base_url": "https://etd.example.com:4300",
            "username": "test_user",
            "password": "test_password",
            "verify": False,
            "proxy": False,
            "max_fetch": 10000,
        }
        mock_client = MagicMock()
        mock_client.get_alerts.return_value = []
        mock_client_cls.return_value = mock_client

        with (
            patch.object(demisto, "command", return_value="test-module"),
            patch.object(demisto, "params", return_value=mock_params),
            patch("SAPETD.return_results"),
        ):
            main()

        # Verify diagnostic report was requested
        mock_client.get_diagnostic_report.assert_called_once()

    @patch("SAPETD.return_error")
    @patch("SAPETD.SAPETDClient")
    @patch("SAPETD.parse_integration_params")
    def test_main_finally_diagnostic_report_on_error(
        self,
        mock_parse: MagicMock,
        mock_client_cls: MagicMock,
        mock_return_error: MagicMock,
        mock_params: dict[str, Any],
    ) -> None:
        """Test that diagnostic report is generated even when command fails."""
        mock_parse.return_value = {
            "base_url": "https://etd.example.com:4300",
            "username": "test_user",
            "password": "test_password",
            "verify": False,
            "proxy": False,
            "max_fetch": 10000,
        }
        mock_client = MagicMock()
        mock_client.get_alerts.side_effect = Exception("API Error")
        mock_client_cls.return_value = mock_client

        with (
            patch.object(demisto, "command", return_value="sap-etd-get-events"),
            patch.object(demisto, "params", return_value=mock_params),
            patch.object(demisto, "args", return_value={"from_date": "3 days ago"}),
            patch.object(demisto, "error"),
        ):
            main()

        # Verify diagnostic report was still requested despite the error
        mock_client.get_diagnostic_report.assert_called_once()
        # Verify error was reported
        mock_return_error.assert_called_once()


# endregion
