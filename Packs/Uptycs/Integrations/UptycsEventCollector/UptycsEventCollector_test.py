# pylint: disable=E9010, E9011
"""Uptycs Event Collector Integration - Unit Tests
Pytest Unit Tests: all function names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing
"""

import json
import re
from datetime import datetime, timezone  # noqa: UP017
from typing import Any

import jwt
import pytest
from CommonServerPython import *
from ContentClientApiModule import ContentClientAuthenticationError

import UptycsEventCollector  # noqa: E402
from UptycsEventCollector import (  # noqa: E402
    APIKeys,
    APIValues,
    Client,
    Config,
    deduplicate_events,
    determine_entry_status,
    enrich_events_for_xsiam,
    fetch_events_command,
    fetch_events_with_pagination,
    generate_jwt_token,
    get_events_command,
    get_formatted_utc_time,
    parse_date_or_use_current,
    parse_integration_params,
    test_module,
)

# ========================================
# Constants
# ========================================

SERVER_URL = "https://test.uptycs.io/"
MOCK_API_KEY = "test-api-key-12345"
MOCK_API_SECRET = "test-api-secret-67890"
MOCK_CUSTOMER_ID = "test-customer-id-uuid"
MOCK_ROLE_ID = "test-role-id"
MOCK_SECURITY_ZONE_ID = "test-security-zone-id"
MOCK_JWT_TOKEN = "mock.jwt.token"


# ========================================
# Fixtures
# ========================================


@pytest.fixture()
def client(mocker):
    """Returns a mocked Client instance for testing.

    The client is mocked to prevent actual HTTP requests and JWT generation.
    """
    mocker.patch.object(UptycsEventCollector, "generate_jwt_token", return_value=MOCK_JWT_TOKEN)

    client_instance = Client(
        base_url=SERVER_URL,
        api_key=MOCK_API_KEY,
        api_secret=MOCK_API_SECRET,
        customer_id=MOCK_CUSTOMER_ID,
        verify=True,
        proxy=False,
    )

    mocker.patch.object(client_instance, "_http_request", return_value={"items": [], "totalCount": 0})

    return client_instance


# ========================================
# Tests: Helper Functions
# ========================================


@pytest.mark.parametrize(
    "date_string,expected_type",
    [
        ("2024-01-01T00:00:00Z", datetime),
        ("2025-09-15 17:10:00", datetime),
        ("3 days ago", datetime),
        ("1 week", datetime),
        (None, datetime),
        ("", datetime),
    ],
)
def test_parse_date_or_use_current_success(date_string: str | None, expected_type: type):
    """Tests parse_date_or_use_current returns datetime for valid inputs."""
    result = parse_date_or_use_current(date_string)
    assert isinstance(result, expected_type)
    assert result.tzinfo == timezone.utc  # noqa: UP017


def test_parse_date_or_use_current_invalid_raises():
    """Tests parse_date_or_use_current raises DemistoException for invalid date."""
    with pytest.raises(DemistoException, match="Failed to parse date string"):
        parse_date_or_use_current("invalid_date_string_12345")


@pytest.mark.parametrize(
    "date_input,expected_format_pattern",
    [
        ("2024-01-01T00:00:00Z", r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"),
        ("3 days ago", r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"),
        (None, r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"),
    ],
)
def test_get_formatted_utc_time(date_input: str | None, expected_format_pattern: str):
    """Tests get_formatted_utc_time returns properly formatted string."""
    result = get_formatted_utc_time(date_input)
    assert isinstance(result, str)
    assert re.match(expected_format_pattern, result)


# ========================================
# Tests: JWT Token Generation
# ========================================


def test_generate_jwt_token_structure():
    """Tests generate_jwt_token returns a valid JWT with 3 parts."""
    token = generate_jwt_token(MOCK_API_KEY, MOCK_API_SECRET)
    parts = token.split(".")
    assert len(parts) == 3, "JWT must have 3 parts: header.payload.signature"


def test_generate_jwt_token_header():
    """Tests generate_jwt_token includes correct header claims."""
    token = generate_jwt_token(MOCK_API_KEY, MOCK_API_SECRET)
    header = jwt.get_unverified_header(token)

    assert header["alg"] == "HS256"
    assert header["typ"] == "JWT"


@pytest.mark.parametrize(
    "role_id,security_zone_id,expected_claims,unexpected_claims",
    [
        (None, None, {"iss": MOCK_API_KEY}, ["roleId", "securityZoneId"]),
        (MOCK_ROLE_ID, None, {"iss": MOCK_API_KEY, "roleId": MOCK_ROLE_ID}, ["securityZoneId"]),
        (None, MOCK_SECURITY_ZONE_ID, {"iss": MOCK_API_KEY, "securityZoneId": MOCK_SECURITY_ZONE_ID}, ["roleId"]),
        (
            MOCK_ROLE_ID,
            MOCK_SECURITY_ZONE_ID,
            {"iss": MOCK_API_KEY, "roleId": MOCK_ROLE_ID, "securityZoneId": MOCK_SECURITY_ZONE_ID},
            [],
        ),
    ],
)
def test_generate_jwt_token_payload_claims(
    role_id: str | None,
    security_zone_id: str | None,
    expected_claims: dict[str, str],
    unexpected_claims: list[str],
):
    """Tests generate_jwt_token includes correct payload claims based on optional parameters."""
    token = generate_jwt_token(MOCK_API_KEY, MOCK_API_SECRET, role_id=role_id, security_zone_id=security_zone_id)
    payload = jwt.decode(token, MOCK_API_SECRET, algorithms=["HS256"])

    # Verify standard time claims
    assert "iat" in payload
    assert "exp" in payload
    assert payload["exp"] - payload["iat"] == Config.TOKEN_EXPIRY_SECONDS

    # Verify expected claims
    for claim, value in expected_claims.items():
        assert payload[claim] == value

    # Verify unexpected claims are absent
    for claim in unexpected_claims:
        assert claim not in payload


# ========================================
# Tests: parse_integration_params
# ========================================


@pytest.mark.parametrize(
    "params,expected_error",
    [
        ({}, r"(?i)server url is required"),
        ({"url": ""}, r"(?i)server url is required"),
        ({"url": SERVER_URL}, r"(?i)api key is required"),
        ({"url": SERVER_URL, "api_key": ""}, r"(?i)api key is required"),
        ({"url": SERVER_URL, "api_key": MOCK_API_KEY}, r"(?i)api secret is required"),
        ({"url": SERVER_URL, "api_key": MOCK_API_KEY, "credentials": {"password": ""}}, r"(?i)api secret is required"),
        (
            {"url": SERVER_URL, "api_key": MOCK_API_KEY, "credentials": {"password": MOCK_API_SECRET}},
            r"(?i)customer id is required",
        ),
        (
            {"url": SERVER_URL, "api_key": MOCK_API_KEY, "credentials": {"password": MOCK_API_SECRET}, "customer_id": ""},
            r"(?i)customer id is required",
        ),
    ],
)
def test_parse_integration_params_missing_required_fail(params: dict[str, Any], expected_error: str):
    """Tests parse_integration_params fails if required fields are missing."""
    with pytest.raises(DemistoException, match=expected_error):
        parse_integration_params(params)


@pytest.mark.parametrize(
    "params,expected_verify,expected_proxy",
    [
        (
            {
                "url": SERVER_URL,
                "api_key": MOCK_API_KEY,
                "credentials": {"password": MOCK_API_SECRET},
                "customer_id": MOCK_CUSTOMER_ID,
                "insecure": True,
                "proxy": True,
            },
            False,
            True,
        ),
        (
            {
                "url": SERVER_URL.rstrip("/"),
                "api_key": MOCK_API_KEY,
                "credentials": {"password": MOCK_API_SECRET},
                "customer_id": MOCK_CUSTOMER_ID,
                "insecure": False,
                "proxy": False,
            },
            True,
            False,
        ),
        (
            {
                "url": f"{SERVER_URL}///",
                "api_key": MOCK_API_KEY,
                "credentials": {"password": MOCK_API_SECRET},
                "customer_id": MOCK_CUSTOMER_ID,
                "insecure": False,
                "proxy": False,
            },
            True,
            False,
        ),
    ],
)
def test_parse_integration_params_success(params: dict[str, Any], expected_verify: bool, expected_proxy: bool):
    """Tests parse_integration_params handles valid configurations."""
    result = parse_integration_params(params)

    assert result["base_url"] == SERVER_URL
    assert result["verify"] == expected_verify
    assert result["proxy"] == expected_proxy
    assert result["api_key"] == MOCK_API_KEY
    assert result["api_secret"] == MOCK_API_SECRET
    assert result["customer_id"] == MOCK_CUSTOMER_ID


@pytest.mark.parametrize(
    "role_id_input,zone_id_input,expected_role_id,expected_zone_id",
    [
        (MOCK_ROLE_ID, MOCK_SECURITY_ZONE_ID, MOCK_ROLE_ID, MOCK_SECURITY_ZONE_ID),
        ("", "", None, None),
    ],
)
def test_parse_integration_params_optional_fields(
    role_id_input: str,
    zone_id_input: str,
    expected_role_id: str | None,
    expected_zone_id: str | None,
):
    """Tests parse_integration_params handles optional role_id and security_zone_id."""
    params = {
        "url": SERVER_URL,
        "api_key": MOCK_API_KEY,
        "credentials": {"password": MOCK_API_SECRET},
        "customer_id": MOCK_CUSTOMER_ID,
        "role_id": role_id_input,
        "security_zone_id": zone_id_input,
    }
    result = parse_integration_params(params)

    assert result["role_id"] == expected_role_id
    assert result["security_zone_id"] == expected_zone_id


# ========================================
# Tests: determine_entry_status
# ========================================


@pytest.mark.parametrize(
    "created_at,updated_at,expected_status",
    [
        ("2024-01-01T00:00:00Z", "2024-01-01T00:00:00Z", "new"),
        ("2024-01-01T00:00:00Z", "2024-01-02T00:00:00Z", "updated"),
        ("2024-01-01T00:00:00Z", "2024-06-15T12:30:00Z", "updated"),
    ],
)
def test_determine_entry_status(created_at: str, updated_at: str, expected_status: str):
    """Tests determine_entry_status returns correct status based on timestamps."""
    result = determine_entry_status(created_at, updated_at)
    assert result == expected_status


# ========================================
# Tests: enrich_events_for_xsiam
# ========================================


@pytest.mark.parametrize(
    "event,expected_time,expected_status",
    [
        (
            {"id": "1", "createdAt": "2024-01-01T00:00:00Z", "updatedAt": "2024-01-01T00:00:00Z"},
            "2024-01-01T00:00:00Z",
            "new",
        ),
        (
            {"id": "1", "createdAt": "2024-01-01T00:00:00Z", "updatedAt": "2024-01-02T00:00:00Z"},
            "2024-01-01T00:00:00Z",
            "updated",
        ),
        (
            {"id": "1", "createdAt": "2024-01-01T00:00:00Z"},
            "2024-01-01T00:00:00Z",
            None,
        ),
        (
            {"id": "1", "updatedAt": "2024-01-02T00:00:00Z"},
            "2024-01-02T00:00:00Z",
            None,
        ),
        (
            {"id": "1"},
            None,
            None,
        ),
    ],
)
def test_enrich_events_for_xsiam(
    event: dict[str, Any],
    expected_time: str | None,
    expected_status: str | None,
):
    """Tests enrich_events_for_xsiam sets _time and _entry_status correctly for various event shapes."""
    events: list[dict[str, Any]] = [event]
    enrich_events_for_xsiam(events)

    if expected_time:
        assert events[0]["_time"] == expected_time
    else:
        assert "_time" not in events[0]

    if expected_status:
        assert events[0]["_entry_status"] == expected_status
    else:
        assert "_entry_status" not in events[0]


def test_enrich_events_for_xsiam_multiple_events():
    """Tests enrich_events_for_xsiam processes multiple events correctly."""
    events: list[dict[str, Any]] = [
        {"id": "1", "createdAt": "2024-01-01T00:00:00Z", "updatedAt": "2024-01-01T00:00:00Z"},
        {"id": "2", "createdAt": "2024-01-01T00:00:00Z", "updatedAt": "2024-01-02T00:00:00Z"},
        {"id": "3", "updatedAt": "2024-01-03T00:00:00Z"},
    ]
    enrich_events_for_xsiam(events)

    assert events[0]["_entry_status"] == "new"
    assert events[1]["_entry_status"] == "updated"
    assert "_entry_status" not in events[2]


def test_enrich_events_for_xsiam_empty_list():
    """Tests enrich_events_for_xsiam handles empty list."""
    events: list[dict[str, Any]] = []
    enrich_events_for_xsiam(events)
    assert events == []


# ========================================
# Tests: deduplicate_events
# ========================================


@pytest.mark.parametrize(
    "events,last_fetched_ids,expected_count,expected_first_id,description",
    [
        (
            [{"id": "1", "createdAt": "2024-01-01"}, {"id": "2", "createdAt": "2024-01-02"}],
            [],
            2,
            "1",
            "first_run_no_last_ids_empty",
        ),
        ([], ["last_id"], 0, None, "empty_events"),
        (
            [
                {"id": "1", "createdAt": "2024-01-01"},
                {"id": "2", "createdAt": "2024-01-02"},
                {"id": "3", "createdAt": "2024-01-03"},
            ],
            ["1"],
            2,
            "2",
            "single_id_filtered",
        ),
        (
            [
                {"id": "1", "createdAt": "2024-01-01"},
                {"id": "2", "createdAt": "2024-01-02"},
                {"id": "3", "createdAt": "2024-01-03"},
            ],
            ["1", "2"],
            1,
            "3",
            "multiple_ids_filtered",
        ),
        (
            [
                {"id": "1", "createdAt": "2024-01-01"},
                {"id": "2", "createdAt": "2024-01-02"},
                {"id": "3", "createdAt": "2024-01-03"},
            ],
            ["1", "2", "3"],
            0,
            None,
            "all_duplicates",
        ),
        (
            [
                {"id": "4", "createdAt": "2024-01-04"},
                {"id": "5", "createdAt": "2024-01-05"},
            ],
            ["1", "2", "3"],
            2,
            "4",
            "no_matches_all_new",
        ),
        (
            [
                {"createdAt": "2024-01-01", "data": "event1"},
                {"id": "2", "createdAt": "2024-01-02"},
            ],
            ["1"],
            2,
            None,
            "events_without_id",
        ),
    ],
)
def test_deduplicate_events(
    events: list[dict[str, Any]],
    last_fetched_ids: list[str],
    expected_count: int,
    expected_first_id: str | None,
    description: str,
):
    """Tests deduplicate_events function with various scenarios."""
    result = deduplicate_events(events, last_fetched_ids)

    assert len(result) == expected_count, f"Failed for {description}"
    if expected_first_id:
        assert result[0]["id"] == expected_first_id


def test_deduplicate_events_preserves_order():
    """Tests that deduplicate_events preserves event order."""
    events = [
        {"id": "1", "createdAt": "2024-01-01", "data": "first"},
        {"id": "2", "createdAt": "2024-01-02", "data": "second"},
        {"id": "3", "createdAt": "2024-01-03", "data": "third"},
        {"id": "4", "createdAt": "2024-01-04", "data": "fourth"},
    ]

    result = deduplicate_events(events, ["1", "2"])

    assert len(result) == 2
    assert result[0]["id"] == "3"
    assert result[0]["data"] == "third"
    assert result[1]["id"] == "4"
    assert result[1]["data"] == "fourth"


# ========================================
# Tests: Client Initialization
# ========================================


def test_client_initialization(client: Client):
    """Tests Client initialization."""
    assert client.customer_id == MOCK_CUSTOMER_ID
    assert client._base_url == SERVER_URL


def test_client_initialization_with_optional_params(mocker):
    """Tests Client initialization with role_id and security_zone_id."""
    mocker.patch.object(UptycsEventCollector, "generate_jwt_token", return_value=MOCK_JWT_TOKEN)

    client_instance = Client(
        base_url=SERVER_URL,
        api_key=MOCK_API_KEY,
        api_secret=MOCK_API_SECRET,
        customer_id=MOCK_CUSTOMER_ID,
        verify=True,
        proxy=False,
        role_id=MOCK_ROLE_ID,
        security_zone_id=MOCK_SECURITY_ZONE_ID,
    )

    assert client_instance.customer_id == MOCK_CUSTOMER_ID
    UptycsEventCollector.generate_jwt_token.assert_called_once_with(  # type: ignore[attr-defined]
        api_key=MOCK_API_KEY,
        api_secret=MOCK_API_SECRET,
        role_id=MOCK_ROLE_ID,
        security_zone_id=MOCK_SECURITY_ZONE_ID,
    )


# ========================================
# Tests: Client.get_alerts
# ========================================


def test_get_alerts_success(mocker, client: Client):
    """Tests get_alerts returns items and count from API response."""
    mock_items = [
        {"id": "alert1", "createdAt": "2024-01-01T00:00:00Z"},
        {"id": "alert2", "createdAt": "2024-01-02T00:00:00Z"},
    ]
    mocker.patch.object(client, "_http_request", return_value={"items": mock_items})

    items = client.get_alerts(created_after="2024-01-01T00:00:00", created_before="2024-01-03T00:00:00")

    assert len(items) == 2
    assert items[0]["id"] == "alert1"


def test_get_alerts_empty_response(mocker, client: Client):
    """Tests get_alerts handles empty response."""
    mocker.patch.object(client, "_http_request", return_value={"items": []})

    items = client.get_alerts(created_after="2024-01-01T00:00:00", created_before="2024-01-03T00:00:00")

    assert len(items) == 0


def test_get_alerts_with_date_range(mocker, client: Client):
    """Tests get_alerts passes correct parameters for date range."""
    mock_http = mocker.patch.object(client, "_http_request", return_value={"items": []})

    client.get_alerts(
        created_after="2024-01-01T00:00:00",
        created_before="2024-01-02T00:00:00",
        offset=10,
        limit=50,
    )

    call_kwargs = mock_http.call_args[1]
    assert call_kwargs["method"] == "GET"
    assert MOCK_CUSTOMER_ID in call_kwargs["url_suffix"]

    params = call_kwargs["params"]
    assert params[APIKeys.OFFSET] == 10
    assert params[APIKeys.LIMIT] == 50
    assert params[APIKeys.SORT] == APIValues.DEFAULT_SORT

    filters = json.loads(params[APIKeys.FILTERS])
    assert "lastOccurredAt" in filters
    assert filters["lastOccurredAt"]["between"] == ["2024-01-01T00:00:00", "2024-01-02T00:00:00"]


# ========================================
# Tests: fetch_events_with_pagination
# ========================================


def test_fetch_events_with_pagination_single_page(mocker, client: Client):
    """Tests fetch_events_with_pagination with single page of results."""
    mock_events = [{"id": f"event{i}", "createdAt": f"2024-01-0{i}T00:00:00Z"} for i in range(1, 4)]

    mocker.patch.object(client, "get_alerts", return_value=mock_events)

    events = fetch_events_with_pagination(client, "2024-01-01T00:00:00", None, 10)

    assert len(events) == 3
    assert events[0]["id"] == "event1"


def test_fetch_events_with_pagination_multiple_pages(mocker, client: Client):
    """Tests fetch_events_with_pagination handles multiple pages."""
    mocker.patch.object(Config, "MAX_PAGE_SIZE", 3)
    page1 = [{"id": f"event{i}", "createdAt": f"2024-01-0{i}T00:00:00Z"} for i in range(1, 4)]
    page2 = [{"id": f"event{i}", "createdAt": f"2024-01-0{i}T00:00:00Z"} for i in range(4, 6)]

    mock_get_alerts = mocker.patch.object(
        client,
        "get_alerts",
        side_effect=[page1, page2],
    )

    events = fetch_events_with_pagination(client, "2024-01-01T00:00:00", None, 10)

    assert len(events) == 5
    assert mock_get_alerts.call_count == 2


def test_fetch_events_with_pagination_stops_at_max(mocker, client: Client):
    """Tests fetch_events_with_pagination stops at max_events."""
    mocker.patch.object(Config, "MAX_PAGE_SIZE", 5)
    page1 = [{"id": f"event{i}", "createdAt": f"2024-01-{i:02d}T00:00:00Z"} for i in range(1, 6)]
    page2 = [{"id": f"event{i}", "createdAt": f"2024-01-{i:02d}T00:00:00Z"} for i in range(6, 9)]

    mocker.patch.object(
        client,
        "get_alerts",
        side_effect=[page1, page2],
    )

    events = fetch_events_with_pagination(client, "2024-01-01T00:00:00", None, 7)

    assert len(events) == 7


def test_fetch_events_with_pagination_empty_page(mocker, client: Client):
    """Tests fetch_events_with_pagination handles empty page."""
    mocker.patch.object(client, "get_alerts", return_value=[])

    events = fetch_events_with_pagination(client, "2024-01-01T00:00:00", None, 10)

    assert len(events) == 0


def test_fetch_events_with_pagination_preserves_api_order(mocker, client: Client):
    """Tests fetch_events_with_pagination preserves the ascending order returned by the API."""
    mock_events = [
        {"id": "event1", "createdAt": "2024-01-01T00:00:00Z"},
        {"id": "event2", "createdAt": "2024-01-02T00:00:00Z"},
        {"id": "event3", "createdAt": "2024-01-03T00:00:00Z"},
    ]

    mocker.patch.object(client, "get_alerts", return_value=mock_events)

    events = fetch_events_with_pagination(client, "2024-01-01T00:00:00", None, 10)

    assert events[0]["id"] == "event1"
    assert events[1]["id"] == "event2"
    assert events[2]["id"] == "event3"


def test_fetch_events_with_pagination_slices_excess_events(mocker, client: Client):
    """Tests fetch_events_with_pagination slices excess events."""
    mocker.patch.object(Config, "MAX_PAGE_SIZE", 10)
    page1 = [{"id": f"event{i}", "createdAt": f"2024-01-{i:02d}T00:00:00Z"} for i in range(1, 11)]
    page2 = [{"id": f"event{i}", "createdAt": f"2024-01-{i:02d}T00:00:00Z"} for i in range(11, 16)]

    mocker.patch.object(
        client,
        "get_alerts",
        side_effect=[page1, page2],
    )

    events = fetch_events_with_pagination(client, "2024-01-01T00:00:00", None, 12)

    assert len(events) == 12
    assert events[0]["id"] == "event1"
    assert events[-1]["id"] == "event12"


@pytest.mark.parametrize(
    "created_after,created_before",
    [
        ("2024-01-01T00:00:00", None),
        ("2024-01-01T00:00:00", "2024-01-02T00:00:00"),
    ],
)
def test_fetch_events_with_pagination_date_parameters(mocker, client: Client, created_after: str, created_before: str | None):
    """Tests fetch_events_with_pagination passes date parameters correctly."""
    mock_get_alerts = mocker.patch.object(client, "get_alerts", return_value=[])

    fetch_events_with_pagination(client, created_after, created_before, 10)

    call_kwargs = mock_get_alerts.call_args[1]
    assert call_kwargs["created_after"] == created_after
    if created_before is not None:
        assert call_kwargs["created_before"] == created_before
    else:
        # When None is passed, fetch_events_with_pagination pins it to current UTC time
        assert call_kwargs["created_before"] is not None


def test_fetch_events_with_pagination_pins_created_before(mocker, client: Client):
    """Tests fetch_events_with_pagination uses the same created_before across all pages when None is passed."""
    mocker.patch.object(Config, "MAX_PAGE_SIZE", 2)
    page1 = [{"id": "event1"}, {"id": "event2"}]
    page2 = [{"id": "event3"}]

    mock_get_alerts = mocker.patch.object(client, "get_alerts", side_effect=[page1, page2])

    fetch_events_with_pagination(client, "2024-01-01T00:00:00", None, 10)

    # Verify get_alerts was called twice (two pages)
    assert mock_get_alerts.call_count == 2

    # Verify the same created_before was used for both calls
    first_call_created_before = mock_get_alerts.call_args_list[0][1]["created_before"]
    second_call_created_before = mock_get_alerts.call_args_list[1][1]["created_before"]
    assert first_call_created_before == second_call_created_before
    assert first_call_created_before is not None


# ========================================
# Tests: test_module Command
# ========================================


@pytest.mark.parametrize(
    "should_succeed,mock_return,mock_exception,expected_result",
    [
        (True, [{"id": "test"}], None, "ok"),
        (
            False,
            None,
            ContentClientAuthenticationError("Auth failed"),
            "Authorization Error: Verify API Key, API Secret, and Customer ID.",
        ),
        (False, None, DemistoException("Error [500] - Internal Server Error"), None),
    ],
)
def test_test_module_command(
    mocker,
    client: Client,
    should_succeed: bool,
    mock_return: list[dict[str, Any]] | None,
    mock_exception: Exception | None,
    expected_result: str | None,
):
    """Tests test_module returns 'ok' on success, auth error message, or raises other errors."""
    if should_succeed:
        mocker.patch.object(UptycsEventCollector, "fetch_events_with_pagination", return_value=mock_return)
        result = test_module(client)
        assert result == expected_result
    elif expected_result:
        mocker.patch.object(UptycsEventCollector, "fetch_events_with_pagination", side_effect=mock_exception)
        result = test_module(client)
        assert result == expected_result
    else:
        mocker.patch.object(UptycsEventCollector, "fetch_events_with_pagination", side_effect=mock_exception)
        with pytest.raises(DemistoException, match=r"(?i)internal server error"):
            test_module(client)


# ========================================
# Tests: get_events_command
# ========================================


def test_get_events_command_success(mocker, client: Client):
    """Tests get_events_command returns correct CommandResults when should_push_events=False."""
    mock_events = [{"id": "123", "alertRuleName": "test_rule", "createdAt": "2024-01-01T00:00:00Z"}]

    mocker.patch.object(UptycsEventCollector, "fetch_events_with_pagination", return_value=mock_events)

    args = {"start_time": "3 days ago", "limit": "10", "should_push_events": "false"}
    result = get_events_command(client, args)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "Uptycs.Alert"
    assert result.outputs_key_field == "id"
    assert result.outputs == mock_events


def test_get_events_command_with_push_events(mocker, client: Client):
    """Tests get_events_command pushes events to XSIAM when should_push_events=True."""
    mock_events = [
        {"id": "123", "alertRuleName": "test_rule", "createdAt": "2024-01-01T00:00:00Z", "updatedAt": "2024-01-01T00:00:00Z"}
    ]

    mocker.patch.object(UptycsEventCollector, "fetch_events_with_pagination", return_value=mock_events)
    mocker.patch.object(UptycsEventCollector, "enrich_events_for_xsiam")
    mocker.patch.object(UptycsEventCollector, "send_events_to_xsiam")

    args = {"start_time": "3 days ago", "limit": "10", "should_push_events": "true"}
    result = get_events_command(client, args)

    assert isinstance(result, str)
    assert "1" in result
    UptycsEventCollector.enrich_events_for_xsiam.assert_called_once_with(mock_events)  # type: ignore[attr-defined]
    UptycsEventCollector.send_events_to_xsiam.assert_called_once_with(  # type: ignore[attr-defined]
        events=mock_events, vendor=Config.VENDOR, product=Config.PRODUCT
    )


def test_get_events_command_default_values(mocker, client: Client):
    """Tests get_events_command uses default values."""
    mocker.patch.object(UptycsEventCollector, "fetch_events_with_pagination", return_value=[])

    result = get_events_command(client, {})

    assert isinstance(result, CommandResults)
    assert result.outputs == []


def test_get_events_command_with_end_time(mocker, client: Client):
    """Tests get_events_command handles end_time parameter."""
    mock_fetch = mocker.patch.object(UptycsEventCollector, "fetch_events_with_pagination", return_value=[])

    args = {"start_time": "1 hour ago", "end_time": "now", "should_push_events": "false"}
    result = get_events_command(client, args)

    assert isinstance(result, CommandResults)
    call_args = mock_fetch.call_args
    assert call_args[0][2] is not None  # created_before


def test_get_events_command_no_push_when_empty(mocker, client: Client):
    """Tests get_events_command does not push when no events and should_push_events=True."""
    mocker.patch.object(UptycsEventCollector, "fetch_events_with_pagination", return_value=[])
    mock_send = mocker.patch.object(UptycsEventCollector, "send_events_to_xsiam")

    args = {"start_time": "1 hour ago", "should_push_events": "true"}
    result = get_events_command(client, args)

    assert isinstance(result, CommandResults)
    mock_send.assert_not_called()


def test_get_events_command_invalid_start_time(client: Client):
    """Tests get_events_command raises DemistoException for an unparseable start_time."""
    args = {"start_time": "not_a_valid_date_12345", "limit": "10"}
    with pytest.raises(DemistoException, match="Failed to parse date string"):
        get_events_command(client, args)


# ========================================
# Tests: fetch_events_command
# ========================================


@pytest.mark.parametrize(
    "test_case,last_run,params,mock_events,expected_last_run_time,expected_events_count",
    [
        (
            "first_run",
            {},
            {"max_fetch": 100},
            [
                {
                    "id": "1",
                    "createdAt": "2024-01-01T00:00:00Z",
                    "lastOccurredAt": "2024-01-01T00:00:00Z",
                    "updatedAt": "2024-01-01T00:00:00Z",
                },
                {
                    "id": "2",
                    "createdAt": "2024-01-02T00:00:00Z",
                    "lastOccurredAt": "2024-01-02T00:00:00Z",
                    "updatedAt": "2024-01-02T00:00:00Z",
                },
            ],
            "2024-01-02T00:00:00Z",
            2,
        ),
        (
            "with_last_run",
            {"last_fetch": "2024-01-01T00:00:00", "last_fetched_ids": []},
            {"max_fetch": 100},
            [
                {
                    "id": "3",
                    "createdAt": "2024-01-03T00:00:00Z",
                    "lastOccurredAt": "2024-01-03T00:00:00Z",
                    "updatedAt": "2024-01-03T00:00:00Z",
                },
            ],
            "2024-01-03T00:00:00Z",
            1,
        ),
    ],
)
def test_fetch_events_command_scenarios(
    mocker,
    client: Client,
    test_case: str,
    last_run: dict[str, Any],
    params: dict[str, Any],
    mock_events: list[dict[str, Any]],
    expected_last_run_time: str,
    expected_events_count: int,
):
    """Tests fetch_events_command under various scenarios."""
    mocker.patch.object(demisto, "getLastRun", return_value=last_run)
    mocker.patch.object(demisto, "setLastRun")
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(UptycsEventCollector, "fetch_events_with_pagination", return_value=mock_events)
    mocker.patch.object(UptycsEventCollector, "enrich_events_for_xsiam")
    mocker.patch.object(UptycsEventCollector, "send_events_to_xsiam")

    fetch_events_command(client)

    demisto.setLastRun.assert_called_once()  # type: ignore[attr-defined]
    call_args = demisto.setLastRun.call_args[0][0]  # type: ignore[attr-defined]
    assert call_args["last_fetch"] == expected_last_run_time

    UptycsEventCollector.enrich_events_for_xsiam.assert_called_once()  # type: ignore[attr-defined]
    UptycsEventCollector.send_events_to_xsiam.assert_called_once_with(  # type: ignore[attr-defined]
        events=mock_events, vendor=Config.VENDOR, product=Config.PRODUCT
    )


def test_fetch_events_command_with_deduplication(mocker, client: Client):
    """Tests fetch_events_command deduplicates events based on last_fetched_ids."""
    mock_events = [
        {
            "id": "1",
            "createdAt": "2024-01-01T00:00:00Z",
            "lastOccurredAt": "2024-01-01T00:00:00Z",
            "updatedAt": "2024-01-01T00:00:00Z",
        },
        {
            "id": "2",
            "createdAt": "2024-01-01T00:00:00Z",
            "lastOccurredAt": "2024-01-01T00:00:00Z",
            "updatedAt": "2024-01-01T00:00:00Z",
        },
        {
            "id": "3",
            "createdAt": "2024-01-02T00:00:00Z",
            "lastOccurredAt": "2024-01-02T00:00:00Z",
            "updatedAt": "2024-01-02T00:00:00Z",
        },
    ]

    mocker.patch.object(demisto, "getLastRun", return_value={"last_fetch": "2024-01-01T00:00:00", "last_fetched_ids": ["1", "2"]})
    mocker.patch.object(demisto, "setLastRun")
    mocker.patch.object(demisto, "params", return_value={"max_fetch": 100})
    mocker.patch.object(UptycsEventCollector, "fetch_events_with_pagination", return_value=mock_events)
    mocker.patch.object(UptycsEventCollector, "enrich_events_for_xsiam")
    mocker.patch.object(UptycsEventCollector, "send_events_to_xsiam")

    fetch_events_command(client)

    # Only event 3 should be sent (events 1 and 2 are duplicates)
    expected_new_events = [mock_events[2]]
    UptycsEventCollector.enrich_events_for_xsiam.assert_called_once_with(expected_new_events)  # type: ignore[attr-defined]


def test_fetch_events_command_all_duplicates(mocker, client: Client):
    """Tests fetch_events_command when all fetched events are duplicates."""
    mock_events = [
        {"id": "1", "createdAt": "2024-01-01T00:00:00Z", "lastOccurredAt": "2024-01-01T00:00:00Z"},
        {"id": "2", "createdAt": "2024-01-01T00:00:00Z", "lastOccurredAt": "2024-01-01T00:00:00Z"},
    ]

    mocker.patch.object(demisto, "getLastRun", return_value={"last_fetch": "2024-01-01T00:00:00", "last_fetched_ids": ["1", "2"]})
    mocker.patch.object(demisto, "setLastRun")
    mocker.patch.object(demisto, "params", return_value={"max_fetch": 100})
    mocker.patch.object(UptycsEventCollector, "fetch_events_with_pagination", return_value=mock_events)
    mocker.patch.object(UptycsEventCollector, "enrich_events_for_xsiam")
    mocker.patch.object(UptycsEventCollector, "send_events_to_xsiam")

    fetch_events_command(client)

    # No events sent to XSIAM (all duplicates)
    UptycsEventCollector.enrich_events_for_xsiam.assert_not_called()  # type: ignore[attr-defined]
    UptycsEventCollector.send_events_to_xsiam.assert_not_called()  # type: ignore[attr-defined]


def test_fetch_events_command_no_events(mocker, client: Client):
    """Tests fetch_events_command when no events are fetched."""
    mocker.patch.object(demisto, "getLastRun", return_value={})
    mocker.patch.object(demisto, "setLastRun")
    mocker.patch.object(demisto, "params", return_value={})
    mocker.patch.object(UptycsEventCollector, "fetch_events_with_pagination", return_value=[])
    mocker.patch.object(UptycsEventCollector, "send_events_to_xsiam")

    fetch_events_command(client)

    UptycsEventCollector.send_events_to_xsiam.assert_not_called()  # type: ignore[attr-defined]


def test_fetch_events_command_no_events_first_run_saves_state(mocker, client: Client):
    """Tests fetch_events_command saves state on first run even with no events."""
    mocker.patch.object(demisto, "getLastRun", return_value={})
    mocker.patch.object(demisto, "setLastRun")
    mocker.patch.object(demisto, "params", return_value={})
    mocker.patch.object(UptycsEventCollector, "fetch_events_with_pagination", return_value=[])

    fetch_events_command(client)

    demisto.setLastRun.assert_called_once()  # type: ignore[attr-defined]
    call_args = demisto.setLastRun.call_args[0][0]  # type: ignore[attr-defined]
    assert "last_fetch" in call_args
    assert call_args["last_fetched_ids"] == []


def test_fetch_events_command_multiple_events_same_last_occurred_at(mocker, client: Client):
    """Tests fetch_events_command collects IDs at the last_fetch timestamp."""
    mock_events = [
        {
            "id": "1",
            "createdAt": "2024-01-01T00:00:00Z",
            "lastOccurredAt": "2024-01-01T00:00:00Z",
            "updatedAt": "2024-01-01T00:00:00Z",
        },
        {
            "id": "2",
            "createdAt": "2024-01-01T00:00:00Z",
            "lastOccurredAt": "2024-01-01T00:00:00Z",
            "updatedAt": "2024-01-01T00:00:00Z",
        },
        {
            "id": "3",
            "createdAt": "2024-01-01T00:00:00Z",
            "lastOccurredAt": "2024-01-01T00:00:00Z",
            "updatedAt": "2024-01-01T00:00:00Z",
        },
    ]

    mocker.patch.object(demisto, "getLastRun", return_value={})
    mocker.patch.object(demisto, "setLastRun")
    mocker.patch.object(demisto, "params", return_value={"max_fetch": 100})
    mocker.patch.object(UptycsEventCollector, "fetch_events_with_pagination", return_value=mock_events)
    mocker.patch.object(UptycsEventCollector, "enrich_events_for_xsiam")
    mocker.patch.object(UptycsEventCollector, "send_events_to_xsiam")

    fetch_events_command(client)

    call_args = demisto.setLastRun.call_args[0][0]  # type: ignore[attr-defined]
    assert call_args["last_fetch"] == "2024-01-01T00:00:00Z"
    assert sorted(call_args["last_fetched_ids"]) == ["1", "2", "3"]


def test_fetch_events_command_missing_last_occurred_at_no_state_update(mocker, client: Client):
    """Tests fetch_events_command does not update state when last event is missing lastOccurredAt."""
    mock_events = [
        {"id": "1", "createdAt": "2024-01-01T00:00:00Z", "updatedAt": "2024-01-01T00:00:00Z"},
    ]

    mocker.patch.object(demisto, "getLastRun", return_value={})
    mocker.patch.object(demisto, "setLastRun")
    mocker.patch.object(demisto, "params", return_value={"max_fetch": 100})
    mocker.patch.object(UptycsEventCollector, "fetch_events_with_pagination", return_value=mock_events)
    mocker.patch.object(UptycsEventCollector, "enrich_events_for_xsiam")
    mocker.patch.object(UptycsEventCollector, "send_events_to_xsiam")

    fetch_events_command(client)

    # Events should still be sent to XSIAM
    UptycsEventCollector.send_events_to_xsiam.assert_called_once()  # type: ignore[attr-defined]

    # setLastRun should NOT be called since lastOccurredAt is missing
    demisto.setLastRun.assert_not_called()  # type: ignore[attr-defined]


def test_fetch_events_command_last_fetch_uses_last_occurred_at_not_created_at(mocker, client: Client):
    """Tests fetch_events_command sets last_fetch from lastOccurredAt, not createdAt, when they differ."""
    mock_events = [
        {
            "id": "1",
            "createdAt": "2024-01-01T00:00:00Z",
            "lastOccurredAt": "2024-01-10T00:00:00Z",
            "updatedAt": "2024-01-10T00:00:00Z",
        },
        {
            "id": "2",
            "createdAt": "2024-01-05T00:00:00Z",
            "lastOccurredAt": "2024-01-15T00:00:00Z",
            "updatedAt": "2024-01-15T00:00:00Z",
        },
    ]

    mocker.patch.object(demisto, "getLastRun", return_value={})
    mocker.patch.object(demisto, "setLastRun")
    mocker.patch.object(demisto, "params", return_value={"max_fetch": 100})
    mocker.patch.object(UptycsEventCollector, "fetch_events_with_pagination", return_value=mock_events)
    mocker.patch.object(UptycsEventCollector, "enrich_events_for_xsiam")
    mocker.patch.object(UptycsEventCollector, "send_events_to_xsiam")

    fetch_events_command(client)

    call_args = demisto.setLastRun.call_args[0][0]  # type: ignore[attr-defined]
    # last_fetch should be from lastOccurredAt of the last event, NOT createdAt
    assert call_args["last_fetch"] == "2024-01-15T00:00:00Z"
    assert call_args["last_fetch"] != "2024-01-05T00:00:00Z"  # createdAt of last event
    assert call_args["last_fetched_ids"] == ["2"]


# ========================================
# Tests: Main Function
# ========================================


def test_main_invalid_command_fail(mocker, capfd):
    """Tests main() raises error for invalid command."""
    with capfd.disabled():
        mocker.patch.object(demisto, "command", return_value="invalid-command")
        mocker.patch.object(
            demisto,
            "params",
            return_value={
                "url": SERVER_URL,
                "api_key": MOCK_API_KEY,
                "credentials": {"password": MOCK_API_SECRET},
                "customer_id": MOCK_CUSTOMER_ID,
            },
        )
        mocker.patch.object(demisto, "args", return_value={})
        mocker.patch.object(UptycsEventCollector, "generate_jwt_token", return_value=MOCK_JWT_TOKEN)

        mock_return_error = mocker.patch("UptycsEventCollector.return_error")

        UptycsEventCollector.main()

        mock_return_error.assert_called_once()
        error_call_args = mock_return_error.call_args[0][0]
        assert re.search(r"invalid-command", error_call_args, re.IGNORECASE)
        assert re.search(r"not implemented", error_call_args, re.IGNORECASE)


@pytest.mark.parametrize(
    "command_name",
    [
        "test-module",
        "uptycs-get-events",
        "fetch-events",
    ],
)
def test_main_command_success(mocker, command_name: str):
    """Tests main() executes supported commands successfully."""
    mocker.patch.object(demisto, "command", return_value=command_name)
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "url": SERVER_URL,
            "api_key": MOCK_API_KEY,
            "credentials": {"password": MOCK_API_SECRET},
            "customer_id": MOCK_CUSTOMER_ID,
        },
    )
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(demisto, "getLastRun", return_value={})
    mocker.patch.object(UptycsEventCollector, "generate_jwt_token", return_value=MOCK_JWT_TOKEN)
    mocker.patch.object(UptycsEventCollector, "fetch_events_with_pagination", return_value=[])
    mock_return_results = mocker.patch("UptycsEventCollector.return_results")

    UptycsEventCollector.main()

    if command_name in ("test-module", "uptycs-get-events"):
        mock_return_results.assert_called_once()


def test_main_command_execution_error(mocker, capfd):
    """Tests main() handles command execution errors gracefully."""
    with capfd.disabled():
        mocker.patch.object(demisto, "command", return_value="uptycs-get-events")
        mocker.patch.object(
            demisto,
            "params",
            return_value={
                "url": SERVER_URL,
                "api_key": MOCK_API_KEY,
                "credentials": {"password": MOCK_API_SECRET},
                "customer_id": MOCK_CUSTOMER_ID,
            },
        )
        mocker.patch.object(demisto, "args", return_value={})
        mocker.patch.object(UptycsEventCollector, "generate_jwt_token", return_value=MOCK_JWT_TOKEN)
        mocker.patch.object(UptycsEventCollector, "fetch_events_with_pagination", side_effect=Exception("API Error"))

        mock_return_error = mocker.patch("UptycsEventCollector.return_error")

        UptycsEventCollector.main()

        mock_return_error.assert_called_once()
        error_message = mock_return_error.call_args[0][0]
        assert re.search(r"uptycs-get-events", error_message, re.IGNORECASE)


def test_main_parse_params_error(mocker, capfd):
    """Tests main() handles parameter parsing errors."""
    with capfd.disabled():
        mocker.patch.object(demisto, "command", return_value="test-module")
        mocker.patch.object(demisto, "params", return_value={})
        mocker.patch.object(demisto, "args", return_value={})

        mock_return_error = mocker.patch("UptycsEventCollector.return_error")

        UptycsEventCollector.main()

        mock_return_error.assert_called_once()
        error_message = mock_return_error.call_args[0][0]
        assert re.search(r"(server url|api key|api secret|customer id) is required", error_message, re.IGNORECASE)
