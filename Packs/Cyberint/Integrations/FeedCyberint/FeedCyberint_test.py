from datetime import datetime, timedelta
import re
from unittest import mock
from unittest.mock import MagicMock, patch

import FeedCyberint
import pytest
from CommonServerPython import DemistoException

date_time = "2025-01-01"

BASE_URL = "https://feed-example.com"
REQUEST_URL1 = f"{BASE_URL}/ioc/api/v1/feed/daily/{date_time}?limit=1000&offset=0"
REQUEST_URL2 = f"{BASE_URL}/ioc/api/v1/feed/daily/{date_time}?limit=1000&offset=1000"
REQUEST_URL3 = f"{BASE_URL}/ioc/api/v1/feed/daily/{date_time}?limit=20000&offset=0"
REQUEST_URL4 = f"{BASE_URL}/ioc/api/v1/feed/daily/{date_time}?limit=20000&offset=20000"
REQUEST_URL5 = f"{BASE_URL}/ioc/api/v1/feed/daily/{date_time}?limit=20&offset=0"
REQUEST_URL6 = f"{BASE_URL}/ioc/api/v1/url?value=http://dummy.com"
REQUEST_URL7 = f"{BASE_URL}/ioc/api/v1/ipv4?value=1.1.1.1"
REQUEST_URL8 = f"{BASE_URL}/ioc/api/v1/domain?value=dummy.com"
REQUEST_URL9 = f"{BASE_URL}/ioc/api/v1/v1/file/sha256?value=6a7b02c43837dcb8e40d271edb88d13d2e723c721a74931857aaef4853317789"
TOKEN = "example_token"


def load_mock_response() -> str:
    """Load mock file that simulates an API response.

    Returns:
        str: Mock file content.
    """
    with open("test_data/indicators.jsonb") as file:
        return file.read()


def load_mock_empty_response() -> str:
    """Load mock file that simulates an API response.

    Returns:
        str: Mock file content.
    """
    with open("test_data/empty.jsonb") as file:
        return file.read()


def load_mock_url_response() -> str:
    """Load mock file that simulates an API response.

    Returns:
        str: Mock file content.
    """
    with open("test_data/url.json") as file:
        return file.read()


def load_mock_ipv4_response() -> str:
    """Load mock file that simulates an API response.

    Returns:
        str: Mock file content.
    """
    with open("test_data/ipv4.json") as file:
        return file.read()


def load_mock_file_sha256_response() -> str:
    """Load mock file that simulates an API response.

    Returns:
        str: Mock file content.
    """
    with open("test_data/file_sha256.json") as file:
        return file.read()


def load_mock_domain_response() -> str:
    """Load mock file that simulates an API response.

    Returns:
        str: Mock file content.
    """
    with open("test_data/domain.json") as file:
        return file.read()


@pytest.fixture()
def mock_client() -> FeedCyberint.Client:
    """
    Establish a mock connection to the client with access token.

    Returns:
        Client: Mock connection to client.
    """
    return FeedCyberint.Client(
        base_url=BASE_URL,
        access_token=TOKEN,
        verify=False,
        proxy=False,
    )


@mock.patch("FeedCyberint.is_execution_time_exceeded")
def test_build_iterator(
    is_execution_time_exceeded_mock,
    requests_mock,
    mock_client: FeedCyberint.Client,
):
    """
    Scenario:
    - Test retrieving a list IOCs from Cyberint feed.

    Given:
    - mock_client.

    When:
    - Called the build_iterator request (this request called by all integration commands).

    Then:
    - Ensure that the IP values is correct.
    - Ensure that the URL values is correct.
    """
    is_execution_time_exceeded_mock.return_value = False

    response1 = load_mock_response()
    response2 = load_mock_empty_response()

    requests_mock.get(REQUEST_URL1, text=response1)
    requests_mock.get(REQUEST_URL2, text=response2)

    with (
        patch.object(mock_client, "request_daily_feed", return_value=response1),
        patch("CommonServerPython.auto_detect_indicator_type") as mock_auto_detect,
    ):
        mock_auto_detect.side_effect = lambda x: "IP" if x == "1.1.1.1" else None
        indicators = mock_client.request_daily_feed()

        assert indicators is not None


@mock.patch("FeedCyberint.is_execution_time_exceeded")
def test_get_indicators_command(
    is_execution_time_exceeded_mock,
    mock_client,
    requests_mock,
):
    """
    Scenario:
    - Test retrieving indicators by filters from feed.

    Given:
    - mock_client.

    When:
    - Called the get_indicators_command.

    Then:
    - Ensure that the IP values is correct.
    - Ensure that the URL values is correct.
    """
    is_execution_time_exceeded_mock.return_value = False

    response1 = load_mock_response()
    response2 = load_mock_empty_response()

    requests_mock.get(REQUEST_URL5, text=response1)
    requests_mock.get(REQUEST_URL6, text=response2)

    args = {"date": date_time, "limit": 20, "offset": 0}

    with (
        patch.object(FeedCyberint, "get_indicators_command", return_value=response1),
        patch("CommonServerPython.auto_detect_indicator_type") as mock_auto_detect,
    ):
        mock_auto_detect.side_effect = lambda x: "IP" if x == "1.1.1.1" else None
        result = FeedCyberint.get_indicators_command(mock_client, args)

        assert result == response1


@mock.patch("FeedCyberint.is_execution_time_exceeded")
def test_get_url_command(
    is_execution_time_exceeded_mock,
    mock_client,
    requests_mock,
):
    """
    Scenario:
    - Test retrieving URL information from feed.

    Given:
    - mock_client.

    When:
    - Called the get_url_command.

    Then:
    - Ensure that the response is correct.
    """
    is_execution_time_exceeded_mock.return_value = False

    response1 = load_mock_url_response()
    response2 = load_mock_empty_response()

    requests_mock.get(REQUEST_URL6, text=response1)
    requests_mock.get(REQUEST_URL6, text=response2)

    args = {"value": "http://dummy.com"}

    with (
        patch.object(FeedCyberint, "get_url_command", return_value=response1),
        patch("CommonServerPython.auto_detect_indicator_type") as mock_auto_detect,
    ):
        mock_auto_detect.side_effect = lambda x: "URL" if x == "http://dummy.com" else None
        result = FeedCyberint.get_url_command(mock_client, args)

        assert result == response1


@mock.patch("FeedCyberint.is_execution_time_exceeded")
def test_get_ipv4_command(
    is_execution_time_exceeded_mock,
    mock_client,
    requests_mock,
):
    """
    Scenario:
    - Test retrieving IPv4 information from feed.

    Given:
    - mock_client.

    When:
    - Called the get_ipv4_command.

    Then:
    - Ensure that the response is correct.
    """
    is_execution_time_exceeded_mock.return_value = False

    response1 = load_mock_ipv4_response()
    response2 = load_mock_empty_response()

    requests_mock.get(REQUEST_URL7, text=response1)
    requests_mock.get(REQUEST_URL7, text=response2)

    args = {"value": "1.1.1.1"}

    with (
        patch.object(FeedCyberint, "get_ipv4_command", return_value=response1),
        patch("CommonServerPython.auto_detect_indicator_type") as mock_auto_detect,
    ):
        mock_auto_detect.side_effect = lambda x: "IP" if x == "1.1.1.1" else None
        result = FeedCyberint.get_ipv4_command(mock_client, args)

        assert result == response1


@mock.patch("FeedCyberint.is_execution_time_exceeded")
def test_get_domain_command(
    is_execution_time_exceeded_mock,
    mock_client,
    requests_mock,
):
    """
    Scenario:
    - Test retrieving Domain information from feed.

    Given:
    - mock_client.

    When:
    - Called the get_domain_command.

    Then:
    - Ensure that the response is correct.
    """
    is_execution_time_exceeded_mock.return_value = False

    response1 = load_mock_domain_response()
    response2 = load_mock_empty_response()

    requests_mock.get(REQUEST_URL8, text=response1)
    requests_mock.get(REQUEST_URL8, text=response2)

    args = {"value": "dummy.com"}

    with (
        patch.object(FeedCyberint, "get_domain_command", return_value=response1),
        patch("CommonServerPython.auto_detect_indicator_type") as mock_auto_detect,
    ):
        mock_auto_detect.side_effect = lambda x: "Domain" if x == "dummy.com" else None
        result = FeedCyberint.get_domain_command(mock_client, args)

        assert result == response1


@patch("FeedCyberint.tableToMarkdown")
def test_get_domain_command_with_invalid_arg(mock_client):
    """Test get_domain_command when value argument is invalid."""

    err_msg = (
        "1 validation error for Request\nquery -> value\n  string does not match regex "
        '"^(?:(?:(?:[[a-z0-9](?:[a-z0-9\\-]*[a-z0-9])?)\\.))*(?:[a-z0-9][a-z0-9\\-]*[a-z0-9])$" '
        "(type=value_error.str.regex; pattern="
        "^(?:(?:(?:[[a-z0-9](?:[a-z0-9\\-]*[a-z0-9])?)\\.))*(?:[a-z0-9][a-z0-9\\-]*[a-z0-9])$)"
    )

    # Mock args input with invalid value
    args = {"value": "@"}

    mock_client.retrieve_domain_from_api.side_effect = TypeError(err_msg)

    # Call the function
    with pytest.raises(TypeError, match=re.escape(err_msg)):
        FeedCyberint.get_domain_command(mock_client, args)


@patch("FeedCyberint.tableToMarkdown")
def test_get_url_command_with_invalid_arg(mock_client):
    """Test get_url_command when value argument is invalid."""

    err_msg = "1 validation error for Request\nquery -> value\n  invalid or missing URL scheme (type=value_error.url.scheme)"

    # Mock args input with invalid value
    args = {"value": "@"}

    mock_client.retrieve_url_from_api.side_effect = TypeError(err_msg)

    # Call the function
    with pytest.raises(TypeError, match=re.escape(err_msg)):
        FeedCyberint.get_url_command(mock_client, args)


@patch("FeedCyberint.tableToMarkdown")
def test_get_ipv4_command_with_invalid_arg(mock_client):
    """Test get_ipv4_command when value argument is invalid."""

    err_msg = "1 validation error for Request\nquery -> value\n  value is not a valid IPv4 address (type=value_error.ipv4address)"

    # Mock args input with invalid value
    args = {"value": "@"}

    mock_client.retrieve_ipv4_from_api.side_effect = TypeError(err_msg)

    # Call the function
    with pytest.raises(TypeError, match=re.escape(err_msg)):
        FeedCyberint.get_ipv4_command(mock_client, args)


@patch("FeedCyberint.tableToMarkdown")
def test_get_file_sha256_command_with_invalid_arg(mock_client):
    """Test get_file_sha256_command when value argument is invalid."""

    err_msg = (
        "1 validation error for Request\nquery -> value\n  string does not match regex "
        '"^[a-f0-9]{64}$" (type=value_error.str.regex; pattern=^[a-f0-9]{64}$)'
    )

    # Mock args input with invalid value
    args = {"value": "@"}

    mock_client.retrieve_file_sha256_from_api.side_effect = TypeError(err_msg)

    # Call the function
    with pytest.raises(TypeError, match=re.escape(err_msg)):
        FeedCyberint.get_file_sha256_command(mock_client, args)


@mock.patch("FeedCyberint.is_execution_time_exceeded")
def test_get_file_sha256_command(
    is_execution_time_exceeded_mock,
    mock_client,
    requests_mock,
):
    """
    Scenario:
    - Test retrieving File SHA256 information from feed.

    Given:
    - mock_client.

    When:
    - Called the get_file_sha256_command.

    Then:
    - Ensure that the response is correct.
    """
    is_execution_time_exceeded_mock.return_value = False

    response1 = load_mock_file_sha256_response()
    response2 = load_mock_file_sha256_response()

    requests_mock.get(REQUEST_URL8, text=response1)
    requests_mock.get(REQUEST_URL8, text=response2)

    args = {"value": "6a7b02c43837dcb8e40d271edb88d13d2e723c721a74931857aaef4853317789"}

    with (
        patch.object(FeedCyberint, "get_file_sha256_command", return_value=response1),
        patch("CommonServerPython.auto_detect_indicator_type") as mock_auto_detect,
    ):
        mock_auto_detect.side_effect = (
            lambda x: "File" if x == "6a7b02c43837dcb8e40d271edb88d13d2e723c721a74931857aaef4853317789" else None
        )
        result = FeedCyberint.get_file_sha256_command(mock_client, args)

        assert result == response1


@mock.patch("FeedCyberint.is_execution_time_exceeded")
def test_fetch_indicators_command_ok(is_execution_time_exceeded_mock, mock_client: FeedCyberint.Client, requests_mock):
    """
    Scenario:
    - Test retrieving indicators by filters from feed.

    Given:
    - mock_client.

    When:
    - Called the fetch_indicators_command.

    Then:
    - Ensure that the IP values is correct.
    - Ensure that the URL values is correct.
    """
    is_execution_time_exceeded_mock.return_value = False

    response1 = load_mock_response()
    response2 = load_mock_empty_response()

    requests_mock.get(REQUEST_URL3, text=response1)
    requests_mock.get(REQUEST_URL4, text=response2)

    with (
        patch.object(FeedCyberint, "fetch_indicators_command", return_value=response1),
        patch("CommonServerPython.auto_detect_indicator_type") as mock_auto_detect,
    ):
        mock_auto_detect.side_effect = lambda x: "IP" if x == "1.1.1.1" else None
        result = FeedCyberint.fetch_indicators_command(mock_client, {})  # pass empty params dict

        assert result is not None


def test_ioc_header_transformer():
    """
    Test the ioc_header_transformer function to ensure it correctly transforms headers.
    """
    # Test predefined headers
    assert FeedCyberint.ioc_header_transformer("detected_activity") == "Detected activity"
    assert FeedCyberint.ioc_header_transformer("ioc_type") == "IoC type"
    assert FeedCyberint.ioc_header_transformer("ioc_value") == "IoC value"
    assert FeedCyberint.ioc_header_transformer("observation_date") == "Observation date"
    assert FeedCyberint.ioc_header_transformer("severity_score") == "Severity score"
    assert FeedCyberint.ioc_header_transformer("confidence") == "Confidence"
    assert FeedCyberint.ioc_header_transformer("description") == "Description"

    # Test fallback case with a mock
    with patch("FeedCyberint.string_to_table_header") as mock_string_to_table_header:
        mock_string_to_table_header.return_value = "Fallback Header"
        result = FeedCyberint.ioc_header_transformer("custom_header")
        mock_string_to_table_header.assert_called_once_with("custom_header")
        assert result == "Fallback Header"


def test_indicator_header_transformer():
    """
    Test the indicator_header_transformer function to ensure it correctly transforms headers.
    """
    # Test predefined headers
    assert FeedCyberint.indicator_header_transformer("type") == "Type"
    assert FeedCyberint.indicator_header_transformer("value") == "Value"
    assert FeedCyberint.indicator_header_transformer("malicious_score") == "Malicious score"
    assert FeedCyberint.indicator_header_transformer("detected_activities") == "Detected activities"
    assert FeedCyberint.indicator_header_transformer("related_entities") == "Related entities"
    assert FeedCyberint.indicator_header_transformer("filenames") == "Filenames"
    assert FeedCyberint.indicator_header_transformer("first_seen") == "First seen"
    assert FeedCyberint.indicator_header_transformer("download_urls") == "Download URLs"
    assert FeedCyberint.indicator_header_transformer("benign") == "Benign"
    assert FeedCyberint.indicator_header_transformer("observation_date") == "Observation date"
    assert FeedCyberint.indicator_header_transformer("occurrences_count") == "Occurrences count"
    assert FeedCyberint.indicator_header_transformer("ips") == "IPs"
    assert FeedCyberint.indicator_header_transformer("registrant_name") == "Whois registrant name"
    assert FeedCyberint.indicator_header_transformer("registrant_email") == "Whois registrant email"
    assert FeedCyberint.indicator_header_transformer("registrant_organization") == "Whois registrant organization"
    assert FeedCyberint.indicator_header_transformer("registrant_country") == "Whois registrant country"
    assert FeedCyberint.indicator_header_transformer("registrant_telephone") == "Whois registrant telephone"
    assert FeedCyberint.indicator_header_transformer("technical_contact_email") == "Whois technical contact email"
    assert FeedCyberint.indicator_header_transformer("technical_contact_name") == "Whois technical contact name"
    assert FeedCyberint.indicator_header_transformer("technical_contact_organization") == "Whois technical contact organization"
    assert FeedCyberint.indicator_header_transformer("registrar_name") == "Whois registrar name"
    assert FeedCyberint.indicator_header_transformer("admin_contact_name") == "Whois admin contact name"
    assert FeedCyberint.indicator_header_transformer("admin_contact_organization") == "Whois admin contact organization"
    assert FeedCyberint.indicator_header_transformer("admin_contact_email") == "Whois admin contact email"
    assert FeedCyberint.indicator_header_transformer("created_date") == "Created date"
    assert FeedCyberint.indicator_header_transformer("updated_date") == "Updated date"
    assert FeedCyberint.indicator_header_transformer("expiration_date") == "Expiration date"
    assert FeedCyberint.indicator_header_transformer("hostname") == "Hostname"
    assert FeedCyberint.indicator_header_transformer("domain") == "Domain"
    assert FeedCyberint.indicator_header_transformer("asn_number") == "ASN number"
    assert FeedCyberint.indicator_header_transformer("asn_organization") == "ASN organization"

    # Test fallback case with a mock
    with patch("FeedCyberint.string_to_table_header") as mock_string_to_table_header:
        mock_string_to_table_header.return_value = "Fallback Header"
        result = FeedCyberint.indicator_header_transformer("custom_header")
        mock_string_to_table_header.assert_called_once_with("custom_header")
        assert result == "Fallback Header"


def test_is_execution_time_exceeded_within_limit():
    """
    Test is_execution_time_exceeded when execution time is within the timeout limit.
    """
    # Use now to create a naive datetime consistent with implementation (datetime.now())
    start_time = datetime.now() - timedelta(seconds=5)  # Well within 20 minute (1200s) timeout
    result = FeedCyberint.is_execution_time_exceeded(start_time)
    assert result is False, "Execution time is within the limit but returned True."


def test_is_execution_time_exceeded_exceeded_limit():
    """
    Test is_execution_time_exceeded when execution time exceeds the timeout limit.
    """
    start_time = datetime.now() - timedelta(seconds=FeedCyberint.EXECUTION_TIMEOUT_SECONDS + 10)  # Exceeds timeout
    result = FeedCyberint.is_execution_time_exceeded(start_time)
    assert result is True, "Execution time exceeded the limit but returned False."


@patch("FeedCyberint.datetime")
def test_is_execution_time_exceeded_mocked(mock_datetime):
    """
    Test is_execution_time_exceeded with mocked datetime to simulate precise timing.
    Patch now() instead of utcnow() to match implementation.
    """
    # Preserve ability to construct new datetime objects
    mock_datetime.side_effect = lambda *args, **kwargs: datetime(*args, **kwargs)
    base_time = datetime(2024, 1, 1, 12, 0, 0)

    # Simulate time just over the limit
    mock_datetime.now.return_value = base_time + timedelta(seconds=FeedCyberint.EXECUTION_TIMEOUT_SECONDS + 1)
    result = FeedCyberint.is_execution_time_exceeded(base_time)
    assert result is True, "Execution time exceeded the limit but returned False."

    # Simulate time well within the limit
    mock_datetime.now.return_value = base_time + timedelta(seconds=5)
    result = FeedCyberint.is_execution_time_exceeded(base_time)
    assert result is False, "Execution time is within the limit but returned True."


def test_get_yesterday_time():
    """
    Test the get_yesterday_time function to ensure it returns the correct date for yesterday.
    """
    # Define a mock current time
    mock_now = datetime(2024, 12, 27, 15, 0, 0)  # Example fixed time

    # Patch datetime.now to return the mock_now
    with patch("FeedCyberint.datetime") as mock_datetime:
        mock_datetime.now.return_value = mock_now
        mock_datetime.side_effect = lambda *args, **kw: datetime(*args, **kw)

        # Call the function
        result = FeedCyberint.get_yesterday_time()

    # Expected result
    expected_yesterday = (mock_now - timedelta(days=1)).strftime(FeedCyberint.DATE_FORMAT)

    # Assert the result matches the expected value
    assert result == expected_yesterday, f"Expected {expected_yesterday}, got {result}"


@patch("FeedCyberint.datetime")
def test_is_x_minutes_ago_yesterday_true(mock_datetime):
    """Test when x minutes ago falls on yesterday."""
    # Mock current datetime to Jan 2, 2025, 00:05 AM
    mock_datetime.now.return_value = datetime(2025, 1, 2, 0, 5)
    mock_datetime.side_effect = lambda *args, **kwargs: datetime(*args, **kwargs)

    assert FeedCyberint.is_x_minutes_ago_yesterday(10) is True


@patch("FeedCyberint.datetime")
def test_is_x_minutes_ago_yesterday_false_same_day(mock_datetime):
    """Test when x minutes ago is still today."""
    # Mock current datetime to Jan 2, 2025, 12:10 AM
    mock_datetime.now.return_value = datetime(2025, 1, 2, 12, 10)
    mock_datetime.side_effect = lambda *args, **kwargs: datetime(*args, **kwargs)

    assert FeedCyberint.is_x_minutes_ago_yesterday(5) is False


@patch("FeedCyberint.datetime")
def test_is_x_minutes_ago_yesterday_false_future(mock_datetime):
    """Test edge case when x minutes ago would result in a future date."""
    # Mock current datetime to Jan 1, 2025, 11:59 PM
    mock_datetime.now.return_value = datetime(2025, 1, 1, 23, 59)
    mock_datetime.side_effect = lambda *args, **kwargs: datetime(*args, **kwargs)

    assert FeedCyberint.is_x_minutes_ago_yesterday(-5) is False


@patch("FeedCyberint.datetime")
def test_is_x_minutes_ago_yesterday_edge_case(mock_datetime):
    """Test edge case when x minutes ago is exactly the last second of yesterday."""
    # Mock current datetime to Jan 2, 2025, 00:00 AM
    mock_datetime.now.return_value = datetime(2025, 1, 2, 0, 0)
    mock_datetime.side_effect = lambda *args, **kwargs: datetime(*args, **kwargs)

    assert FeedCyberint.is_x_minutes_ago_yesterday(1) is True


def test_retrieve_indicators_from_api_success(mock_client, requests_mock):
    """Test retrieve_indicators_from_api with a successful response."""

    date_time = "2025-01-01"
    limit = 100
    offset = 0
    mock_response = '{"ioc_value": "example.com"}\n{"ioc_value": "malicious.com"}'

    # Mock the HTTP request
    url_suffix = f"/ioc/api/v1/feed/daily/{date_time}?limit={limit}&offset={offset}"
    requests_mock.get(
        f"{BASE_URL}{url_suffix}",
        text=mock_response,
        status_code=200,
    )

    response = FeedCyberint.Client.retrieve_indicators_from_api(mock_client, date_time, limit, offset)

    assert response == mock_response


def test_retrieve_indicators_from_api_failure(mock_client, requests_mock):
    """Test retrieve_indicators_from_api with an HTTP error."""

    date_time = "2025-01-01"
    limit = 100
    offset = 0

    # Mock the HTTP request to return a 500 error
    url_suffix = f"/ioc/api/v1/feed/daily/{date_time}?limit={limit}&offset={offset}"
    requests_mock.get(
        f"{BASE_URL}{url_suffix}",
        status_code=500,
        text="Internal Server Error",
    )

    with pytest.raises(DemistoException):
        FeedCyberint.Client.retrieve_indicators_from_api(mock_client, date_time, limit, offset)


def test_retrieve_indicators_from_api_timeout(mock_client, requests_mock):
    """Test retrieve_indicators_from_api with a timeout."""

    date_time = "2025-01-01"
    limit = 100
    offset = 0

    # Mock the HTTP request to simulate a timeout
    url_suffix = f"/ioc/api/v1/feed/daily/{date_time}?limit={limit}&offset={offset}"
    requests_mock.get(
        f"{BASE_URL}{url_suffix}",
        exc=TimeoutError("Request timed out"),
    )

    with pytest.raises(TimeoutError):
        FeedCyberint.Client.retrieve_indicators_from_api(mock_client, date_time, limit, offset)


def test_retrieve_indicators_from_api_invalid_response(mock_client, requests_mock):
    """Test retrieve_indicators_from_api with an invalid response."""

    date_time = "2025-01-01"
    limit = 100
    offset = 0
    mock_response = "Invalid JSON response"

    # Mock the HTTP request
    url_suffix = f"/ioc/api/v1/feed/daily/{date_time}?limit={limit}&offset={offset}"
    requests_mock.get(
        f"{BASE_URL}{url_suffix}",
        text=mock_response,
        status_code=200,
    )

    response = FeedCyberint.Client.retrieve_indicators_from_api(mock_client, date_time, limit, offset)

    assert response == mock_response


def test_test_module_forbidden_error(mock_client):
    """Test test_module with a forbidden error."""
    # Mock `request_daily_feed` to raise a DemistoException with FORBIDDEN status
    exception = DemistoException("Forbidden")
    exception.res = MagicMock(status_code=403)
    mock_client.request_daily_feed = MagicMock(side_effect=exception)

    result = FeedCyberint.test_module(mock_client, feed_enabled=True)

    assert result == "Authorization Error: invalid `API Token`"
    mock_client.request_daily_feed.assert_called_once_with(limit=10, test=True)


def test_test_module_unexpected_error(mock_client):
    """Test test_module with an unexpected error."""
    # Mock `request_daily_feed` to raise a generic DemistoException
    exception = DemistoException("Unexpected error")
    FeedCyberint.Client.request_daily_feed = MagicMock(side_effect=exception)

    with pytest.raises(DemistoException, match="Unexpected error"):
        FeedCyberint.test_module(mock_client, feed_enabled=True)

    FeedCyberint.Client.request_daily_feed.assert_called_once_with(limit=10, test=True)


@patch("FeedCyberint.datetime")
def test_get_today_time(mock_datetime):
    """Test get_today_time to ensure it returns the correct formatted date."""
    # Define a fixed datetime for testing
    fixed_datetime = datetime(2025, 1, 2, 12, 30, 45)
    mock_datetime.now.return_value = fixed_datetime

    # Call the function
    result = FeedCyberint.get_today_time()

    # Assert the result matches the expected formatted string
    assert result == fixed_datetime.strftime(FeedCyberint.DATE_FORMAT)
    mock_datetime.now.assert_called_once()


@patch("FeedCyberint.fetch_indicators")
@patch("FeedCyberint.get_yesterday_time")
@patch("FeedCyberint.is_x_minutes_ago_yesterday")
def test_fetch_indicators_command(mock_is_x_minutes_ago_yesterday, mock_get_yesterday_time, mock_fetch_indicators, mock_client):
    """Test fetch_indicators_command function."""
    # Mock parameters
    params = {
        "tlp_color": "RED",
        "feedTags": "tag1,tag2",
        "severity_from": "2",
        "confidence_from": "50",
        "feed_name": "feed1,feed2",
        "indicator_type": "IP,Domain",
        "feedFetchInterval": "1440",
    }

    # Mock return values for the helper functions
    mock_is_x_minutes_ago_yesterday.return_value = True
    mock_get_yesterday_time.return_value = "2024-12-31T00:00:00Z"
    mock_fetch_indicators.side_effect = [
        [{"indicator": "192.168.1.1", "type": "IP"}],
        [{"indicator": "example.com", "type": "Domain"}],
    ]

    # Call the function
    result = FeedCyberint.fetch_indicators_command(mock_client, params)

    # Assertions
    assert len(result) == 2
    assert result[0]["indicator"] == "192.168.1.1"
    assert result[0]["type"] == "IP"
    assert result[1]["indicator"] == "example.com"
    assert result[1]["type"] == "Domain"

    # Verify helper function calls
    mock_is_x_minutes_ago_yesterday.assert_called_once_with(1440)
    mock_get_yesterday_time.assert_called_once()
    assert mock_fetch_indicators.call_count == 2
    mock_fetch_indicators.assert_any_call(
        client=mock_client,
        date_time="2024-12-31T00:00:00Z",
        tlp_color="RED",
        feed_tags=["tag1", "tag2"],
        feed_names=["feed1", "feed2"],
        indicator_types=["IP", "Domain"],
        severity_from=2,
        confidence_from=50,
    )
    mock_fetch_indicators.assert_any_call(
        client=mock_client,
        tlp_color="RED",
        feed_tags=["tag1", "tag2"],
        feed_names=["feed1", "feed2"],
        indicator_types=["IP", "Domain"],
        severity_from=2,
        confidence_from=50,
    )


@patch("FeedCyberint.demisto")
def test_main_test_module(mock_demisto, mock_client):
    """Test main() with the 'test-module' command."""
    # Mock parameters and command
    mock_demisto.params.return_value = {
        "url": "https://example.com",
        "access_token": {"password": "test-token"},
        "insecure": False,
        "proxy": False,
    }
    mock_demisto.command.return_value = "test-module"

    # Mock test_module
    mock_test_module = MagicMock()
    mock_test_module.return_value = "ok"

    # Replace test_module with mock
    with patch("FeedCyberint.test_module", mock_test_module):
        FeedCyberint.main()

    # Assertions
    mock_test_module.assert_called_once()


@patch("FeedCyberint.demisto")
def test_main_get_indicators(mock_demisto, mock_client):
    """Test main() with the 'cyberint-get-indicators' command."""
    # Mock parameters and command
    mock_demisto.params.return_value = {
        "url": "https://example.com",
        "access_token": {"password": "test-token"},
        "insecure": False,
        "proxy": False,
    }
    mock_demisto.command.return_value = "cyberint-get-indicators"
    mock_demisto.args.return_value = {"arg1": "value1"}

    # Mock get_indicators_command
    mock_get_indicators_command = MagicMock()
    mock_get_indicators_command.return_value = "indicator-results"

    # Replace get_indicators_command with mock
    with patch("FeedCyberint.get_indicators_command", mock_get_indicators_command):
        FeedCyberint.main()


@patch("FeedCyberint.demisto")
def test_main_get_url(mock_demisto, mock_client):
    """Test main() with the 'cyberint-get-url' command."""
    # Mock parameters and command
    mock_demisto.params.return_value = {
        "url": "https://example.com",
        "access_token": {"password": "test-token"},
        "insecure": False,
        "proxy": False,
    }
    mock_demisto.command.return_value = "cyberint-get-url"
    mock_demisto.args.return_value = {"arg1": "http://dummy.com"}

    # Mock get_url_command
    mock_get_url_command = MagicMock()
    mock_get_url_command.return_value = "url-results"

    # Replace get_url_command with mock
    with patch("FeedCyberint.get_url_command", mock_get_url_command):
        FeedCyberint.main()


@patch("FeedCyberint.demisto")
def test_main_get_domain(mock_demisto, mock_client):
    """Test main() with the 'cyberint-get-domain' command."""
    # Mock parameters and command
    mock_demisto.params.return_value = {
        "url": "https://example.com",
        "access_token": {"password": "test-token"},
        "insecure": False,
        "proxy": False,
    }
    mock_demisto.command.return_value = "cyberint-get-domain"
    mock_demisto.args.return_value = {"arg1": "dummy.com"}

    # Mock get_domain_command
    mock_get_domain_command = MagicMock()
    mock_get_domain_command.return_value = "domain-results"

    # Replace get_domain_command with mock
    with patch("FeedCyberint.get_domain_command", mock_get_domain_command):
        FeedCyberint.main()


@patch("FeedCyberint.demisto")
def test_main_get_ipv4(mock_demisto, mock_client):
    """Test main() with the 'cyberint-get-ipv4' command."""
    # Mock parameters and command
    mock_demisto.params.return_value = {
        "url": "https://example.com",
        "access_token": {"password": "test-token"},
        "insecure": False,
        "proxy": False,
    }
    mock_demisto.command.return_value = "cyberint-get-ipv4"
    mock_demisto.args.return_value = {"arg1": "1.1.1.1"}

    # Mock get_ipv4_command
    mock_get_ipv4_command = MagicMock()
    mock_get_ipv4_command.return_value = "ipv4-results"

    # Replace get_ipv4_command with mock
    with patch("FeedCyberint.get_ipv4_command", mock_get_ipv4_command):
        FeedCyberint.main()


@patch("FeedCyberint.demisto")
def test_main_get_file_sha256(mock_demisto, mock_client):
    """Test main() with the 'cyberint-get-file-sha256' command."""
    # Mock parameters and command
    mock_demisto.params.return_value = {
        "url": "https://example.com",
        "access_token": {"password": "test-token"},
        "insecure": False,
        "proxy": False,
    }
    mock_demisto.command.return_value = "cyberint-get-file-sha256"
    mock_demisto.args.return_value = {"arg1": "6a7b02c43837dcb8e40d271edb88d13d2e723c721a74931857aaef4853317789"}

    # Mock get_file_sha256_command
    mock_get_file_sha256_command = MagicMock()
    mock_get_file_sha256_command.return_value = "file-sha256-results"

    # Replace get_file_sha256_command with mock
    with patch("FeedCyberint.get_file_sha256_command", mock_get_file_sha256_command):
        FeedCyberint.main()


@patch("FeedCyberint.demisto")
def test_main_fetch_indicators(mock_demisto, mock_client):
    """Test main() with the 'fetch-indicators' command."""
    # Mock parameters and command
    mock_demisto.params.return_value = {
        "url": "https://example.com",
        "access_token": {"password": "test-token"},
        "insecure": False,
        "proxy": False,
    }
    mock_demisto.command.return_value = "fetch-indicators"

    # Mock fetch_indicators_command and batch
    mock_fetch_indicators_command = MagicMock()
    mock_fetch_indicators_command.return_value = [{"indicator1": "value1"}, {"indicator2": "value2"}]

    mock_batch = MagicMock()
    mock_batch.side_effect = lambda indicators, batch_size: [indicators[:batch_size]]

    with patch("FeedCyberint.fetch_indicators_command", mock_fetch_indicators_command), patch("FeedCyberint.batch", mock_batch):
        FeedCyberint.main()

    # Assertions
    mock_batch.assert_called_once_with([{"indicator1": "value1"}, {"indicator2": "value2"}], batch_size=5000)
    mock_demisto.createIndicators.assert_called_once_with([{"indicator1": "value1"}, {"indicator2": "value2"}])


@patch("FeedCyberint.demisto")
@patch("FeedCyberint.Client.retrieve_indicators_from_api")
def test_process_feed_response_valid(mock_demisto, mock_client):
    """Test process_feed_response with valid JSON and valid indicators."""

    # Mock auto_detect_indicator_type
    mock_auto_detect = MagicMock(return_value=True)
    with patch("FeedCyberint.auto_detect_indicator_type", mock_auto_detect):
        result = mock_client.process_feed_response("2025-01-01", 100, 0)

    assert len(result) == 0


@patch("FeedCyberint.demisto")
@patch("FeedCyberint.Client.retrieve_indicators_from_api")
def test_process_feed_response_invalid_json(mock_retrieve_indicators, mock_demisto, mock_client):
    """Test process_feed_response with invalid JSON."""
    # Mock invalid JSON response from retrieve_indicators_from_api
    mock_response = '{"ioc_value": "indicator1"}\n{invalid json}'
    mock_retrieve_indicators.return_value = mock_response

    # Mock demisto.error to capture error logs
    mock_demisto.error = MagicMock()

    result = mock_client.process_feed_response("2025-01-01", 100, 0)

    # Assertions
    assert result == []  # Should return an empty list on failure


@patch("FeedCyberint.demisto")
@patch("FeedCyberint.Client.retrieve_indicators_from_api")
def test_process_feed_response_no_indicators(mock_retrieve_indicators, mock_demisto, mock_client):
    """Test process_feed_response when no indicators are returned."""
    # Mock response with no indicators
    mock_response = ""
    mock_retrieve_indicators.return_value = mock_response

    result = mock_client.process_feed_response("2025-01-01", 100, 0)

    # Assertions
    assert result == []  # Should return an empty list if no indicators


@patch("FeedCyberint.demisto")
@patch("FeedCyberint.Client.retrieve_indicators_from_api")
def test_process_feed_response_valid_but_no_matching_indicators(mock_retrieve_indicators, mock_demisto, mock_client):
    """Test process_feed_response with valid JSON, but no matching indicators."""
    # Mock valid JSON response with non-matching indicators
    mock_response = '{"ioc_value": "invalid_indicator"}\n{"ioc_value": "another_invalid_indicator"}'
    mock_retrieve_indicators.return_value = mock_response

    # Mock auto_detect_indicator_type to return False for all values
    mock_auto_detect = MagicMock(return_value=False)
    with patch("FeedCyberint.auto_detect_indicator_type", mock_auto_detect):
        result = mock_client.process_feed_response("2025-01-01", 100, 0)

    # Assertions
    mock_retrieve_indicators.assert_called_once_with("2025-01-01", 100, 0)
    mock_auto_detect.assert_any_call("invalid_indicator")
    mock_auto_detect.assert_any_call("another_invalid_indicator")
    assert result == []  # Should return an empty list since no valid indicators matched


@patch("FeedCyberint.demisto")
@patch("FeedCyberint.Client.retrieve_indicators_from_api")
def test_process_feed_response_valid_with_matching_indicators(mock_retrieve_indicators, mock_demisto, mock_client):
    """Test process_feed_response with valid JSON and matching indicators."""
    # Mock valid JSON response with matching indicators
    mock_response = '{"ioc_value": "valid_indicator"}\n{"ioc_value": "another_valid_indicator"}'
    mock_retrieve_indicators.return_value = mock_response

    # Mock auto_detect_indicator_type to return True for all values
    mock_auto_detect = MagicMock(return_value=True)
    with patch("FeedCyberint.auto_detect_indicator_type", mock_auto_detect):
        result = mock_client.process_feed_response("2025-01-01", 100, 0)

    # Assertions
    mock_retrieve_indicators.assert_called_once_with("2025-01-01", 100, 0)
    mock_auto_detect.assert_any_call("valid_indicator")
    mock_auto_detect.assert_any_call("another_valid_indicator")
    assert len(result) == 2
    assert result[0]["ioc_value"] == "valid_indicator"
    assert result[1]["ioc_value"] == "another_valid_indicator"


@patch("FeedCyberint.tableToMarkdown")
def test_get_indicators_command_with_invalid_limit(mock_client):
    """Test get_indicators_command when the limit argument is invalid."""

    # Mock args input with invalid limit
    args = {"date": "2025-01-01", "limit": None, "offset": 0}

    # Call the function, limit should be parsed as 0

    with pytest.raises(
        TypeError, match=r"int\(\) argument must be a string, a bytes-like object or a real number, not 'NoneType'"
    ):
        FeedCyberint.get_indicators_command(mock_client, args)


def test_process_feed_response_wrong_data(mock_client, requests_mock, capfd):
    with capfd.disabled():
        date_time = "2025-01-02"
        limit = 10
        offset = 0
        mock_response = "test"

        # Mock the HTTP request
        url_suffix = f"/ioc/api/v1/feed/daily/{date_time}?limit={limit}&offset={offset}"
        requests_mock.get(
            f"{BASE_URL}{url_suffix}",
            text=mock_response,
            status_code=200,
        )

        # Call the method with test data
        mock_auto_detect = MagicMock(return_value=True)
        with patch("FeedCyberint.auto_detect_indicator_type", mock_auto_detect):
            result = FeedCyberint.Client.process_feed_response(mock_client, date_time="2025-01-02", limit=10, offset=0)

        # Assert that the result is an empty list (i.e., no indicators found)
        assert result == []


def test_get_indicators_command_ok(mock_client, requests_mock):
    expected_output = "Human-readable Markdown output"
    date_time = "2025-01-02"
    limit = 10
    offset = 0

    # Mock the response from process_feed_response
    mock_response = "[{'detected_activity': 'activity_1}]"

    # Mock the HTTP request
    url_suffix = f"/ioc/api/v1/feed/daily/{date_time}?limit={limit}&offset={offset}"
    requests_mock.get(
        f"{BASE_URL}{url_suffix}",
        text=mock_response,
        status_code=200,
    )

    with (
        patch.object(FeedCyberint, "get_indicators_command", return_value=expected_output),
        patch("CommonServerPython.tableToMarkdown"),
    ):
        # Define the arguments for the command
        args = {"date": "2025-01-02", "limit": 2, "offset": 0}

        # Call the function
        result = FeedCyberint.get_indicators_command(mock_client, args)

        # Validate the CommandResults
        assert result == expected_output


def test_test_module_feed_enabled_success(mock_client):
    """Test test_module with feed_enabled=True and successful request_daily_feed call."""
    # Mock successful request_daily_feed
    mock_client.request_daily_feed = MagicMock(return_value=[])

    result = FeedCyberint.test_module(mock_client, feed_enabled=True)

    assert result == "ok"
    mock_client.request_daily_feed.assert_called_once_with(limit=10, test=True)


def test_test_module_feed_disabled_success(mock_client):
    """Test test_module with feed_enabled=False and successful retrieve_domain_from_api call."""
    # Mock successful retrieve_domain_from_api
    mock_client.retrieve_domain_from_api = MagicMock(return_value={})

    result = FeedCyberint.test_module(mock_client, feed_enabled=False)

    assert result == "ok"
    mock_client.retrieve_domain_from_api.assert_called_once_with("checkpoint.com")


def test_test_module_feed_enabled_unauthorized_error(mock_client):
    """Test test_module with feed_enabled=True and unauthorized error."""
    # Mock `request_daily_feed` to raise a DemistoException with UNAUTHORIZED status
    exception = DemistoException("Unauthorized")
    exception.res = MagicMock(status_code=401)
    mock_client.request_daily_feed = MagicMock(side_effect=exception)

    result = FeedCyberint.test_module(mock_client, feed_enabled=True)

    assert result == "Authorization Error: invalid `API Token`"
    mock_client.request_daily_feed.assert_called_once_with(limit=10, test=True)


def test_test_module_feed_enabled_forbidden_error(mock_client):
    """Test test_module with feed_enabled=True and forbidden error."""
    # Mock `request_daily_feed` to raise a DemistoException with FORBIDDEN status
    exception = DemistoException("Forbidden")
    exception.res = MagicMock(status_code=403)
    mock_client.request_daily_feed = MagicMock(side_effect=exception)

    result = FeedCyberint.test_module(mock_client, feed_enabled=True)

    assert result == "Authorization Error: invalid `API Token`"
    mock_client.request_daily_feed.assert_called_once_with(limit=10, test=True)


def test_test_module_feed_disabled_unauthorized_error(mock_client):
    """Test test_module with feed_enabled=False and unauthorized error."""
    # Mock `retrieve_domain_from_api` to raise a DemistoException with UNAUTHORIZED status
    exception = DemistoException("Unauthorized")
    exception.res = MagicMock(status_code=401)
    mock_client.retrieve_domain_from_api = MagicMock(side_effect=exception)

    result = FeedCyberint.test_module(mock_client, feed_enabled=False)

    assert result == "Authorization Error: invalid `API Token`"
    mock_client.retrieve_domain_from_api.assert_called_once_with("checkpoint.com")


def test_test_module_feed_disabled_forbidden_error(mock_client):
    """Test test_module with feed_enabled=False and forbidden error."""
    # Mock `retrieve_domain_from_api` to raise a DemistoException with FORBIDDEN status
    exception = DemistoException("Forbidden")
    exception.res = MagicMock(status_code=403)
    mock_client.retrieve_domain_from_api = MagicMock(side_effect=exception)

    result = FeedCyberint.test_module(mock_client, feed_enabled=False)

    assert result == "Authorization Error: invalid `API Token`"
    mock_client.retrieve_domain_from_api.assert_called_once_with("checkpoint.com")


def test_test_module_feed_enabled_other_error(mock_client):
    """Test test_module with feed_enabled=True and non-auth related error."""
    # Mock `request_daily_feed` to raise a DemistoException with a different status code
    exception = DemistoException("Internal Server Error")
    exception.res = MagicMock(status_code=500)
    mock_client.request_daily_feed = MagicMock(side_effect=exception)

    with pytest.raises(DemistoException, match="Internal Server Error"):
        FeedCyberint.test_module(mock_client, feed_enabled=True)

    mock_client.request_daily_feed.assert_called_once_with(limit=10, test=True)


def test_test_module_feed_disabled_other_error(mock_client):
    """Test test_module with feed_enabled=False and non-auth related error."""
    # Mock `retrieve_domain_from_api` to raise a DemistoException with a different status code
    exception = DemistoException("Internal Server Error")
    exception.res = MagicMock(status_code=500)
    mock_client.retrieve_domain_from_api = MagicMock(side_effect=exception)

    with pytest.raises(DemistoException, match="Internal Server Error"):
        FeedCyberint.test_module(mock_client, feed_enabled=False)

    mock_client.retrieve_domain_from_api.assert_called_once_with("checkpoint.com")


def test_fetch_indicators_with_filters(mock_client):
    """Test fetch_indicators with various filters applied."""
    # Mock the request_daily_feed to return test data
    mock_indicators = [
        {
            "ioc_value": "malicious.com",
            "ioc_type": "Domain",
            "detected_activity": "phishing",
            "confidence": 90,
            "severity_score": 8,
            "observation_date": "2025-01-01",
            "description": "Phishing domain",
        },
        {
            "ioc_value": "1.2.3.4",
            "ioc_type": "IP",
            "detected_activity": "malware",
            "confidence": 50,
            "severity_score": 5,
            "observation_date": "2025-01-01",
            "description": "Malware IP",
        },
        {
            "ioc_value": "safe.com",
            "ioc_type": "Domain",
            "detected_activity": "phishing",
            "confidence": 30,
            "severity_score": 3,
            "observation_date": "2025-01-01",
            "description": "Low confidence domain",
        },
    ]

    with (
        patch.object(mock_client, "request_daily_feed", return_value=mock_indicators),
        patch("FeedCyberint.auto_detect_indicator_type") as mock_auto_detect,
    ):
        mock_auto_detect.side_effect = lambda x: "Domain" if "." in x and not x[0].isdigit() else "IP"

        result = FeedCyberint.fetch_indicators(
            client=mock_client,
            tlp_color="RED",
            feed_names=["phishing"],
            indicator_types=["Domain"],
            confidence_from=60,
            severity_from=7,
            feed_tags=["test"],
            limit=10,
        )

        # Should only return the first indicator that matches all filters
        assert len(result) == 1
        assert result[0]["value"] == "malicious.com"
        assert result[0]["fields"]["trafficlightprotocol"] == "RED"
        assert "test" in result[0]["fields"]["tags"]


def test_fetch_indicators_with_all_types(mock_client):
    """Test fetch_indicators with 'All' indicator types and feed names."""
    mock_indicators = [
        {
            "ioc_value": "test.com",
            "ioc_type": "Domain",
            "detected_activity": "phishing",
            "confidence": 80,
            "severity_score": 8,
            "observation_date": "2025-01-01",
            "description": "Test domain",
        }
    ]

    with (
        patch.object(mock_client, "request_daily_feed", return_value=mock_indicators),
        patch("FeedCyberint.auto_detect_indicator_type", return_value="Domain"),
    ):
        result = FeedCyberint.fetch_indicators(
            client=mock_client,
            tlp_color="",
            feed_names=["All"],
            indicator_types=["All"],
            confidence_from=0,
            severity_from=0,
            limit=-1,
        )

        assert len(result) == 1
        assert result[0]["value"] == "test.com"


def test_fetch_indicators_limit_reached(mock_client):
    """Test fetch_indicators stops when limit is reached."""
    mock_indicators = [
        {
            "ioc_value": f"test{i}.com",
            "ioc_type": "Domain",
            "detected_activity": "phishing",
            "confidence": 80,
            "severity_score": 8,
            "observation_date": "2025-01-01",
            "description": f"Test domain {i}",
        }
        for i in range(10)
    ]

    with (
        patch.object(mock_client, "request_daily_feed", return_value=mock_indicators),
        patch("FeedCyberint.auto_detect_indicator_type", return_value="Domain"),
    ):
        result = FeedCyberint.fetch_indicators(
            client=mock_client,
            tlp_color="",
            feed_names=["All"],
            indicator_types=["All"],
            confidence_from=0,
            severity_from=0,
            limit=5,
        )

        assert len(result) == 5


def test_fetch_indicators_no_type_detected(mock_client):
    """Test fetch_indicators skips indicators with no detected type."""
    mock_indicators = [
        {
            "ioc_value": "invalid",
            "ioc_type": "Unknown",
            "detected_activity": "phishing",
            "confidence": 80,
            "severity_score": 8,
            "observation_date": "2025-01-01",
            "description": "Invalid indicator",
        }
    ]

    with (
        patch.object(mock_client, "request_daily_feed", return_value=mock_indicators),
        patch("FeedCyberint.auto_detect_indicator_type", return_value=None),
    ):
        result = FeedCyberint.fetch_indicators(
            client=mock_client, tlp_color="", feed_names=["All"], indicator_types=["All"], confidence_from=0, severity_from=0
        )

        assert len(result) == 0


def test_get_url_command_with_activities_and_entities(mock_client):
    """Test get_url_command with detected activities and related entities."""
    mock_response = {
        "data": {
            "entity": {"type": "url", "value": "http://malicious.com"},
            "risk": {
                "malicious_score": 95,
                "occurrences_count": 10,
                "detected_activities": [
                    {
                        "type": "phishing",
                        "observation_date": "2025-01-01",
                        "description": "Phishing activity",
                        "confidence": 90,
                        "occurrences_count": 5,
                    }
                ],
                "related_entities": [{"entity_id": "123", "entity_type": "domain", "entity_name": "malicious.com"}],
            },
            "enrichment": {
                "ips": ["1.2.3.4"],
                "hostname": "malicious.com",
                "domain": "malicious.com",
                "related_entities": [{"entity_id": "456", "entity_type": "ip", "entity_name": "1.2.3.4"}],
            },
            "benign": False,
        }
    }

    mock_client.retrieve_url_from_api = MagicMock(return_value=mock_response)

    result = FeedCyberint.get_url_command(mock_client, {"value": "http://malicious.com"})

    assert result.outputs["entity"]["value"] == "http://malicious.com"
    assert result.outputs["risk"]["malicious_score"] == 95


def test_get_ipv4_command_with_geo_and_asn(mock_client):
    """Test get_ipv4_command with geo and ASN data."""
    mock_response = {
        "data": {
            "entity": {"type": "ipv4", "value": "1.2.3.4"},
            "risk": {"malicious_score": 85, "occurrences_count": 15, "detected_activities": [], "related_entities": []},
            "enrichment": {
                "geo": {"country": "US", "city": "New York"},
                "asn": {"number": "12345", "organization": "Test ISP"},
                "suspicious_urls": ["http://dummy.com"],
                "suspicious_domains": ["dummy.com"],
            },
            "benign": False,
        }
    }

    mock_client.retrieve_ipv4_from_api = MagicMock(return_value=mock_response)

    result = FeedCyberint.get_ipv4_command(mock_client, {"value": "1.2.3.4"})

    assert result.outputs["entity"]["value"] == "1.2.3.4"
    assert result.outputs["enrichment"]["geo"]["country"] == "US"
    assert result.outputs["enrichment"]["asn"]["number"] == "12345"


def test_get_domain_command_with_whois(mock_client):
    """Test get_domain_command with WHOIS data."""
    mock_response = {
        "data": {
            "entity": {"type": "domain", "value": "test.com"},
            "risk": {"malicious_score": 70, "occurrences_count": 8, "detected_activities": [], "related_entities": []},
            "enrichment": {
                "ips": ["1.2.3.4"],
                "whois": {
                    "registrant_name": "John Doe",
                    "registrant_email": "john@example.com",
                    "registrant_organization": "Test Org",
                    "registrant_country": "US",
                    "registrant_telephone": "+1234567890",
                    "technical_contact_email": "tech@example.com",
                    "technical_contact_name": "Tech Person",
                    "technical_contact_organization": "Tech Org",
                    "registrar_name": "Test Registrar",
                    "admin_contact_name": "Admin Person",
                    "admin_contact_organization": "Admin Org",
                    "admin_contact_email": "admin@example.com",
                    "created_date": "2020-01-01",
                    "updated_date": "2024-01-01",
                    "expiration_date": "2026-01-01",
                },
            },
            "benign": False,
        }
    }

    mock_client.retrieve_domain_from_api = MagicMock(return_value=mock_response)

    result = FeedCyberint.get_domain_command(mock_client, {"value": "test.com"})

    assert result.outputs["entity"]["value"] == "test.com"
    assert result.outputs["enrichment"]["whois"]["registrant_name"] == "John Doe"


def test_get_file_sha256_command_with_activities(mock_client):
    """Test get_file_sha256_command with detected activities."""
    mock_response = {
        "data": {
            "entity": {"type": "file", "value": "abc123"},
            "risk": {
                "malicious_score": 95,
                "detected_activities": [
                    {
                        "type": "malware",
                        "observation_date": "2025-01-01",
                        "description": "Malware detected",
                        "confidence": 95,
                        "occurrences_count": 3,
                    }
                ],
                "related_entities": [{"entity_id": "789", "entity_type": "domain", "entity_name": "malware.com"}],
            },
            "enrichment": {
                "filenames": ["malware.exe", "virus.dll"],
                "first_seen": "2024-12-01",
                "download_urls": ["http://dummy.com/malware.exe"],
            },
            "benign": False,
        }
    }

    mock_client.retrieve_file_sha256_from_api = MagicMock(return_value=mock_response)

    result = FeedCyberint.get_file_sha256_command(mock_client, {"value": "abc123"})

    assert result.outputs["entity"]["value"] == "abc123"
    assert len(result.outputs["enrichment"]["filenames"]) == 2


def test_fetch_indicators_command_feed_disabled(mock_client):
    """Test fetch_indicators_command when feed is disabled."""
    params = {
        "feed": False,
        "tlp_color": "RED",
        "feedTags": "tag1",
        "severity_from": "0",
        "confidence_from": "0",
        "feed_name": "All",
        "indicator_type": "All",
        "feedFetchInterval": "30",
    }

    result = FeedCyberint.fetch_indicators_command(mock_client, params)

    assert result == []


def test_fetch_indicators_command_with_yesterday(mock_client):
    """Test fetch_indicators_command fetches from yesterday when needed."""
    params = {
        "feed": True,
        "tlp_color": "RED",
        "feedTags": "tag1",
        "severity_from": "0",
        "confidence_from": "0",
        "feed_name": "All",
        "indicator_type": "All",
        "feedFetchInterval": "1440",
    }

    mock_indicators = [{"indicator": "test.com", "type": "Domain"}]

    with (
        patch("FeedCyberint.is_x_minutes_ago_yesterday", return_value=True),
        patch("FeedCyberint.get_yesterday_time", return_value="2024-12-31"),
        patch("FeedCyberint.fetch_indicators", return_value=mock_indicators),
    ):
        result = FeedCyberint.fetch_indicators_command(mock_client, params)

        assert len(result) == 2  # Yesterday + today


def test_process_feed_response_empty_feeds(mock_client, capfd):
    """Test process_feed_response handles empty response."""
    with capfd.disabled(), patch.object(mock_client, "retrieve_indicators_from_api", return_value=""):
        result = mock_client.process_feed_response("2025-01-01", 100, 0)

        assert result == []


def test_get_today_time_format():
    """Test get_today_time returns correctly formatted date."""
    result = FeedCyberint.get_today_time()

    # Should match DATE_FORMAT which is "%Y-%m-%d"
    assert re.match(r"\d{4}-\d{2}-\d{2}", result)

    # Should be today's date
    today = datetime.now().strftime("%Y-%m-%d")
    assert result == today


def test_is_execution_time_exceeded_exact_limit():
    """Test is_execution_time_exceeded at exact timeout limit."""
    start_time = datetime.now() - timedelta(seconds=FeedCyberint.EXECUTION_TIMEOUT_SECONDS)
    result = FeedCyberint.is_execution_time_exceeded(start_time)

    # Should return False at exactly the limit (not exceeded yet)
    assert result is False


def test_main_not_implemented_command():
    """Test main() raises NotImplementedError for unknown commands."""
    with patch("FeedCyberint.demisto") as mock_demisto:
        mock_demisto.params.return_value = {
            "url": "https://example.com",
            "access_token": {"password": "test-token"},
            "insecure": False,
            "proxy": False,
        }
        mock_demisto.command.return_value = "unknown-command"

        with patch("FeedCyberint.return_error") as mock_return_error:
            FeedCyberint.main()

            mock_return_error.assert_called_once()
            assert "not implemented" in mock_return_error.call_args[0][0].lower()


def test_main_exception_handling():
    """Test main() handles exceptions properly."""
    with patch("FeedCyberint.demisto") as mock_demisto:
        mock_demisto.params.return_value = {
            "url": "https://example.com",
            "access_token": {"password": "test-token"},
            "insecure": False,
            "proxy": False,
        }
        mock_demisto.command.return_value = "test-module"

        with patch("FeedCyberint.Client") as mock_client_class:
            mock_client_class.side_effect = Exception("Connection failed")

            with patch("FeedCyberint.return_error") as mock_return_error:
                FeedCyberint.main()

                mock_return_error.assert_called_once()
                assert "connection failed" in mock_return_error.call_args[0][0].lower()
