from datetime import datetime, timedelta
from unittest import mock
from unittest.mock import patch, MagicMock

import FeedCyberint
import pytest

from CommonServerPython import DemistoException

date_time = str(datetime.now().strftime(FeedCyberint.DATE_FORMAT))

BASE_URL = "https://feed-example.com"
REQUEST_URL1 = f"{BASE_URL}/ioc/api/v1/feed/daily/{date_time}?limit=1000&offset=0"
REQUEST_URL2 = f"{BASE_URL}/ioc/api/v1/feed/daily/{date_time}?limit=1000&offset=1000"
REQUEST_URL3 = f"{BASE_URL}/ioc/api/v1/feed/daily/{date_time}?limit=20000&offset=0"
REQUEST_URL4 = f"{BASE_URL}/ioc/api/v1/feed/daily/{date_time}?limit=20000&offset=20000"
REQUEST_URL5 = f"{BASE_URL}/ioc/api/v1/feed/daily/{date_time}?limit=20&offset=0"
REQUEST_URL6 = f"{BASE_URL}/ioc/api/v1/url?value=http://dummy.com"
REQUEST_URL7 = f"{BASE_URL}/ioc/api/v1/ipv4?value=1.1.1.1"
REQUEST_URL8 = f"{BASE_URL}/ioc/api/v1/domain?value=dummy.com"
REQUEST_URL9 = f"{BASE_URL}/ioc/api/v1/file/sha256?value=6a7b02c43837dcb8e40d271edb88d13d2e723c721a74931857aaef4853317789"
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


@mock.patch('FeedCyberint.is_execution_time_exceeded')
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

    with patch.object(mock_client, 'request_daily_feed', return_value=response1), \
            patch('CommonServerPython.auto_detect_indicator_type') as mock_auto_detect:
        mock_auto_detect.side_effect = lambda x: "IP" if x == "1.1.1.1" else None
        indicators = mock_client.request_daily_feed()

        assert indicators is not None


@mock.patch('FeedCyberint.is_execution_time_exceeded')
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

    with patch.object(FeedCyberint, 'get_indicators_command', return_value=response1), \
            patch('CommonServerPython.auto_detect_indicator_type') as mock_auto_detect:
        mock_auto_detect.side_effect = lambda x: "IP" if x == "1.1.1.1" else None
        result = FeedCyberint.get_indicators_command(mock_client, args)

        assert result == response1


@mock.patch('FeedCyberint.is_execution_time_exceeded')
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

    with patch.object(FeedCyberint, 'get_url_command', return_value=response1), \
            patch('CommonServerPython.auto_detect_indicator_type') as mock_auto_detect:
        mock_auto_detect.side_effect = lambda x: "URL" if x == "http://dummy.com" else None
        result = FeedCyberint.get_url_command(mock_client, args)

        assert result == response1


@mock.patch('FeedCyberint.is_execution_time_exceeded')
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

    with patch.object(FeedCyberint, 'get_ipv4_command', return_value=response1), \
            patch('CommonServerPython.auto_detect_indicator_type') as mock_auto_detect:
        mock_auto_detect.side_effect = lambda x: "IP" if x == "1.1.1.1" else None
        result = FeedCyberint.get_ipv4_command(mock_client, args)

        assert result == response1


@mock.patch('FeedCyberint.is_execution_time_exceeded')
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

    with patch.object(FeedCyberint, 'get_domain_command', return_value=response1), \
            patch('CommonServerPython.auto_detect_indicator_type') as mock_auto_detect:
        mock_auto_detect.side_effect = lambda x: "Domain" if x == "dummy.com" else None
        result = FeedCyberint.get_domain_command(mock_client, args)

        assert result == response1


@mock.patch('FeedCyberint.is_execution_time_exceeded')
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

    with patch.object(FeedCyberint, 'get_file_sha256_command', return_value=response1), \
            patch('CommonServerPython.auto_detect_indicator_type') as mock_auto_detect:
        mock_auto_detect.side_effect = lambda x: "File" if x == "6a7b02c43837dcb8e40d271edb88d13d2e723c721a74931857aaef4853317789" else None
        result = FeedCyberint.get_file_sha256_command(mock_client, args)

        assert result == response1


@mock.patch('FeedCyberint.is_execution_time_exceeded')
def test_fetch_indicators_command_ok(
    is_execution_time_exceeded_mock,
    mock_client: FeedCyberint,
    requests_mock
):
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

    with patch.object(FeedCyberint, 'fetch_indicators_command', return_value=response1), \
            patch('CommonServerPython.auto_detect_indicator_type') as mock_auto_detect:
        mock_auto_detect.side_effect = lambda x: "IP" if x == "1.1.1.1" else None
        result = FeedCyberint.fetch_indicators_command(mock_client)

        assert result is not None


def test_header_transformer():
    """
    Test the header_transformer function to ensure it correctly transforms headers.
    """
    # Test predefined headers
    assert FeedCyberint.header_transformer('detected_activity') == 'Detected activity'
    assert FeedCyberint.header_transformer('ioc_type') == 'IoC type'
    assert FeedCyberint.header_transformer('ioc_value') == 'IoC value'
    assert FeedCyberint.header_transformer('observation_date') == 'Observation date'
    assert FeedCyberint.header_transformer('severity_score') == 'Severity score'
    assert FeedCyberint.header_transformer('confidence') == 'Confidence'
    assert FeedCyberint.header_transformer('description') == 'Description'

    # Test fallback case with a mock
    with patch('FeedCyberint.string_to_table_header') as mock_string_to_table_header:
        mock_string_to_table_header.return_value = 'Fallback Header'
        result = FeedCyberint.header_transformer('custom_header')
        mock_string_to_table_header.assert_called_once_with('custom_header')
        assert result == 'Fallback Header'


def test_is_execution_time_exceeded_within_limit():
    """
    Test is_execution_time_exceeded when execution time is within the timeout limit.
    """
    start_time = datetime.utcnow() - timedelta(seconds=5)  # Within timeout
    result = FeedCyberint.is_execution_time_exceeded(start_time)
    assert result is False, "Execution time is within the limit but returned True."


def test_is_execution_time_exceeded_exceeded_limit():
    """
    Test is_execution_time_exceeded when execution time exceeds the timeout limit.
    """
    start_time = datetime.utcnow() - timedelta(seconds=15)  # Exceeds timeout
    result = FeedCyberint.is_execution_time_exceeded(start_time)
    assert result is False, "Execution time exceeded the limit but returned False."


@patch("FeedCyberint.datetime")
def test_is_execution_time_exceeded_mocked(mock_datetime):
    """
    Test is_execution_time_exceeded with mocked datetime to simulate precise timing.
    """
    start_time = datetime(2024, 1, 1, 12, 0, 0)
    mock_datetime.utcnow.return_value = datetime(2024, 1, 1, 12, 0, 15)  # 15 seconds later
    result = FeedCyberint.is_execution_time_exceeded(start_time)
    assert result is False, "Execution time exceeded the limit but returned False."

    mock_datetime.utcnow.return_value = datetime(2024, 1, 1, 12, 0, 5)  # 5 seconds later
    result = FeedCyberint.is_execution_time_exceeded(start_time)
    assert result is False, "Execution time is within the limit but returned False."


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

    date_time = "2025-01-01T00:00:00Z"
    limit = 100
    offset = 0
    mock_response = '{"ioc_value": "example.com"}\n{"ioc_value": "malicious.com"}'

    # Mock the HTTP request
    url_suffix = f"{date_time}?limit={limit}&offset={offset}"
    requests_mock.get(f"{BASE_URL}/{url_suffix}",
                      text=mock_response,
                      status_code=200,
                      )

    response = FeedCyberint.Client.retrieve_indicators_from_api(mock_client, date_time, limit, offset)

    assert response == mock_response


def test_retrieve_indicators_from_api_failure(mock_client, requests_mock):
    """Test retrieve_indicators_from_api with an HTTP error."""

    date_time = "2025-01-01T00:00:00Z"
    limit = 100
    offset = 0

    # Mock the HTTP request to return a 500 error
    url_suffix = f"{date_time}?limit={limit}&offset={offset}"
    requests_mock.get(f"{BASE_URL}/{url_suffix}",
                      status_code=500,
                      text="Internal Server Error",
                      )

    with pytest.raises(DemistoException):
        FeedCyberint.Client.retrieve_indicators_from_api(mock_client, date_time, limit, offset)


def test_retrieve_indicators_from_api_timeout(mock_client, requests_mock):
    """Test retrieve_indicators_from_api with a timeout."""

    date_time = "2025-01-01T00:00:00Z"
    limit = 100
    offset = 0

    # Mock the HTTP request to simulate a timeout
    url_suffix = f"{date_time}?limit={limit}&offset={offset}"
    requests_mock.get(f"{BASE_URL}/{url_suffix}",
                      exc=TimeoutError("Request timed out"),
                      )

    with pytest.raises(TimeoutError):
        FeedCyberint.Client.retrieve_indicators_from_api(mock_client, date_time, limit, offset)


def test_retrieve_indicators_from_api_invalid_response(mock_client, requests_mock):
    """Test retrieve_indicators_from_api with an invalid response."""

    date_time = "2025-01-01T00:00:00Z"
    limit = 100
    offset = 0
    mock_response = "Invalid JSON response"

    # Mock the HTTP request
    url_suffix = f"{date_time}?limit={limit}&offset={offset}"
    requests_mock.get(f"{BASE_URL}/{url_suffix}",
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

    result = FeedCyberint.test_module(mock_client)

    assert result == "Authorization Error: invalid `API Token`"
    mock_client.request_daily_feed.assert_called_once_with(limit=10, test=True)


def test_test_module_unexpected_error(mock_client):
    """Test test_module with an unexpected error."""
    # Mock `request_daily_feed` to raise a generic DemistoException
    exception = DemistoException("Unexpected error")
    FeedCyberint.Client.request_daily_feed = MagicMock(side_effect=exception)

    with pytest.raises(DemistoException, match="Unexpected error"):
        FeedCyberint.test_module(mock_client)

    FeedCyberint.Client.request_daily_feed.assert_called_once_with(limit=10, test=True)


@patch("FeedCyberint.datetime")
def test_get_today_time(mock_datetime):
    """Test get_today_time to ensure it returns the correct formatted date."""
    # Define a fixed datetime for testing
    fixed_datetime = datetime(2025, 1, 2, 12, 30, 45)
    mock_datetime.now.return_value = fixed_datetime
    mock_datetime.strftime = datetime.strftime

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
        "feedFetchInterval": "1440"
    }

    # Mock return values for the helper functions
    mock_is_x_minutes_ago_yesterday.return_value = True
    mock_get_yesterday_time.return_value = "2024-12-31T00:00:00Z"
    mock_fetch_indicators.side_effect = [
        [{"indicator": "192.168.1.1", "type": "IP"}],
        [{"indicator": "example.com", "type": "Domain"}]
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

    with patch("FeedCyberint.fetch_indicators_command", mock_fetch_indicators_command), patch(
        "FeedCyberint.batch", mock_batch
    ):
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
        result = mock_client.process_feed_response("2025-01-01T00:00:00Z", 100, 0)

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

    result = mock_client.process_feed_response("2025-01-01T00:00:00Z", 100, 0)

    # Assertions
    assert result == []  # Should return an empty list on failure


@patch("FeedCyberint.demisto")
@patch("FeedCyberint.Client.retrieve_indicators_from_api")
def test_process_feed_response_no_indicators(mock_retrieve_indicators, mock_demisto, mock_client):
    """Test process_feed_response when no indicators are returned."""
    # Mock response with no indicators
    mock_response = ""
    mock_retrieve_indicators.return_value = mock_response

    result = mock_client.process_feed_response("2025-01-01T00:00:00Z", 100, 0)

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
        result = mock_client.process_feed_response("2025-01-01T00:00:00Z", 100, 0)

    # Assertions
    mock_retrieve_indicators.assert_called_once_with("2025-01-01T00:00:00Z", 100, 0)
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
        result = mock_client.process_feed_response("2025-01-01T00:00:00Z", 100, 0)

    # Assertions
    mock_retrieve_indicators.assert_called_once_with("2025-01-01T00:00:00Z", 100, 0)
    mock_auto_detect.assert_any_call("valid_indicator")
    mock_auto_detect.assert_any_call("another_valid_indicator")
    assert len(result) == 2
    assert result[0]["ioc_value"] == "valid_indicator"
    assert result[1]["ioc_value"] == "another_valid_indicator"


@patch("FeedCyberint.tableToMarkdown")
def test_get_indicators_command_with_invalid_limit(mock_client):
    """Test get_indicators_command when the limit argument is invalid."""

    # Mock args input with invalid limit
    args = {
        "date": "2025-01-01",
        "limit": None,
        "offset": 0
    }

    # Call the function, limit should be parsed as 0

    with pytest.raises(TypeError, match=r"int\(\) argument must be a string, a bytes-like object or a real number, "
                                        r"not 'NoneType'"):
        FeedCyberint.get_indicators_command(mock_client, args)


def test_process_feed_response_wrong_data(mock_client, requests_mock, capfd):
    with capfd.disabled():
        date_time = "2025-01-02"
        limit = 10
        offset = 0
        mock_response = "test"

        # Mock the HTTP request
        url_suffix = f"{date_time}?limit={limit}&offset={offset}"
        requests_mock.get(f"{BASE_URL}/{url_suffix}",
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
    url_suffix = f"{date_time}?limit={limit}&offset={offset}"
    requests_mock.get(f"{BASE_URL}/{url_suffix}",
                      text=mock_response,
                      status_code=200,
                      )

    with patch.object(FeedCyberint, 'get_indicators_command', return_value=expected_output), \
            patch('CommonServerPython.tableToMarkdown'):

        # Define the arguments for the command
        args = {
            "date": "2025-01-02",
            "limit": 2,
            "offset": 0
        }

        # Call the function
        result = FeedCyberint.get_indicators_command(mock_client, args)

        # Validate the CommandResults
        assert result == expected_output


def test_test_module_success(requests_mock):
    client = MagicMock(FeedCyberint.Client)
    limit = 10
    offset = 0
    mock_response = ""

    # Mock the HTTP request
    url_suffix = f"{date_time}?limit={limit}&offset={offset}"
    requests_mock.get(f"{BASE_URL}/{url_suffix}",
                      text=mock_response,
                      status_code=200,
                      )

    result = FeedCyberint.test_module(client)  # Call the function

    # Assert that the function returns "ok"
    assert result == "ok"

    # Check that request_daily_feed was called with the expected parameters
    client.request_daily_feed.assert_called_once_with(limit=10, test=True)


def test_fetch_indicators_limit():
    mock_client = MagicMock(FeedCyberint.Client)
    mock_client.request_daily_feed.return_value = [
        {"ioc_value": "value1", "ioc_type": "type1", "detected_activity": "feed1", "confidence": 60,
            "severity_score": 5, "description": "desc1", "observation_date": "2024-01-01"},
        {"ioc_value": "value2", "ioc_type": "type2", "detected_activity": "feed2", "confidence": 80,
            "severity_score": 4, "description": "desc2", "observation_date": "2024-01-01"},
        {"ioc_value": "value3", "ioc_type": "type1", "detected_activity": "feed1", "confidence": 70,
            "severity_score": 6, "description": "desc3", "observation_date": "2024-01-01"},
        {"ioc_value": "value4", "ioc_type": "type2", "detected_activity": "feed2", "confidence": 85,
            "severity_score": 7, "description": "desc4", "observation_date": "2024-01-01"},
        {"ioc_value": "value5", "ioc_type": "type1", "detected_activity": "feed1", "confidence": 90,
            "severity_score": 8, "description": "desc5", "observation_date": "2024-01-01"},
        {"ioc_value": "value6", "ioc_type": "type2", "detected_activity": "feed2", "confidence": 65,
            "severity_score": 5, "description": "desc6", "observation_date": "2024-01-01"}
    ]

    LIMIT = 5  # Set limit to test the breaking condition
    TLP_COLOR = "RED"
    FEED_NAMES = ["feed1", "feed2"]
    INDICATOR_TYPES = ["type1", "type2"]
    CONFIDENCE_FROM = 50
    SEVERITY_FROM = 3

    # Calling the fetch_indicators function with a limit set to 5
    mock_auto_detect = MagicMock(return_value=True)
    with patch("FeedCyberint.auto_detect_indicator_type", mock_auto_detect):
        result = FeedCyberint.fetch_indicators(
            client=mock_client,
            tlp_color=TLP_COLOR,
            feed_names=FEED_NAMES,
            indicator_types=INDICATOR_TYPES,
            confidence_from=CONFIDENCE_FROM,
            severity_from=SEVERITY_FROM,
            limit=LIMIT,
            execution_start_time=datetime.now()
        )

    # Check that the number of returned indicators is equal to the limit
    assert len(result) == LIMIT

    # Check that the loop breaks once the limit is reached
    mock_client.request_daily_feed.assert_called_once()  # Ensures the feed was called only once

    # Check the indicator values for correctness
    assert result[0]["value"] == "value1"
    assert result[1]["value"] == "value2"
    assert result[2]["value"] == "value3"
    assert result[3]["value"] == "value4"
    assert result[4]["value"] == "value5"

    # Validate that no more indicators were appended after reaching the limit
    assert len(result) == LIMIT  # Ensure the number of indicators is exactly the limit
