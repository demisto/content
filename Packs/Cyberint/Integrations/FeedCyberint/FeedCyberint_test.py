from datetime import datetime, timedelta
from unittest import mock
from unittest.mock import patch

import FeedCyberint
import pytest

date_time = str(datetime.now().strftime(FeedCyberint.DATE_FORMAT))

BASE_URL = "https://feed-example.com/"
REQUEST_URL1 = f"{BASE_URL}{date_time}?limit=1000&offset=0"
REQUEST_URL2 = f"{BASE_URL}{date_time}?limit=1000&offset=1000"
REQUEST_URL3 = f"{BASE_URL}{date_time}?limit=20000&offset=0"
REQUEST_URL4 = f"{BASE_URL}{date_time}?limit=20000&offset=20000"
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

    indicators = mock_client.request_daily_feed()

    url_indicators = {indicator.get("value", "") for indicator in indicators if indicator.get("type", "") == "URL"}
    ip_indicators = {indicator.get("value", "") for indicator in indicators if indicator.get("type", "") == "IP"}

    assert url_indicators is not None
    assert ip_indicators is not None


@mock.patch('FeedCyberint.is_execution_time_exceeded')
def test_get_indicators_command(
    is_execution_time_exceeded_mock,
    requests_mock,
    mock_client: FeedCyberint.Client,
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

    requests_mock.get(REQUEST_URL3, text=response1)
    requests_mock.get(REQUEST_URL4, text=response2)

    expected_url = "http://www.tal1.com/"
    expected_ip = "1.1.1.1"

    args = {"date": "2024-10-10", "limit": 20, "offset": 0}

    result = FeedCyberint.get_indicators_command(mock_client, args)

    url_indicators = {indicator["value"] for indicator in result.raw_response if indicator["type"] == "URL"}
    ip_indicators = {indicator["value"] for indicator in result.raw_response if indicator["type"] == "IP"}

    assert expected_url in url_indicators
    assert expected_ip in ip_indicators


@mock.patch('FeedCyberint.is_execution_time_exceeded')
def test_fetch_indicators_command(
    is_execution_time_exceeded_mock,
    requests_mock,
    mock_client: FeedCyberint.Client,
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

    expected_url = "http://www.tal1.com/"
    expected_ip = "1.1.1.1"

    params = {
        "tlp_color": "GREEN",
        "severity_from": "0",
        "confidence_from": "0",
        "feed_name": ["All"],
        "indicator_type": ["All"],
        "feedFetchInterval": 300,
    }

    result = FeedCyberint.fetch_indicators_command(mock_client, params)

    url_indicators = {indicator["value"] for indicator in result if indicator["type"] == "URL"}
    ip_indicators = {indicator["value"] for indicator in result if indicator["type"] == "IP"}

    assert expected_url in url_indicators
    assert expected_ip in ip_indicators


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
    with patch('Cyberint.string_to_table_header') as mock_string_to_table_header:
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
    assert result is True, "Execution time exceeded the limit but returned False."


@patch("Cyberint.datetime")
def test_is_execution_time_exceeded_mocked(mock_datetime):
    """
    Test is_execution_time_exceeded with mocked datetime to simulate precise timing.
    """
    start_time = datetime(2024, 1, 1, 12, 0, 0)
    mock_datetime.utcnow.return_value = datetime(2024, 1, 1, 12, 0, 15)  # 15 seconds later
    result = FeedCyberint.is_execution_time_exceeded(start_time)
    assert result is True, "Execution time exceeded the limit but returned False."

    mock_datetime.utcnow.return_value = datetime(2024, 1, 1, 12, 0, 5)  # 5 seconds later
    result = FeedCyberint.is_execution_time_exceeded(start_time)
    assert result is False, "Execution time is within the limit but returned True."


def test_get_yesterday_time():
    """
    Test get_yesterday_time to ensure it correctly returns the date string for yesterday.
    """
    # Mock the current time for consistent testing
    mock_current_time = datetime(2024, 1, 2, 12, 0, 0)  # Example current time

    with patch("Cyberint.datetime") as mock_datetime:
        mock_datetime.now.return_value = mock_current_time
        mock_datetime.side_effect = lambda *args, **kw: datetime(*args, **kw)

        # Call the function
        result = FeedCyberint.get_yesterday_time()

        # Calculate the expected result
        expected_yesterday = mock_current_time - timedelta(days=1)
        expected_result = expected_yesterday.strftime(FeedCyberint.DATE_FORMAT)

        # Assert the result matches the expected value
        assert result == expected_result, f"Expected {expected_result}, but got {result}"
