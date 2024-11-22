from datetime import datetime
from unittest import mock

import FeedCyberint
import pytest

date_time = str((datetime.now().strftime(FeedCyberint.DATE_FORMAT)))

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
    with open("test_data/indicators.jsonb", "r") as file:
        return file.read()


def load_mock_empty_response() -> str:
    """Load mock file that simulates an API response.

    Returns:
        str: Mock file content.
    """
    with open("test_data/empty.jsonb", "r") as file:
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

    expected_url = "http://www.tal1.com/"
    expected_ip = "1.1.1.1"

    indicators = mock_client.request_daily_feed()
    print(f'Indicators: {indicators}')

    url_indicators = {indicator["value"] for indicator in indicators if indicator["type"] == "URL"}
    ip_indicators = {indicator["value"] for indicator in indicators if indicator["type"] == "IP"}

    assert expected_url in url_indicators
    assert expected_ip in ip_indicators


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

    args = {"limit": 20}

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
