from datetime import datetime

import FeedCyberint
import pytest

date_time = str((datetime.now().strftime(FeedCyberint.DATE_FORMAT)))

ENVIRONMENT = "environment-example"
BASE_URL = f"https://{ENVIRONMENT}.cyberint.io/ioc/api/v1/feed/daily/"
REQUEST_URL = f"{BASE_URL}{date_time}"
TOKEN = "example_token"


def load_mock_response() -> str:
    """Load mock file that simulates an API response.

    Returns:
        str: Mock file content.
    """
    with open("test_data/indicators.jsonb", "r") as file:
        return file.read()


@pytest.fixture()
def mock_client() -> FeedCyberint.Client:
    """
    Establish a mock connection to the client with access token.

    Returns:
        Client: Mock connection to client.
    """
    return FeedCyberint.Client(
        environment=ENVIRONMENT,
        access_token=TOKEN,
        verify=False,
        proxy=False,
    )


def test_build_iterator(
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
    response = load_mock_response()

    requests_mock.get(REQUEST_URL, text=response)

    expected_url = "http://www.tal1.com/"
    expected_ip = "1.1.1.1"

    indicators = mock_client.build_iterator()

    url_indicators = {indicator["value"] for indicator in indicators if indicator["type"] == "URL"}
    ip_indicators = {indicator["value"] for indicator in indicators if indicator["type"] == "IP"}

    assert expected_url in url_indicators
    assert expected_ip in ip_indicators


def test_get_indicators_command(
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
    response = load_mock_response()

    requests_mock.get(REQUEST_URL, text=response)

    expected_url = "http://www.tal1.com/"
    expected_ip = "1.1.1.1"

    params = {
        "tlp_color": "GREEN",
        "severity_from": "0",
        "confidence_from": "0",
        "feed_name": ["All"],
        "indicator_type": ["All"],
        "limit": 10,
    }
    args = {"limit": 20}

    result = FeedCyberint.get_indicators_command(mock_client, params, args)

    url_indicators = {indicator["value"] for indicator in result.raw_response if indicator["type"] == "URL"}
    ip_indicators = {indicator["value"] for indicator in result.raw_response if indicator["type"] == "IP"}

    assert expected_url in url_indicators
    assert expected_ip in ip_indicators


def test_fetch_indicators_command(
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
    response = load_mock_response()

    requests_mock.get(REQUEST_URL, text=response)

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
