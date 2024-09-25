import json
from datetime import datetime
import pytest
from pytest_mock import MockerFixture


with open("./test_data/response.json") as f:
    RESPONSE = json.load(f)


@pytest.fixture(autouse=True)
def mock_demisto_params(mocker: MockerFixture):
    """
    Automatically patches 'demistomock.params' for all test cases.
    """
    mocker.patch("demistomock.params", return_value={
        "api_url": "https://api.shodan.io",
        "credentials": {"credential": "", "credentials": {}, "password": "123"},
        'max_fetch': '2'
    })


def test_get_events_command(mocker: MockerFixture):
    from Shodan_v2 import get_events_command

    mock_http_request = mocker.patch("Shodan_v2.http_request", return_value=RESPONSE)
    _, events = get_events_command({"max_fetch": 2})

    assert len(events) == 2
    assert events[0]["name"] == "test_alert2"

    mock_http_request.assert_called_once_with("GET", "/shodan/alert/info")


def test_filter_events(mocker: MockerFixture):
    from Shodan_v2 import filter_events
    filtered_events = filter_events(events=RESPONSE, limit=3, last_run={'last_fetch_time': '2024-08-10T12:46:18.012000'})
    assert len(filtered_events) == 3
    assert filtered_events[0]["name"] == "test_alert2"


def test_format_record_keys():
    from Shodan_v2 import format_record_keys
    event = [{"column_name": "val1"}]
    hr = format_record_keys(event)

    assert hr == [{"Column Name": "val1"}]


def test_add_time_to_events():
    from Shodan_v2 import add_time_to_events
    add_time_to_events(RESPONSE)

    assert "_time" in RESPONSE[0]


def test_parse_event_date():
    from Shodan_v2 import parse_event_date
    created = parse_event_date(RESPONSE[0])
    assert isinstance(created, datetime)


def test_fetch_events(mocker):
    from Shodan_v2 import fetch_events
    mock_http_request = mocker.patch("Shodan_v2.http_request", return_value=RESPONSE)
    last_run, filtered_events = fetch_events({"last_fetch_time": "2024-08-10T12:46:18.012000"}, {'max_fetch': '2'})

    assert len(filtered_events) == 2
    assert last_run == {'last_fetch_time': '2024-08-12T08:46:18.012000', 'last_event_ids': ['6789']}
    mock_http_request.assert_called_once_with("GET", "/shodan/alert/info")
