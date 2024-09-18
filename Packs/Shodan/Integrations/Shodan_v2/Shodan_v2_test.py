import json
from datetime import datetime
from pytest_mock import MockerFixture


with open("./test_data/response.json") as f:
    RESPONSE = json.load(f)


def test_get_events_command(mocker: MockerFixture):
    mocker.patch("demistomock.params", return_value={"api_url": "https://api.shodan.io", "credentials":
                                                     {"credential": "", "credentials": {}, "password": "123", }, },)
    from Shodan_v2 import get_events_command

    mock_http_request = mocker.patch("Shodan_v2.http_request", return_value=RESPONSE)
    _, events = get_events_command({"max_fetch": 2, "start_date": "2024-08-10T12:46:18.012000"})

    assert len(events) == 2
    assert events[0]["name"] == "test_alert2"

    mock_http_request.assert_called_once_with("GET", "/shodan/alert/info")


def test_filter_events(mocker: MockerFixture):
    mocker.patch("demistomock.params", return_value={"api_url": "https://api.shodan.io", "credentials":
                                                     {"credential": "", "credentials": {}, "password": "123", }, },)
    from Shodan_v2 import filter_events
    start_date = datetime.strptime("2024-08-10T12:46:18.012000", "%Y-%m-%dT%H:%M:%S.%f")
    filtered_events = filter_events(events=RESPONSE, start_date=start_date, limit=3)
    assert len(filtered_events) == 3
    assert filtered_events[0]["name"] == "test_alert2"
