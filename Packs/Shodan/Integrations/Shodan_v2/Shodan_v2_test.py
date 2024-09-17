import json
from datetime import datetime

from Shodan_v2 import get_events_command, filter_events

with open('./test_data/respons.json') as f:
    RESPONSE = json.load(f)


def test_get_events_command(mocker):
    mock_http_request = mocker.patch('http_request', return_value=RESPONSE)
    hr, events = get_events_command({'max_fetch': 2, 'start_date': '2024-08-13T00:00:00.000'})

    assert len(events) == 2
    assert events[0]["name"] == "test_alert"

    mock_http_request.assert_called_once_with('GET', '/shodan/alert/info')


def test_filter_events():
    start_date = datetime.strptime('2024-08-13T00:00:00.000', "%Y-%m-%dT%H:%M:%S.%f")

    filtered_events = filter_events(events=RESPONSE, start_date=start_date, limit=3)

    assert len(filtered_events) == 2
    assert filtered_events[0]["name"] == "nat-alert"
