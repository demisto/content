from pytest_mock import mocker
from Shodan_v2 import get_events_command


def test_get_events_command():
    mocker.patch.object("http_request", return_value=respons.json)

    hr, events = get_events_command()
