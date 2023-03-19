import demistomock as demisto
import json
import io
from freezegun import freeze_time


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


get_alerts_dict = util_load_json('test_data/get_alerts_test.json')


class Client:
    def get_alerts_request(self, max_fetch, last_fetch, next_page_token):
        return get_alerts_dict


def test_get_alert():
    """
        Given:
            - The maximun number of events to fetch, tha date of the last fetch and the next page token.
        When:
            - Calling to one of the commands in the event collector.
        Then:
            - The list of the events and the next page token is returned.
    """
    from OrcaEventCollector import get_alerts
    client = Client()
    expected_alerts = get_alerts_dict.get('data', [])
    expected_next_page_token = 'next_page_token'
    alerts, next_page_token = get_alerts(client, 1, '2023-03-08T00:00:00', None)
    assert expected_alerts == alerts
    assert expected_next_page_token == next_page_token


test_params = {
    "credentials": {
        "password": "api_token",
    },
    "insecure": True,
    "proxy": False,
    "server_url": "server_url",
    "first_fetch": "3 days",
    "max_fetch": "1"
}


def mock_set_last_run(last_run):
    return last_run


@freeze_time("2023-03-14T13:34:14")
def test_main(mocker):
    """
        When:
            - Calling to fetch-events command.
        Then:
            - fetch the event and setLastRun.
    """
    from OrcaEventCollector import main
    mocker.patch.object(demisto, 'command', return_value='fetch-events')
    mocker.patch.object(demisto, 'params', return_value=test_params)
    mock_last_run = mocker.patch.object(demisto, 'setLastRun', side_effect=mock_set_last_run)
    mocker.patch('OrcaEventCollector.send_events_to_xsiam')
    mocker.patch('OrcaEventCollector.Client.get_alerts_request', return_value=get_alerts_dict)
    main()
    assert mock_last_run.call_args[0][0] == {'lastRun': '2023-03-13T00:00:00', 'next_page_token': 'next_page_token'}
