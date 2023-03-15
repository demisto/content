
import json
import io


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
            - Calling to one of the commands in the eb=vent collector.
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
