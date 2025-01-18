from decyfirEventCollector import Client, fetch_events
from datetime import datetime, timedelta
import json

def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


def test_fetch_events(mocker):
    mock_decyfir_event_response = util_load_json('test_data/decyfir_events_data.json')
    mock_pa_event_response = util_load_json('test_data/events_data.json')
    date_format = '%Y-%m-%dT%H:%M:%SZ'
    client = Client(
        base_url='test_url',
        verify=False,
    )
    mocker.patch.object(Client, 'get_decyfir_event_logs', return_value=mock_decyfir_event_response['iocs'])
    last_fetch = (datetime.now() - timedelta(days=2)).strftime(date_format)
    last_run = {
        'last_fetch': last_fetch
    }
    data = fetch_events(
        client=client,
        decyfir_api_key='api_key',
        first_fetch='30 days',
        last_run=last_run, max_fetch=20,
    )
    assert data.raw_response == mock_pa_event_response
