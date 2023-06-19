import demistomock as demisto
import io
import json
import pytest

def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


"""*****COMMAND FUNCTIONS****"""


def test_get_model_breach(mocker):
    """Tests darktrace-get--model-breach command function.

    Configures requests_mock instance to generate the appropriate
    get_alerts API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from DarktraceEventCollector import Client, main

    mock_params = {'first_fetch': '3 days ago', 'max_fetch': '2', 'insecure': True,
                   'proxy': False, 'base_url': 'https://mock.darktrace.com',
                   'public_creds': {'password': 'example_pub'},
                   'private_creds': {'password': 'example_pri'}}

    mocker.patch.object(demisto, 'params', return_value=mock_params)
    mocker.patch.object(demisto, 'command', return_value='fetch-events')
    mocker.patch.object(Client, 'http_request', return_value=util_load_json('test_data/get_alerts.json'))
    main()
