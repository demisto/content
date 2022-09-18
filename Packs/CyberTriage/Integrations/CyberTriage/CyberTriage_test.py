import pytest
import io
from CommonServerPython import *
from CyberTriage import CyberTriageClient, test_connection_command, triage_endpoint_command
SERVER_URL = 'https://test_url.com'


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


@pytest.fixture()
def client():
    return Client(server='test', rest_port='test', api_key='test', user='test', password='test', verify_server_cert=True, ok_codes=None)
