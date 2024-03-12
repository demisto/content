import pytest
import io
from CommonServerPython import *
from StellarCyber import Client, get_alert_command, test_module_command, close_incident_command, update_incident_command, get_remote_data_command, get_modified_remote_data_command
SERVER_URL = 'https://test_url.com'


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


@pytest.fixture()
def client():
    return Client(dp_host='test', username='test', password='test', verify=True, proxy=None, tenantid=None, is_saas=True)
