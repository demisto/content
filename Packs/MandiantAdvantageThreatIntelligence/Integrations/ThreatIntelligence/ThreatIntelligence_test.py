import pytest
import io
from CommonServerPython import *
from ThreatIntelligence import MandiantClient
SERVER_URL = 'https://test_url.com'


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


@pytest.fixture()
def client():
    return Client(base_url=SERVER_URL, api_key='test', secret_key='test',
                  verify=True, proxy=True, timeout=None, first_fetch='test', limit=None, types=None, metadata=True, enrichment=True, tags=None,
                  tlp_color=None)
