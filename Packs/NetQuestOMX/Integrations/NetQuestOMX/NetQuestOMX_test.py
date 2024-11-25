from datetime import datetime
from datetime import timedelta

from freezegun import freeze_time
from CommonServerPython import get_integration_context
from NetQuestOMX import TOKEN_TTL, DATE_FORMAT_FOR_TOKEN, Client
import json
import pytest


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


# ----------------------------------------- COMMAND FUNCTIONS TESTS ---------------------------
@freeze_time('2021-08-26')
@pytest.fixture
def net_quest_omx_client(requests_mock):
    credentials = {"identifier": 'UserName', "password": 'Password'}
    requests_mock.post('https://www.example.com/api/SessionService/Sessions', json={})
    return Client(base_url='https://www.example.com', credentials=credentials, verify=True, proxy=False)


def test_login_client(net_quest_omx_client):
    """
    Given:
        - NetQuestOMX client object
    When:
        - getting the integration context
    Then:
        - Ensure the expiration time is calculated as expected in the integration context (TTL - 60 seconds safety)
    """

    integration_context = get_integration_context()

    assert integration_context["expiration_time"] == \
           (datetime.utcnow() + timedelta(seconds=(TOKEN_TTL - 60))).strftime(DATE_FORMAT_FOR_TOKEN)
