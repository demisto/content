from datetime import datetime
from datetime import timedelta

from freezegun import freeze_time
from CommonServerPython import get_integration_context, BaseClient
from NetQuestOMX import Client, TOKEN_TTL, DATE_FORMAT_FOR_TOKEN
import json
import pytest


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


# ----------------------------------------- COMMAND FUNCTIONS TESTS ---------------------------
HEADERS = {'Content-Type': 'application/json', "X-Auth-Token": None}


@pytest.fixture
def netquest_omx_client(mocker, requests_mock):
    credentials = {"identifier": 'UserName', "password": 'Password'}
    mocker.patch.object(BaseClient, '_headers', return_value=HEADERS)
    requests_mock.post('https://www.example.com/api/SessionService/Sessions')

    return Client(base_url='https://www.example.com', credentials=credentials, verify=True, proxy=False)


@freeze_time('2021-08-26')
def test_login_client(mocker, requests_mock, netquest_omx_client):
    """
    Given:
        - credentials for the client
    When:
        - creating a NetQuestOMX client object
    Then:
        - Ensure the expiration time is written as expected in the integration context
    """
    from NetQuestOMX import Client
    mocker.patch.object(BaseClient, 'headers', return_value=HEADERS)
    requests_mock.post('https://www.example.com/api/SessionService/Sessions')
    credentials = {"identifier": 'UserName', "password": 'Password'}
    Client(base_url='https://www.example.com', credentials=credentials, verify=True, proxy=False)
    integration_context = get_integration_context()

    assert integration_context["expiration_time"] == \
           (datetime.utcnow() + timedelta(seconds=(TOKEN_TTL - 60))).strftime(DATE_FORMAT_FOR_TOKEN)
