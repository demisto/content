from datetime import datetime
from datetime import timedelta
import CommonServerPython
from freezegun import freeze_time
from pytest_mock import MockerFixture
from CommonServerPython import get_integration_context
from NetQuestOMX import TOKEN_TTL, DATE_FORMAT_FOR_TOKEN, Client
import json
import demistomock as demisto


INTEGRATION_CONTEXT = {}


def get_integration_context():
    return INTEGRATION_CONTEXT


def set_integration_context(integration_context):
    global INTEGRATION_CONTEXT
    INTEGRATION_CONTEXT = integration_context


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


# ----------------------------------------- COMMAND FUNCTIONS TESTS ---------------------------

@freeze_time('2020-06-03T02:00:00Z')
def test_new_token_login_client(requests_mock):
    """
    Given:
        - NetQuestOMX client object
    When:
        - getting the integration context
    Then:
        - Ensure the expiration time of the new token is calculated as expected in the integration context (TTL - 60s for safety)
    """
    credentials = {"identifier": 'UserName', "password": 'Password'}
    requests_mock.post('https://www.example.com/api/SessionService/Sessions', json={'Token': 'TEST'})
    Client(base_url='https://www.example.com', credentials=credentials, verify=True, proxy=False)
    integration_context = CommonServerPython.get_integration_context()

    assert integration_context["expiration_time"] == \
        (datetime.utcnow() + timedelta(seconds=(TOKEN_TTL - 60))).strftime(DATE_FORMAT_FOR_TOKEN)


@freeze_time('2020-06-03T02:00:00Z')
def test_old_token_login_client(mocker: MockerFixture):
    """
    Given:
        - Mocked integration context which contains a valid token (not expired)
    When:
        - Building a client
    Then:
        - Ensure that no new token is generated (since the existing token is not expired)
    """
    credentials = {"identifier": 'UserName', "password": 'Password'}
    cache = {
        "Token": "TEST",
        "expiration_time": (datetime.utcnow() + timedelta(seconds=TOKEN_TTL)).strftime(DATE_FORMAT_FOR_TOKEN)
    }
    set_integration_context(cache)
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mock_refresh_access_token = mocker.patch.object(Client, '_refresh_access_token')

    Client(base_url='https://www.example.com', credentials=credentials, verify=True, proxy=False)

    mock_refresh_access_token.assert_not_called()  # ensuring _refresh_access_token was not called
