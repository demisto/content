import json
import io
import HPEArubaClearpass
from HPEArubaClearpass import *
from HPEArubaClearpass import Client
from freezegun import freeze_time
import demistomock as demisto
import pytest

CLIENT_ID = "id123"
CLIENT_SECRET = "secret123"
CLIENT_AUTH = \
    {
        "access_token": "auth123",
        "expires_in": 28800,
        "token_type": "Bearer",
        "scope": None
    }
NEW_ACCESS_TOKEN = "new123"

TEST_LOGIN_LIST = \
    [
        ({}, "auth123"),  # no integration context, should generate new access token
        ({"access_token": "old123", "expires_in": "2021-05-03T12:00:00Z"},  # access token valid
         "old123"),
        ({"access_token": "old123", "expires_in": "2021-05-03T10:00:00Z"},  # access token expired
         "auth123"),
    ]


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def create_client(proxy: bool = False, verify: bool = False, base_url: str = "https://example.com/api/"
                  , client_id: str = CLIENT_ID, client_secret: str = CLIENT_SECRET):
    return Client(proxy=proxy, verify=verify, base_url=base_url, client_id=client_id, client_secret=client_secret)


@pytest.mark.parametrize('context_data, expected_token', TEST_LOGIN_LIST)
@freeze_time("2021-05-03T11:00:00Z")
def test_login(mocker, context_data, expected_token):
    client = create_client()
    mocker.patch.object(HPEArubaClearpass, "get_integration_context", return_value=context_data)
    mocker.patch.object(client, "generate_new_access_token", return_value=CLIENT_AUTH)
    client.login()
    assert client.access_token == expected_token
