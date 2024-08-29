from datetime import datetime, timedelta, timezone

from freezegun import freeze_time
from CommonServerPython import *


import pytest
from IBMSecurityVerifyEventCollector import Client


@pytest.fixture()
def mock_client(mocker) -> Client:
    mocker.patch.object(Client, "_authenticate")
    client = Client(
        base_url="https://www.example.com",
        client_id="DUMMY_CLIENT_ID",
        client_secret="DUMMY_SECRET_KEY",
        verify=False,
        proxy=False,
    )
    client._headers = {"Authorization": "Bearer DUMMY_TOKEN"}
    return client


@pytest.mark.parametrize(
    "token_data, expected_result",
    [
        (
            {
                "access_token": "valid_token",
                "expiry_time_utc": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
            },
            True
        ),
        (
            {
                "access_token": "valid_token",
                "expiry_time_utc": datetime.now(timezone.utc).isoformat()
            },
            False
        ),
    ]
)
def test_is_token_valid(mock_client, token_data, expected_result):
    result = mock_client._is_token_valid(token_data)
    assert result == expected_result


@freeze_time("2024-08-29 12:00:00")
def test_get_new_token(mocker, mock_client):
    expires_in = 7200
    expiry_time_utc = datetime.now(timezone.utc) + timedelta(seconds=expires_in)
    expected_result = {"access_token": "DUMMY_TOKEN", "expiry_time_utc": expiry_time_utc.isoformat()}

    response = {"access_token": "DUMMY_TOKEN", "expires_in": expires_in}
    http_request = mocker.patch.object(Client, "_http_request", return_value=response)

    rustle = mock_client._get_new_token()

    http_request.assert_called_with(
        method="POST",
        url_suffix="/endpoint/default/token",
        data={
            "client_id": "DUMMY_CLIENT_ID",
            "client_secret": "DUMMY_SECRET_KEY",
            "grant_type": "client_credentials",
        },
    )

    assert rustle == expected_result
