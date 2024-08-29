from datetime import datetime, timedelta, timezone
from CommonServerPython import *


import pytest
from IBMSecurityVerifyEventCollector import Client


@pytest.fixture()
def mock_client(mocker) -> Client:
    mocker.patch.object(Client, "_authenticate")
    client = Client(
        base_url="test",
        client_id="client_id",
        client_secret="secret_key",
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
