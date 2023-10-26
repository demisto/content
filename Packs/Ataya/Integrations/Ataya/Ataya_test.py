from Ataya import Client, assign_command

MOCK_URL = "http://123-fake-api.com"

MOCK_IMSI = "46666610000001"

MOCK_ASSIGN_USER_RESPONSE = {
    "status": "assigned",
    "resources": [MOCK_IMSI]
}


def test_assign_command(requests_mock):
    requests_mock.put(
        f'{MOCK_URL}/api/v1/mgmt/5gc/clientAction/setstatus', json=MOCK_ASSIGN_USER_RESPONSE)
    client = Client(
        api_key="123456789",
        base_url=MOCK_URL,
        proxy=False,
        verify=False
    )

    result = assign_command(client=client, imsi=MOCK_IMSI)
    assert MOCK_ASSIGN_USER_RESPONSE['status'] in result
