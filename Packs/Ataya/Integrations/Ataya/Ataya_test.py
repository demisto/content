import pytest
from CommonServerPython import DemistoException

from Ataya import Client, assign_command


MOCK_URL = "http://123-fake-api.com"

MOCK_IMSI = "46666610000001"

MOCK_ASSIGN_USER_RESPONSE = {
    "status": "assigned",
    "resources": [MOCK_IMSI]
}

MOCK_UNASSIGN_USER_RESPONSE = {
    "status": "unassigned",
    "resources": [MOCK_IMSI]
}

MOCK_GET_NODE_RESPONSE = {
    "count": 1
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


def test_assign_command_exception():

    client = Client(
        api_key="123456789",
        base_url=MOCK_URL,
        proxy=False,
        verify=False
    )

    with pytest.raises(DemistoException, match="the imsi argument cannot be empty."):
        assign_command(client=client)


def test_assign_command_assign_fail(requests_mock):
    requests_mock.put(
        f'{MOCK_URL}/api/v1/mgmt/5gc/clientAction/setstatus', json=MOCK_UNASSIGN_USER_RESPONSE)
    client = Client(
        api_key="123456789",
        base_url=MOCK_URL,
        proxy=False,
        verify=False
    )

    with pytest.raises(DemistoException, match="Assign User Fail"):
        assign_command(client=client, imsi=MOCK_IMSI)


def test_get_node_api(requests_mock):
    requests_mock.get(
        f'{MOCK_URL}/api/v1/mgmt/5gc/networks/default/nodes', json=MOCK_GET_NODE_RESPONSE)
    client = Client(
        api_key="123456789",
        base_url=MOCK_URL,
        proxy=False,
        verify=False
    )

    result = client.getNode()
    assert result['count'] > 0


def test_module_command(requests_mock):

    from Ataya import test_module
    requests_mock.get(
        f'{MOCK_URL}/api/v1/mgmt/5gc/networks/default/nodes', json=MOCK_GET_NODE_RESPONSE)
    client = Client(
        api_key="123456789",
        base_url=MOCK_URL,
        proxy=False,
        verify=False
    )

    test_module(client=client)
