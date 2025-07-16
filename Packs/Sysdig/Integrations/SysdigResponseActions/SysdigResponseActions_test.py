"""
Sysdig Response Actions Integration - Unit Tests file
"""

import pytest
from http import HTTPStatus
import requests
from unittest.mock import patch
from SysdigResponseActions import (
    Client,
    execute_response_action_command,
    create_system_capture_command,
    get_capture_file_command,
    get_action_execution_command,
)

import json


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


KILL_CONTAINER_RESPONSE = util_load_json("test_data/response_api/kill_container_response.json")
GET_ACTION_EXECUTION_RESPONSE = util_load_json("test_data/response_api/get_execution_response.json")
SYSTEM_CAPTURE_RESPONSE = util_load_json("test_data/system_capture/create_response.json")


@pytest.fixture
def mock_response():
    """Fixture to mock the session.request method"""
    with patch.object(requests.Session, "request") as mock_request:
        yield mock_request


def test_execute_response_action(mock_response):
    # Successful response
    mock_response.return_value.json.return_value = KILL_CONTAINER_RESPONSE
    mock_response.return_value.status_code = HTTPStatus.OK
    client = Client(base_url="https://us2.app.sysdig.com", verify=False, headers={"Authorization": "Bearer token"}, proxy=False)
    result = execute_response_action_command(
        client, {"actionType": "KILL_CONTAINER", "container_id": "123456789012", "callerId": "test_kill_container_07"}
    )
    result = result.to_context().get("Contents")

    assert result.get("actionType") == "KILL_CONTAINER"
    assert result.get("status") == "created"
    assert result.get("callerId") == "test_kill_container_07"
    assert result.get("executionContext").get("container.id") == "123456789012"


def test_create_system_capture(mock_response):
    # Successful response
    mock_response.return_value.json.return_value = SYSTEM_CAPTURE_RESPONSE
    mock_response.return_value.status_code = HTTPStatus.OK
    client = Client(base_url="https://us2.app.sysdig.com", verify=False, headers={"Authorization": "Bearer token"}, proxy=False)
    result = create_system_capture_command(
        client,
        {
            "host_name": "ip-1-2-3-4.us-west-1.compute.internal",
            "container_id": "123456789012",
            "capture_name": "test_capture",
            "agent_id": "123456789012",
            "customer_id": "123456789012",
            "machine_id": "aa:bb:cc:11:22:33",
        },
    )
    result = result.to_context().get("Contents").get("capture")

    assert result.get("status") == "requested"
    assert result.get("agent").get("machineId") == "aa:bb:cc:11:22:33"
    assert result.get("containerId") == "123456789012"
    assert result.get("agent").get("hostName") == "ip-1-2-3-4.us-west-1.compute.internal"


def test_get_capture_file(mock_response):
    # Successful response
    mock_response.return_value.content = b"abc"  # Dummy bytes
    mock_response.return_value.status_code = HTTPStatus.OK
    client = Client(base_url="https://us2.app.sysdig.com", verify=False, headers={"Authorization": "Bearer token"}, proxy=False)
    result = get_capture_file_command(client, {"capture_id": "1234567890"})
    result = result.to_context().get("Contents")


def test_get_action_execution(mock_response):
    # Successful response
    mock_response.return_value.json.return_value = GET_ACTION_EXECUTION_RESPONSE
    mock_response.return_value.status_code = HTTPStatus.OK
    client = Client(base_url="https://us2.app.sysdig.com", verify=False, headers={"Authorization": "Bearer token"}, proxy=False)
    result = get_action_execution_command(client, {"action_execution_id": "b137bf86-399f-43f7-8d2b-53060af4da9f"})
    result = result.to_context().get("Contents")

    assert result.get("actionType") == "KILL_CONTAINER"
    assert result.get("status") == "COMPLETED"
    assert result.get("callerId") == "test_kill_container_07"
    assert result.get("executionContext").get("container.id") == "123456789012"
