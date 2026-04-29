"""
Sysdig Response Actions Integration - Unit Tests file
"""

import pytest
from http import HTTPStatus
import requests
from unittest.mock import patch
import demistomock as demisto  # noqa: F401

from SysdigResponseActions import (
    Client,
    execute_response_action_command,
    create_system_capture_command,
    get_capture_file_command,
    get_action_execution_command,
    get_agent_by_mac_command,
    get_customer_info_command,
    _cache_is_valid,
)

import json
import time


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


KILL_CONTAINER_RESPONSE = util_load_json("test_data/response_api/kill_container_response.json")
GET_ACTION_EXECUTION_RESPONSE = util_load_json("test_data/response_api/get_execution_response.json")
SYSTEM_CAPTURE_RESPONSE = util_load_json("test_data/system_capture/create_response.json")
GET_AGENTS_CONNECTED_RESPONSE = util_load_json("test_data/response_api/get_agents_connected_response.json")
GET_USERS_ME_RESPONSE = util_load_json("test_data/response_api/get_users_me_response.json")


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


# --- _cache_is_valid ---


def test_cache_is_valid_returns_false_when_none():
    assert _cache_is_valid(None) is False


def test_cache_is_valid_returns_false_when_missing_cached_at():
    assert _cache_is_valid({"data": {}}) is False


def test_cache_is_valid_returns_true_when_fresh():
    entry = {"cached_at": time.time() - 100, "data": {}}
    assert _cache_is_valid(entry, ttl=3600) is True


def test_cache_is_valid_returns_false_when_expired():
    entry = {"cached_at": time.time() - 7200, "data": {}}
    assert _cache_is_valid(entry, ttl=3600) is False


# --- get_agent_by_mac_command ---


def test_get_agent_by_mac_api_hit(mock_response, mocker):
    mock_response.return_value.json.return_value = GET_AGENTS_CONNECTED_RESPONSE
    mock_response.return_value.status_code = HTTPStatus.OK
    mocker.patch.object(demisto, "getIntegrationContext", return_value={})
    mock_set_ctx = mocker.patch.object(demisto, "setIntegrationContext")

    client = Client(base_url="https://us2.app.sysdig.com", verify=False, headers={"Authorization": "Bearer token"}, proxy=False)
    result = get_agent_by_mac_command(client, {"machine_id": "aa:bb:cc:dd:ee:01"})
    outputs = result.to_context().get("Contents")

    assert outputs["agentId"] == "99001"
    assert outputs["customerId"] == "55001"
    assert outputs["hostName"] == "ip-10-0-1-100.us-west-2.compute.internal"
    assert outputs["machineId"] == "aa:bb:cc:dd:ee:01"
    assert outputs["hostId"] == "host-uid-aaaa-0001"
    assert outputs["clusterName"] == "prod-us-west-2"
    mock_set_ctx.assert_called_once()


def test_get_agent_by_mac_cache_hit(mocker):
    cached_agent = {
        "agentId": "99001",
        "customerId": "55001",
        "hostName": "cached-host",
        "machineId": "aa:bb:cc:dd:ee:01",
        "hostId": "host-uid-cached",
        "clusterName": "cached-cluster",
    }
    ctx = {"agent_aa:bb:cc:dd:ee:01": {"data": cached_agent, "cached_at": time.time()}}
    mocker.patch.object(demisto, "getIntegrationContext", return_value=ctx)

    client = Client(base_url="https://us2.app.sysdig.com", verify=False, headers={"Authorization": "Bearer token"}, proxy=False)
    result = get_agent_by_mac_command(client, {"machine_id": "aa:bb:cc:dd:ee:01"})
    outputs = result.to_context().get("Contents")

    assert outputs["hostName"] == "cached-host"
    assert outputs["clusterName"] == "cached-cluster"


def test_get_agent_by_mac_force_refresh(mock_response, mocker):
    cached_agent = {
        "agentId": "99001",
        "customerId": "55001",
        "hostName": "stale-host",
        "machineId": "aa:bb:cc:dd:ee:01",
        "hostId": "old-uid",
        "clusterName": "old-cluster",
    }
    ctx = {"agent_aa:bb:cc:dd:ee:01": {"data": cached_agent, "cached_at": time.time()}}
    mocker.patch.object(demisto, "getIntegrationContext", return_value=ctx)
    mocker.patch.object(demisto, "setIntegrationContext")
    mock_response.return_value.json.return_value = GET_AGENTS_CONNECTED_RESPONSE
    mock_response.return_value.status_code = HTTPStatus.OK

    client = Client(base_url="https://us2.app.sysdig.com", verify=False, headers={"Authorization": "Bearer token"}, proxy=False)
    result = get_agent_by_mac_command(client, {"machine_id": "aa:bb:cc:dd:ee:01", "force_refresh": "true"})
    outputs = result.to_context().get("Contents")

    assert outputs["hostName"] == "ip-10-0-1-100.us-west-2.compute.internal"


def test_get_agent_by_mac_not_found(mock_response, mocker):
    mock_response.return_value.json.return_value = GET_AGENTS_CONNECTED_RESPONSE
    mock_response.return_value.status_code = HTTPStatus.OK
    mocker.patch.object(demisto, "getIntegrationContext", return_value={})

    client = Client(base_url="https://us2.app.sysdig.com", verify=False, headers={"Authorization": "Bearer token"}, proxy=False)
    with pytest.raises(ValueError, match="No connected agent found"):
        get_agent_by_mac_command(client, {"machine_id": "ff:ff:ff:ff:ff:ff"})


def test_get_agent_by_mac_missing_machine_id():
    client = Client(base_url="https://us2.app.sysdig.com", verify=False, headers={"Authorization": "Bearer token"}, proxy=False)
    with pytest.raises(ValueError, match="machine_id .* is required"):
        get_agent_by_mac_command(client, {})


# --- get_customer_info_command ---


def test_get_customer_info_api_hit(mock_response, mocker):
    mock_response.return_value.json.return_value = GET_USERS_ME_RESPONSE
    mock_response.return_value.status_code = HTTPStatus.OK
    mocker.patch.object(demisto, "getIntegrationContext", return_value={})
    mock_set_ctx = mocker.patch.object(demisto, "setIntegrationContext")

    client = Client(base_url="https://us2.app.sysdig.com", verify=False, headers={"Authorization": "Bearer token"}, proxy=False)
    result = get_customer_info_command(client, {})
    outputs = result.to_context().get("Contents")

    assert outputs["customerId"] == "55001"
    assert outputs["customerName"] == "Acme Corp"
    mock_set_ctx.assert_called_once()


def test_get_customer_info_cache_hit(mocker):
    ctx = {"customer_info": {"data": {"customer_id": "55001", "customer_name": "Cached Corp"}, "cached_at": time.time()}}
    mocker.patch.object(demisto, "getIntegrationContext", return_value=ctx)

    client = Client(base_url="https://us2.app.sysdig.com", verify=False, headers={"Authorization": "Bearer token"}, proxy=False)
    result = get_customer_info_command(client, {})
    outputs = result.to_context().get("Contents")

    assert outputs["customerId"] == "55001"
    assert outputs["customerName"] == "Cached Corp"


def test_get_customer_info_force_refresh(mock_response, mocker):
    ctx = {"customer_info": {"data": {"customer_id": "00000", "customer_name": "Old Corp"}, "cached_at": time.time()}}
    mocker.patch.object(demisto, "getIntegrationContext", return_value=ctx)
    mocker.patch.object(demisto, "setIntegrationContext")
    mock_response.return_value.json.return_value = GET_USERS_ME_RESPONSE
    mock_response.return_value.status_code = HTTPStatus.OK

    client = Client(base_url="https://us2.app.sysdig.com", verify=False, headers={"Authorization": "Bearer token"}, proxy=False)
    result = get_customer_info_command(client, {"force_refresh": "true"})
    outputs = result.to_context().get("Contents")

    assert outputs["customerId"] == "55001"
    assert outputs["customerName"] == "Acme Corp"
