"""
Sysdig Response Actions Integration - Unit Tests file
"""

import pytest
from http import HTTPStatus
import requests
from unittest.mock import patch
from SysdigResponseActions import Client, call_response_api_command, create_system_capture_command, download_capture_file_command

import json


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())

KILL_CONTAINER_RESPONSE = util_load_json('response_actions/Integrations/Sysdig-Response-Actions/test_data/response_api/kill_container_response.json')
SYSTEM_CAPTURE_RESPONSE = util_load_json('response_actions/Integrations/Sysdig-Response-Actions/test_data/system_capture/create_response.json')


# TODO: ADD HERE unit tests for every command
@pytest.fixture
def mock_response():
    """Fixture to mock the session.request method"""
    with patch.object(requests.Session, "request") as mock_request:
        yield mock_request

def test_call_response_api(mock_response):
    # Successful response
    mock_response.return_value.json.return_value = KILL_CONTAINER_RESPONSE
    mock_response.return_value.status_code = HTTPStatus.OK
    client = Client(base_url='https://us2.app.sysdig.com', verify=False, headers={'Authorization': 'Bearer token'}, proxy=False)
    result = call_response_api_command(client, {'method': 'POST', 'url_suffix': '/secure/response-actions/v1alpha1/action-executions', 'actionType': 'KILL_CONTAINER', 'container_id': '123456789012', "callerId": "test_kill_container_07"})
    result = result.to_context().get('Contents')
    assert result.get('actionType') == 'KILL_CONTAINER' and result.get('status') == 'created' and result.get('callerId') == 'test_kill_container_07' and result.get('executionContext').get('container.id') == '123456789012'

def test_create_system_capture(mock_response):
    # Successful response
    mock_response.return_value.json.return_value = SYSTEM_CAPTURE_RESPONSE
    mock_response.return_value.status_code = HTTPStatus.OK
    client = Client(base_url='https://us2.app.sysdig.com', verify=False, headers={'Authorization': 'Bearer token'}, proxy=False)
    result = create_system_capture_command(client, {'method': 'POST', 'url_suffix': '/secure/response-actions/v1alpha1/action-executions', 'host_name': 'ip-1-2-3-4.us-west-1.compute.internal', 'container_id': '123456789012', "capture_name": "test_capture", "agent_id": "123456789012", "customer_id": "123456789012", "machine_id": "aa:bb:cc:11:22:33"})
    result = result.to_context().get('Contents').get('capture')
    assert result.get('status') == 'requested' and result.get('agent').get('machineId') == "aa:bb:cc:11:22:33" and result.get('containerId') == '123456789012' and result.get('agent').get('hostName') == "ip-1-2-3-4.us-west-1.compute.internal"

def test_download_capture(mock_response):
    # Successful response
    mock_response.return_value.content = bytes(b'abc') # Dummy bytes
    mock_response.return_value.status_code = HTTPStatus.OK
    client = Client(base_url='https://us2.app.sysdig.com', verify=False, headers={'Authorization': 'Bearer token'}, proxy=False)
    result = download_capture_file_command(client, {'capture_id': '1234567890'})
    result = result.to_context().get('Contents')
