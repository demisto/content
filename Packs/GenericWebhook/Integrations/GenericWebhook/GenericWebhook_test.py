import asyncio
import json
from http import HTTPStatus
from unittest.mock import patch, MagicMock
# import demistomock as demisto
from fastapi import Request
import pytest
from fastapi.testclient import TestClient

from GenericWebhook import app, parse_incidents
from CommonServerPython import *


@pytest.fixture
def client():
    return TestClient(app)


def test_handle_post_single_incident(mocker, client):
    incident_data = {"name": "Test Incident", "type": "Test Type", "occurred": "2024-03-17T12:00:00Z",
                     "raw_json": {"key": "value"}}
    return_incidents = [{'name': 'something'}]

    create_incidents = mocker.patch.object(demisto, 'createIncidents', return_value=return_incidents)
    response = client.post('/', json=incident_data)

    called_arg = create_incidents.call_args_list[0].args[0]
    assert isinstance(called_arg, list) and len(called_arg) == 1
    assert response.status_code == HTTPStatus.OK
    assert response.json() == return_incidents


def test_handle_post_multiple_incident(mocker, client):
    incident_data = [{"name": "Test Incident", "type": "Test Type", "occurred": "2024-03-17T12:00:00Z",
                      "raw_json": {"key": "value"}},
                     {"name": "Test Incident2", "type": "Test Type", "occurred": "2024-03-17T12:00:00Z",
                      "raw_json": {"key": "value"}}]
    return_incidents = [{'name': 'something'}]

    create_incidents = mocker.patch.object(demisto, 'createIncidents', return_value=return_incidents)
    response = client.post('/', json=incident_data)

    called_arg = create_incidents.call_args_list[0].args[0]
    assert isinstance(called_arg, list) and len(called_arg) == 2
    assert response.status_code == HTTPStatus.OK
    assert response.json() == return_incidents


def test_handle_post_with_invalid_credentials(mocker, client):
    mocker.patch.object(demisto, 'params', return_value={'credentials': {
        'identifier': 'user',
        'password': 'pass'
    }})
    response = client.post('/', json=[{"name": "Test Incident"}], auth=('invalid_username', 'invalid_password'))
    assert response.status_code == HTTPStatus.UNAUTHORIZED
    assert response.text == 'Authorization failed.'


def test_handle_post_with_valid_credentials(mocker, client):
    mocker.patch.object(demisto, 'params', return_value={'credentials': {
        'identifier': 'user',
        'password': 'pass'
    }})
    response = client.post('/', json=[{"name": "Test Incident"}], auth=('user', 'pass'))
    # assert response.status_code == HTTPStatus.OK
    # assert response.text == '[]'


def test_handle_post_with_missing_data(mocker, client):
    mocker.patch.object(demisto, 'error')
    response = client.post('/')
    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert 'Request, and raw_json field must be in JSON format' in response.text


def test_handle_post_with_invalid_json(mocker, client):
    mocker.patch.object(demisto, 'error')
    response = client.post('/', data='invalid_json')
    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert 'Request, and raw_json field must be in JSON format' in response.text


@pytest.mark.parametrize('body', [
    '''[{"name": "Test Incident 1", "type": "Test Type 1", 
"occurred": "2024-03-17T12:00:00Z",
"raw_json": {"key": "value"}}]''',
    json.dumps([
        {"name": "Test Incident 1", "type": "Test Type 1",
         "occurred": "2024-03-17T12:00:00Z",
         "raw_json": "{\"key\" : \"value\"}"}])])
def test_parse_request(body):
    # Prepare a mock Request object with JSON data
    mock_request = MagicMock(spec=Request)

    async def mockbody():
        return body.encode('utf-8')

    mock_request.body = mockbody

    # Call the parse_incidents function with the mock Request
    result = asyncio.run(parse_incidents(mock_request))

    # Check if the function returns a list of dictionaries with the parsed incidents
    assert isinstance(result, list)
    assert len(result) == 1
    assert result[0]['name'] == 'Test Incident 1'
    assert result[0]['type'] == 'Test Type 1'
    assert result[0]['occurred'] == '2024-03-17T12:00:00Z'
    assert result[0]['raw_json'] == {'key': 'value'}
