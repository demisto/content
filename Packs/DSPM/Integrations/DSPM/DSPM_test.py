import json
import pytest
import demistomock as demisto  # noqa: F401
from datetime import datetime  # noqa: F401
from unittest.mock import patch, MagicMock  # noqa: F401
from CommonServerPython import *  # noqa: F401

from DSPM import (
    Client,
    test_module,
    get_risk_findings_command
)


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


# Helper function to mock http request
def mock_http_request(method, url_suffix, params=None, headers=None, data=None, json_data=None):
    if url_suffix == '/v1/risk-findings':
        return util_load_json('test_data/risk-findings-response.json')
    elif url_suffix.startswith('/v1/assets/id?id='):
        return {'id': 'asset1', 'name': 'Test Asset'}
    elif 'status' in url_suffix:
        return {'status': 'updated'}
    return {}


@pytest.fixture
def client() -> Client:
    return Client(
        base_url='https://example.com',
        api_key='api_key',
        verify=True,
        proxy=False
    )


def test_test_module(client: Client, mocker):
    mocker.patch.object(client, '_http_request', side_effect=mock_http_request)
    result = test_module(client)
    assert result == 'ok'


def test_get_risk_findings_command(client: Client, mocker):
    mocker.patch.object(client, '_http_request', side_effect=mock_http_request)
    args = {}
    result = get_risk_findings_command(client, args)
    assert isinstance(result, CommandResults)
    assert result.outputs[0]['id'] == '7e9a3891-8970-4c08-961a-03f49e239d68'


# def test_get_asset_details_command(client, mocker):
#     mocker.patch.object(client, '_http_request', side_effect=mock_http_request)
#     args = {'asset_id': 'asset1'}
#     result = get_asset_details_command(client, args)
#     assert isinstance(result, CommandResults)
#     assert result.outputs['asset']['name'] == 'Test Asset'


# def test_update_risk_finding_status_command(client, mocker):
#     mocker.patch.object(client, '_http_request', side_effect=mock_http_request)
#     args = {'findingId': '1', 'status': 'OPEN'}
#     with patch('demistomock.return_results') as mock_return_results:
#         update_risk_finding_status_command(client, args)
#         mock_return_results.assert_called_once_with('Risk finding 1 updated to status OPEN')


# # TODO: REMOVE the following dummy unit test function
# def test_baseintegration_dummy():
#     """Tests helloworld-say-hello command function.

#     Checks the output of the command function with the expected output.

#     No mock is needed here because the say_hello_command does not call
#     any external API.
#     """
#     from BaseIntegration import Client, baseintegration_dummy_command

#     client = Client(base_url='some_mock_url', verify=False)
#     args = {
#         'dummy': 'this is a dummy response'
#     }
#     response = baseintegration_dummy_command(client, args)

#     mock_response = util_load_json('test_data/baseintegration-dummy.json')

#     assert response.outputs == mock_response
# # TODO: ADD HERE unit tests for every command
