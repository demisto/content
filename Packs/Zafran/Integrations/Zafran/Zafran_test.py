import pytest
import io
from CommonServerPython import *
from Zafran import Client, mitigation_performed_command, mitigations_export_command, mitigations_performed_command
SERVER_URL = 'https://test_url.com'


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


@pytest.fixture()
def client():
    return Client(server_url=SERVER_URL, verify=None, proxy=None, headers=None, auth=None)


def test_mitigation_performed_command(client, requests_mock):
    """
        When:
        Given:
        Then:
        """
    args = {'external_ticket_id': 'ticketid', 'external_ticket_url':
            'ticketurl', 'id': 'id', 'state': 'in_progress'}
    mock_response_mitigation_performed_request = util_load_json(
        './test_data/outputs/mitigation_performed_request.json')
    requests_mock.post(f"{SERVER_URL}/mitigations/performed", json=mock_response_mitigation_performed_request)
    results = mitigation_performed_command(client=client, args=args)
    assert results.outputs_prefix == 'Zafran.MitigationsPerformedResponse'
    assert results.outputs_key_field == ''
    assert results.readable_output == 'Mitigation status updated successfully'
    assert results.raw_response == mock_response_mitigation_performed_request


def test_mitigations_export_command(client, requests_mock):
    """
        When:
        Given:
        Then:
        """
    args = {}
    mock_response_mitigations_export_request = util_load_json(
        './test_data/outputs/mitigations_export_request.json')
    mock_results = util_load_json(
        './test_data/outputs/mitigations_export_command.json')
    requests_mock.get(f"{SERVER_URL}/mitigations", json=mock_response_mitigations_export_request)
    results = mitigations_export_command(client=client, args=args)
    assert results.outputs_prefix == 'Zafran.UpstreamMitigation'
    assert results.outputs_key_field == 'id'
    assert results.outputs == mock_results.get('outputs')
    assert results.raw_response == mock_response_mitigations_export_request


def test_mitigations_performed_command(client, requests_mock):
    """
        When:
        Given:
        Then:
        """
    args = {'mitigation_id': None, 'mitigation_ids': 'id1,id2', 'state':
            'in_progress'}
    mock_response_mitigations_performed_request = util_load_json(
        './test_data/outputs/mitigations_performed_request.json')
    requests_mock.post(f"{SERVER_URL}/mitigations", json=mock_response_mitigations_performed_request)
    results = mitigations_performed_command(client=client, args=args)
    assert results.outputs_prefix == 'Zafran.MitigationsPerformedResponse'
    assert results.outputs_key_field == ''
    assert results.readable_output == 'Mitigations status updated successfully'
    assert results.raw_response == mock_response_mitigations_performed_request
