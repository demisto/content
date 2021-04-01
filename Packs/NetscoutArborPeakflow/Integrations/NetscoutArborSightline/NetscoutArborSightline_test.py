import json
import io
import pytest
from Packs.NetscoutArborPeakflow.Integrations.NetscoutArborSightline.NetscoutArborSightline import NetscoutClient, \
    fetch_incidents_command, list_alerts_command, alert_annotation_list_command, mitigation_list_command, \
    mitigation_template_list_command
import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import


# from Packs

def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


client = NetscoutClient(base_url='dummy_url', verify=False, proxy=False, first_fetch='3 days', max_fetch=10)
http_responses = util_load_json(
    'Packs/NetscoutArborPeakflow/Integrations/NetscoutArborSightline/test_data/http_responses.json')
command_results = util_load_json(
    'Packs/NetscoutArborPeakflow/Integrations/NetscoutArborSightline/test_data/command_results.json')


@pytest.fixture(autouse=True)
def setup(mocker):
    mocker.patch.object(demisto, 'debug')


def test_fetch_incidents_command(mocker):
    """
    Given:
    - NetscoutClient client.

    When:
     - Fetching incidents.

    Then:
     - Ensure that the incidents returned are as expected.
    """
    alerts_http_response = http_responses['incidents']
    alerts_command_results = command_results['fetched_incidents']

    mocker.patch.object(client, "list_alerts", return_value=alerts_http_response)
    mocker.patch.object(client, "calculate_amount_of_incidents", return_value=40)
    mocker.patch.object(demisto, 'incidents')

    fetch_incidents_command(client)
    demisto.incidents.assert_called_with(alerts_command_results)


@pytest.mark.parametrize('function_to_mock,http_response_key,expected_command_results_key,args', [
    ('list_alerts', 'incidents', 'get_incidents', {}),
    ('get_alert', 'incident', 'get_incident', {'alert_id': 1})
])
def test_list_alerts_commands(mocker, function_to_mock, http_response_key, expected_command_results_key, args):
    alerts_http_response = http_responses[http_response_key]
    alerts_command_results = command_results[expected_command_results_key]

    mocker.patch.object(client, function_to_mock, return_value=alerts_http_response)

    command_result: CommandResults = list_alerts_command(client, args)
    assert command_result.outputs == alerts_command_results


def test_alert_annotation_list_command(mocker):
    alerts_http_response = http_responses['annotations']
    alerts_command_results = command_results['list_annotations']

    mocker.patch.object(client, 'get_annotations', return_value=alerts_http_response)

    command_result = alert_annotation_list_command(client, {'alert_id': '2009'})
    assert command_result.outputs == alerts_command_results


def test_mitigation_list_command(mocker):
    alerts_http_response = http_responses['mitigations']
    alerts_command_results = command_results['list_mitigations']

    mocker.patch.object(client, 'list_mitigations', return_value=alerts_http_response)

    command_result = mitigation_list_command(client, {})
    assert command_result.outputs == alerts_command_results


def test_mitigation_template_list_command(mocker):
    alerts_http_response = http_responses['mitigation_templates']
    alerts_command_results = command_results['list_mitigation_templates']

    mocker.patch.object(client, 'mitigation_template_list', return_value=alerts_http_response)

    command_result = mitigation_template_list_command(client, {})
    assert command_result.outputs == alerts_command_results
