import json
import io
import pytest
from Packs.NetscoutArborPeakflow.Integrations.NetscoutArborSightline.NetscoutArborSightline import NetscoutClient, \
    fetch_incidents_command, list_alerts_command, alert_annotation_list_command, mitigation_list_command, \
    mitigation_template_list_command, router_list_command, tms_group_list_command, managed_object_list_command, \
    mitigation_create_command
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


@pytest.mark.parametrize(
    'function_to_mock,function_to_test,args,http_response_key,expected_command_results_key', [
        ('list_alerts', list_alerts_command, {}, 'incidents', 'get_incidents'),
        ('get_alert', list_alerts_command, {'alert_id': 1}, 'incident', 'get_incident'),
        ('get_annotations', alert_annotation_list_command, {'alert_id': '2009'}, 'annotations', 'list_annotations'),
        ('list_mitigations', mitigation_list_command, {}, 'mitigations', 'list_mitigations'),
        ('create_mitigation', mitigation_create_command,
         {"description": "just desc", "ip_version": "IPv4", "name": "test_mit", "ongoing": "true",
          "sub_object": "{\"protection_prefixes\": [\"192.0.2.0/24\"]}", "sub_type": "flowspec"}, 'mitigation',
         'create_mitigation'),
        ('mitigation_template_list', mitigation_template_list_command, {}, 'mitigation_templates',
         'list_mitigation_templates'),
        ('router_list', router_list_command, {}, 'routers', 'list_routers'),
        ('managed_object_list', managed_object_list_command, {}, 'managed_objects', 'list_managed_objects'),
        ('tms_group_list', tms_group_list_command, {}, 'tms_groups', 'list_tms_group'),
    ])
def test_list_alerts_commands(mocker, function_to_mock, function_to_test, args, http_response_key,
                              expected_command_results_key):
    """
    Given:
    - NetscoutClient client.

    When:
     - Case A: Calling the list_alerts_command function.
     - Case B: Calling the list_alerts_command function with a specific alert.
     - Case C: Calling the alert_annotation_list_command function.
     - Case D: Calling the mitigation_list_command function with a specific alert.
     - Case E: Calling the mitigation_create_command function with mitigation details.
     - Case F: Calling the mitigation_template_list_command function.
     - Case G: Calling the router_list_command function.
     - Case H: Calling the managed_object_list_command function.
     - Case I: Calling the tms_group_list_command function.

    Then:
     - Case A: Assert that the command results has the relevant alerts with the relevant extracted fields.
     - Case B: Assert that the command results has only one alert and that it has the relevant extracted fields.
     - Case C: Assert that the command results has the relevant annotations with the relevant extracted fields.
     - Case D: Assert that the command results contains the alert ID and has the relevant mitigations with the relevant
            extracted fields.
     - Case E: Assert that the command results has the newly create mitigation with its relevant extracted fields.
     - Case F: Assert that the command results has the relevant mitigation template list with the relevant extracted
            fields.
     - Case G: Assert that the command results has the relevant router list with the relevant extracted fields.
     - Case H: Assert that the command results has the relevant list of manged groups with the relevant extracted
            fields.
     - Case I: Assert that the command results has the relevant list of tms groups with the relevant extracted fields.

    """
    mocked_http_response = http_responses[http_response_key]
    expected_command_results = command_results[expected_command_results_key]

    mocker.patch.object(client, function_to_mock, return_value=mocked_http_response)

    # tms_group_list_command is the only command that does not get args
    if function_to_test == tms_group_list_command:
        command_result: CommandResults = function_to_test(client)
    else:
        command_result: CommandResults = function_to_test(client, args)
    assert command_result.outputs == expected_command_results
