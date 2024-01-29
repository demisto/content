import demistomock as demisto
import ForwardAuditLogsToSplunkHEC
import pytest
from CommonServerPython import *


def execute_command_side_effect(command: str, args: Dict):
    if command == "splunk-submit-event-hec":
        return [{'Contents': {'response': ["result1"]}}]
    if command == "core-api-post":
        if args["uri"] == '/settings/audits':
            return [{'Contents': {'response': {'total': 2, "audits": ["audit1", "audit2"]}}, "Type": entryTypes["note"]}]
        return [{'Contents': {'response': {'total': 2, "reply": {"data": ["audit1", "audit2"]}}}, "Type": entryTypes["note"]}]
    return None


@pytest.mark.parametrize(
    'xsoar_version, expected_uri',
    [
        ({"version": "6.10"}, "/settings/audits"),
        ({"version": "8.1"}, '/public_api/v1/audits/management_logs')
    ]
)
def test_forward_audit_logs_to_splunk_main_flow(mocker, xsoar_version, expected_uri):
    """
    Given:
        - xsoar version
    When:
        - Calling main flow
    Then:
        - make sure the correct uri is called for each xsoar version
    """
    mocker.patch.object(demisto, 'args', return_value={'timeframe': '3'})
    execute_command_mocker = mocker.patch.object(
        demisto,
        'executeCommand',
        side_effect=execute_command_side_effect
    )
    mocker.patch.object(ForwardAuditLogsToSplunkHEC, "get_demisto_version", return_value=xsoar_version)
    return_results_mocker = mocker.patch.object(ForwardAuditLogsToSplunkHEC, "return_results")
    ForwardAuditLogsToSplunkHEC.main()
    assert return_results_mocker.called
    assert execute_command_mocker.call_args_list[0][0][1]['uri'] == expected_uri
