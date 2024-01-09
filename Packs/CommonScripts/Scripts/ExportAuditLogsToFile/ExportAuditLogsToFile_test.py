import demistomock as demisto
import pytest
import ExportAuditLogsToFile
from freezegun import freeze_time
from CommonServerPython import *


def execute_command_side_effect(command: str, args: Dict):
    if command == "splunk-submit-event-hec":
        return [{'Contents': {'response': ["result1"]}}]
    if command == "core-api-post":
        if args["uri"] == '/settings/audits':
            return [{'Contents': {'response': {'total': 2, "audits": ["audit1", "audit2"]}}, "Type": entryTypes["note"]}]
        return [{'Contents': {'response': {'total': 2, "reply": {"data": ["audit1", "audit2"]}}}, "Type": entryTypes["note"]}]
    return None


@freeze_time('2020-04-20')
def test_main_no_logs_xsoar6(mocker):
    mocker.patch.object(demisto, 'args', return_value={'output': 'html', 'days_back': '5'})
    execute_command_mock = mocker.patch.object(
        demisto, 'executeCommand', return_value=[{'Contents': {'response': {'total': 0}}, "Type": entryTypes["note"]}]
    )
    mocker.patch.object(ExportAuditLogsToFile, "get_demisto_version", return_value={"version": "6.10"})
    ExportAuditLogsToFile.main()
    assert execute_command_mock.call_args.args[1]['body']['fromDate'] == '2020-04-15T00:00:00Z'


@freeze_time('2020-04-20')
@pytest.mark.parametrize(
    'xsoar_version, expected_uri',
    [
        ({"version": "6.10"}, "/settings/audits"),
        ({"version": "8.1"}, '/public_api/v1/audits/management_logs')
    ]
)
def test_main_with_logs(mocker, xsoar_version, expected_uri):
    """
    Given:
        - xsoar version
    When:
        - Calling main flow
    Then:
        - make sure the correct uri is called for each xsoar version
        - make sure audit logs are fetched when its xsoar 6/8
    """
    mocker.patch.object(demisto, 'args', return_value={'output': 'json', 'days_back': '5'})
    execute_command_mocker = mocker.patch.object(
        demisto,
        'executeCommand',
        side_effect=execute_command_side_effect
    )
    mocker.patch.object(ExportAuditLogsToFile, "fileResult", return_value=["audit1", "audit2"])
    mocker.patch.object(ExportAuditLogsToFile, "get_demisto_version", return_value=xsoar_version)
    demisto_results_mocker = mocker.patch.object(demisto, "results", return_value=[])
    ExportAuditLogsToFile.main()
    assert demisto_results_mocker.called
    assert "Fetched 2 audit log events" in demisto_results_mocker.call_args_list[1][0][0]
    assert execute_command_mocker.call_args_list[0][0][1]["uri"] == expected_uri
