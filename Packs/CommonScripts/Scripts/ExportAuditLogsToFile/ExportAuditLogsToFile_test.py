import demistomock as demisto
import ExportAuditLogsToFile
from freezegun import freeze_time
from CommonServerPython import *


@freeze_time('2020-04-20')
def test_main_no_logs_xsoar6(mocker):
    mocker.patch.object(demisto, 'args', return_value={'output': 'html', 'days_back': '5'})
    execute_command_mock = mocker.patch.object(
        demisto, 'executeCommand', return_value=[{'Contents': {'response': {'total': 0}}}]
    )
    ExportAuditLogsToFile.main()
    assert execute_command_mock.call_args.args[1]['body']['fromDate'] == '2020-04-15T00:00:00Z'


@freeze_time('2020-04-20')
def test_main_with_logs_xsoar6(mocker):
    mocker.patch.object(demisto, 'args', return_value={'output': 'json', 'days_back': '5'})
    execute_command_mocker = mocker.patch.object(
        demisto,
        'executeCommand',
        return_value=[{'Contents': {'response': {'total': 2, "audits": ["audit1", "audit2"], "Type": entryTypes["note"]}}}]
    )
    mocker.patch.object(ExportAuditLogsToFile, "fileResult", return_value=["audit1", "audit2"])
    mocker.patch.object(ExportAuditLogsToFile, "get_demisto_version", return_value={"version": "6.10"})
    demisto_results_mocker = mocker.patch.object(demisto, "results", return_value=[])
    ExportAuditLogsToFile.main()
    assert demisto_results_mocker.called
    assert "Fetched 2 audit log events" in demisto_results_mocker.call_args_list[1][0][0]
    assert execute_command_mocker.call_args_list[0][0][1]["uri"] == '/settings/audits'


@freeze_time('2020-04-20')
def test_main_with_logs_xsoar8(mocker):
    mocker.patch.object(demisto, 'args', return_value={'output': 'json', 'days_back': '5'})
    execute_command_mocker = mocker.patch.object(
        demisto,
        'executeCommand',
        return_value=[{'Contents': {'response': {'total': 2, "reply": {"data": ["audit1", "audit2"]}, "Type": entryTypes["note"]}}}]
    )
    mocker.patch.object(ExportAuditLogsToFile, "fileResult", return_value=["audit1", "audit2"])
    mocker.patch.object(ExportAuditLogsToFile, "get_demisto_version", return_value={"version": "8.1"})
    demisto_results_mocker = mocker.patch.object(demisto, "results", return_value=[])
    ExportAuditLogsToFile.main()
    assert demisto_results_mocker.called
    assert "Fetched 2 audit log events" in demisto_results_mocker.call_args_list[1][0][0]
    assert execute_command_mocker.call_args_list[0][0][1]["uri"] == '/public_api/v1/audits/management_logs'