import demistomock as demisto
from ExportAuditLogsToFile import main
from freezegun import freeze_time


@freeze_time('2020-04-20')
def test_main(mocker):
    mocker.patch.object(demisto, 'args', return_value={'output': 'html', 'days_back': '5'})
    execute_command_mock = mocker.patch.object(demisto, 'executeCommand',
                                               return_value=[{'Contents': {'response': {'total': 0}}}])
    main()
    assert execute_command_mock.call_args.args[1]['body']['fromDate'] == '2020-04-15T00:00:00Z'
