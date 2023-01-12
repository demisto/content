import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def test_stop_scheduled_task(mocker):
    import StopScheduledTask

    demisto_execute_mock = mocker.patch.object(demisto, 'executeCommand', return_value=[{
        'Type': EntryType.NOTE,
        'ContentFormats': EntryFormat.TEXT,
        'Contents': ''
    }])

    args = {
        'taskID': '100'
    }
    StopScheduledTask.stop_scheduled_task(args)

    execute_command_args = demisto_execute_mock.call_args_list[0][0]
    assert demisto_execute_mock.call_count == 1
    assert execute_command_args[0] == 'scheduleEntry'
    assert execute_command_args[1] == {'cancel': 'cancel', 'id': '100'}
