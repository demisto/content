import demistomock as demisto
from CommonServerPython import *
import pytest


def test_MattermostAskUser_with_error(mocker):
    """
    Given:
        - Execute the MattermostAskUser command.
    When:
        - The execute command ('addEntitlement') result has an error entry.
    Then:
        - Validating the results and the calling to sys.exit after.
    """
    from MattermostAskUser import main
    execute_command_res = [{'Contents': [], 'Type': EntryType.ERROR}]
    mocker.patch.object(demisto, 'executeCommand', return_value=execute_command_res)
    results_mock = mocker.patch.object(demisto, 'results')
    with pytest.raises(SystemExit) as pytest_wrapped_e:
        main()
    results = results_mock.call_args[0][0]
    assert results == execute_command_res
    assert pytest_wrapped_e.type is SystemExit
    assert pytest_wrapped_e.value.code == 0


def test_MattermostAskUser(mocker):
    """
    Given:
        - The script args.
    When:
        - Running the MattermostAskUser command.
    Then:
        - Validating the results after manipulating the data and execute the 'send-notification' command.
    """
    from MattermostAskUser import main
    mocker.patch.object(demisto, 'args', return_value={'message': 'message', 'persistent': 'persistent',
                                                       'replyEntriesTag': 'replyEntriesTag',
                                                       'task': '1', 'user': {'email'}, 'lifetime': 'test'})
    execute_command_add_entitlement_res = [{'Type': EntryType.NOTE, 'Contents': 'some-guid'}]
    execute_command_send_notification_res = [{'Type': EntryType.NOTE, 'HumanReadable':
                                                                      'Message sent to Mattermost successfully.'
                                                                      ' \nThread ID is: 1660645689.649679'}]
    execute_mock = mocker.patch.object(demisto, 'executeCommand', side_effect=[execute_command_add_entitlement_res,
                                                                               execute_command_send_notification_res])
    results_mock = mocker.patch.object(demisto, 'results')
    main()
    assert execute_mock.call_count == 2
    results_mock.assert_called_once()
    results = results_mock.call_args[0][0]
    assert results == execute_command_send_notification_res
