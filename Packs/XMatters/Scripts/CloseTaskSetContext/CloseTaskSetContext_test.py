# Test runner for CloseTaskSetContext

from CloseTaskSetContext import main
import demistomock as demisto


def test_close_task_set_context(mocker):
    demisto.log('stuff')

    def executeCommand(name, args=None):
        if name == 'taskComplete':
            # Success
            return {}
        else:
            raise ValueError('Unimplemented command called: {}'.format(name))

    mocker.patch.object(demisto, 'args', return_value={
        "entry_id": "waiter",
        "context_key": "XMatters.UserResponseOut",
        "comments": "This is a comment"
    })

    # mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    mocker.patch.object(demisto, 'results')

    main()

    # If we got here we're good.
    assert True
