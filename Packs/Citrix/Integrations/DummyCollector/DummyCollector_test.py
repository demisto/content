import pytest
from DummyCollector import main
import demistomock as demisto


def test_okta_get_events_not_implemented(mocker):
    """
    Given:
        - The okta-get-events command is called.
    When:
        - The command is dispatched in main().
    Then:
        - A NotImplementedError should be raised and return_error should be called.
    """
    mocker.patch.object(demisto, 'command', return_value='okta-get-events')
    mocker.patch.object(demisto, 'params', return_value={})
    mocker.patch.object(demisto, 'args', return_value={})
    return_error_mock = mocker.patch('DummyCollector.return_error')

    main()

    assert return_error_mock.called
    assert 'not implemented' in return_error_mock.call_args[0][0].lower()
