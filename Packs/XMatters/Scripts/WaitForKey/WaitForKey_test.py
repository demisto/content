# Test runner for WaitForKey

from WaitForKey import main
import demistomock as demisto


def test_main(mocker):
    """Tests WaitForKey script

    :param mocker:
    :return:
    """

    mocker.patch.object(demisto, 'args', return_value={
        "context_key": "XMatters.UserResponseOut",
        "iterations": "5"
    })

    context1 = {
        'XMatters.UserResponseOut': 'Ban Host'
    }
    mocker.patch.object(demisto, 'context', return_value=context1)

    main()
    # If we got here we're good.
    assert True
