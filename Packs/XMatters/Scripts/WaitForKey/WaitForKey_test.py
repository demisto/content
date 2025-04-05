# Test runner for WaitForKey

import demistomock as demisto
from WaitForKey import main


def test_main(mocker):
    """Tests WaitForKey script

    :param mocker:
    :return:
    """

    mocker.patch.object(demisto, "args", return_value={"context_key": "XMatters.UserResponseOut", "iterations": "5"})

    context1 = {"XMatters.UserResponseOut": "Ban Host"}
    mocker.patch.object(demisto, "context", return_value=context1)

    main()
    # If we got here we're good.
    assert True
