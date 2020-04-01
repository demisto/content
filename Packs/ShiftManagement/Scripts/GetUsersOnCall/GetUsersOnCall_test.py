import pytest
import demistomock as demisto
from GetUsersOnCall import main

USERS_ON_CALL_RESULTS = [
    {
        'Type': 1,
        'HumanReadable': '## On-Call Users'
                         'Username | Email | Name | Phone | Roles'
                         '-|-|-|-|'
                         'bar | bar@demisto.com | Bar Lolz | \+650-123456 | demisto: \[AnalystShift\]'
                         'eliya | eliya@demisto.com | Eliya Sadan | \+650-655989 | demisto: \[AnalystShift\]'
                         'ido | ido@demisto.com | Ido Shavit | \+650-655989 | demisto: \[AnalystShift\]'
                         'yuval | yuval@demisto.com | Yuval Ben-Shalom | \+650-655989 | demisto: \[AnalystShift\]'
    }
]


def execute_command(name, args=None):
    if name == 'getUsers':
        return USERS_ON_CALL_RESULTS
    else:
        return None


def test_get_users_on_call(mocker):
    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)
    mocker.patch.object(demisto, 'results')
    main()
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert USERS_ON_CALL_RESULTS[0]['HumanReadable'] == results[0]
