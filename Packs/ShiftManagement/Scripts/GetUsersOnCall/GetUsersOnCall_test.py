import demistomock as demisto
from GetUsersOnCall import main

USERS_ON_CALL_RESULTS = [
    {
        'Type': 1,
        'HumanReadable': '## On-Call Users'
                         'Username | Email | Name | Phone | Roles'
                         '-|-|-|-|'
                         'batman | batman@demisto.com | Batman | \+650-123456 | demisto: \[AnalystShift\]'
                         'robin | robin@demisto.com | Robin | \+650-655989 | demisto: \[AnalystShift\]'
                         'joker | joker@demisto.com | The Joker | \+650-655989 | demisto: \[AnalystShift\]'
                         'brucewaine | bwaine@demisto.com | Bruce Waine | \+650-655989 | demisto: \[AnalystShift\]'
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
    assert USERS_ON_CALL_RESULTS[0]['HumanReadable'] == results[0]['Contents']
