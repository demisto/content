import demistomock as demisto
from GetUsersOnCall import main

USERS_ON_CALL_RESULTS = [
    {
        'Type': 1,
        'Contents': [
            {
                'email': 'batman@demisto.com', 'name': 'Batman',
                'phone': '+650-123456', 'roles': {'demisto': ['AnalystShift']},
                'username': 'batman'
            },
            {
                'email': 'robin@demisto.com', 'name': 'Robin',
                'phone': '+650-655989', 'roles': {'demisto': ['AnalystShift']},
                'username': 'robin'
            },
            {
                'email': 'joker@demisto.com', 'name': 'The Joker',
                'phone': '+650-655989', 'roles': {'demisto': ['AnalystShift']},
                'username': 'joker'
            },
            {
                'email': 'bwaine@demisto.com', 'name': 'Bruce Waine',
                'phone': '+650-655989', 'roles': {'demisto': ['AnalystShift']},
                'username': 'brucewaine'
            },
        ],
        'HumanReadable': '### On-Call Users\n'
                         '|username|email|name|phone|roles|\n'
                         '|---|---|---|---|---|\n'
                         '| batman | batman@demisto.com | Batman | +650-123456 | demisto: AnalystShift |\n'
                         '| robin | robin@demisto.com | Robin | +650-655989 | demisto: AnalystShift |\n'
                         '| joker | joker@demisto.com | The Joker | +650-655989 | demisto: AnalystShift |\n'
                         '| brucewaine | bwaine@demisto.com | Bruce Waine | +650-655989 | demisto: AnalystShift |\n'
    }
]

OOO_USERS_LIST_RESULT = [{
    'Type': 1,
    'Contents': '[{"user": "brucewaine", "offuntil": "2021-01-07", "addedby": "admin"}]',
    'HumanReadable': 'Done: list OOO List was succesfully loaded:\n\n[{"user": "brucewaine", '
                     '"offuntil": "2021-01-07", "addedby": "admin"}]'
}]


def execute_command(name, args=None):
    if name == 'getUsers':
        return USERS_ON_CALL_RESULTS
    elif name == 'getList':
        return OOO_USERS_LIST_RESULT
    else:
        return None


def test_get_users_on_call(mocker):
    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)
    mocker.patch.object(demisto, 'results')

    # Validate that the output of the script is identical to the input human readable when all users (including Out Of
    # Office users) should be returned:
    mocker.patch.object(demisto, 'args', return_value={'include_OOO_users': 'true'})
    main()
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert USERS_ON_CALL_RESULTS[0]['HumanReadable'] == results[0]['Contents']

    # Validate that the user that is defined in the `OOO List` is not in the output when filtering out the OOO users:
    mocker.patch.object(demisto, 'args', return_value={'include_OOO_users': 'false'})
    main()
    results = demisto.results.call_args[0]
    assert 'brucewaine' not in results[0]['Contents']
