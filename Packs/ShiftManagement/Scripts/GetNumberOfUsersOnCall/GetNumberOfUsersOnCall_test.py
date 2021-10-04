import demistomock as demisto
from GetNumberOfUsersOnCall import main

USERS_ON_CALL = [
    {
        'Type': 1,
        'Contents': [
            {
                'id': 'user1'
            },
            {
                'id': 'user2'
            },
            {
                'id': 'user3'
            }
        ]
    }
]


def execute_command(name, args=None):
    if name == 'getUsers':
        return USERS_ON_CALL
    else:
        return None


def test_get_number_of_users_oncall(mocker):
    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)
    mocker.patch.object(demisto, 'results')
    main()
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0] == 3
