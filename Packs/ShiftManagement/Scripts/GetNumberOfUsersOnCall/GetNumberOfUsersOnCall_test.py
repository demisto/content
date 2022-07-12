import demistomock as demisto
from GetNumberOfUsersOnCall import main, DemistoException
import pytest

USERS_ON_CALL = [
    {
        'Type': 1,
        'Contents': [
            {
                'id': 'user1',
                'username': 'user1'
            },
            {
                'id': 'user2',
                'username': 'user2'
            },
            {
                'id': 'user3',
                'username': 'user3'
            }
        ]
    }
]

USERS_AWAY = [
    {
        'Type': 1,
        'EntryContext': {
            'AwayUsers': [{'username': 'user2'}]
        }
    }
]


def execute_command(name, args=None):
    if name == 'getUsers':
        return USERS_ON_CALL
    elif name == 'GetAwayUsers':
        return USERS_AWAY
    else:
        return None


def test_get_number_of_users_oncall(mocker):
    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)
    mocker.patch.object(demisto, 'results')
    main()
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0] == 2


def throw_exception(name):
    raise DemistoException('error')


def test_invalid_away_users_call(mocker):
    import GetNumberOfUsersOnCall
    mocker.patch.object(demisto, 'executeCommand', return_value=[{'Type': 4, 'Contents': 'Error'}])
    mocker.patch.object(GetNumberOfUsersOnCall, 'get_error', side_effect=throw_exception)
    with pytest.raises(DemistoException):
        main()
