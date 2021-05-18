import demistomock as demisto
from GetShiftsPerUser import main

ROLES = [
    {
        'name': 'Shift1',
        'shifts': [
            {'fromDay': 0, 'fromHour': 8, 'fromMinute': 0, 'toDay': 3,
             'toHour': 12, 'toMinute': 0},
            {'fromDay': 4, 'fromHour': 16, 'fromMinute': 0, 'toDay': 6,
             'toHour': 20, 'toMinute': 0}
        ]
    },
    {
        'name': 'Administrator',
        'shifts': None
    },
    {
        'name': 'Shift2',
        'shifts': [
            {'fromDay': 0, 'fromHour': 8, 'fromMinute': 0, 'toDay': 3,
             'toHour': 12, 'toMinute': 0},
            {'fromDay': 4, 'fromHour': 16, 'fromMinute': 0, 'toDay': 6,
             'toHour': 20, 'toMinute': 0},
            {'fromDay': 1, 'fromHour': 3, 'fromMinute': 0, 'toDay': 4,
             'toHour': 6, 'toMinute': 0}
        ]
    }
]

USERS = [
    {
        'Type': 1,
        'Contents': [
            {
                'id': 'user1',
                'name': 'User1',
                'roles': {
                    'demisto': ['Shift1']
                },
                "allRoles": ['Shift1', 'Administrator']
            },
            {
                'id': 'admin',
                'name': 'Admin',
                'roles': {
                    'demisto': ['Administrator']
                },
                "allRoles": ['Administrator']
            }
        ]
    }
]

GET_ROLES_RESPONSE = [{
    'Type': 1,
    'Contents': ROLES
}]


def execute_command(name, args=None):
    if name == 'getRoles':
        return GET_ROLES_RESPONSE
    elif name == 'getUsers':
        return USERS
    else:
        return None


def test_get_shifts_per_user(mocker):
    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'args', return_value={'userId': 'user1'})
    main()
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert """### User1's Shifts
|Start|End|
|---|---|
| Sunday 08:00 | Wednesday 12:00 |
| Thursday 16:00 | Saturday 20:00 |
""" in results[0]
