import demistomock as demisto
from GetRolesPerShift import main

ROLES = [
    {
        'name': 'Shift1',
        'shifts': [
            {'fromDay': 0, 'fromHour': 8, 'fromMinute': 0, 'toDay': 3, 'toHour': 12, 'toMinute': 0},
            {'fromDay': 4, 'fromHour': 16, 'fromMinute': 0, 'toDay': 6, 'toHour': 20, 'toMinute': 0}
        ]
    },
    {
        'name': 'Administrator',
        'shifts': None
    },
    {
        'name': 'Shift2',
        'shifts': [
            {'fromDay': 0, 'fromHour': 8, 'fromMinute': 0, 'toDay': 3, 'toHour': 12, 'toMinute': 0},
            {'fromDay': 4, 'fromHour': 16, 'fromMinute': 0, 'toDay': 6, 'toHour': 20, 'toMinute': 0},
            {'fromDay': 1, 'fromHour': 3, 'fromMinute': 0, 'toDay': 4, 'toHour': 6, 'toMinute': 0}
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
    else:
        return None


def test_get_shifts(mocker):
    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)
    mocker.patch.object(demisto, 'results')
    main()
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0] == """Roles Per Shift
|Hours / Days|Sunday|Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|
|---|---|---|---|---|---|---|---|
| __0:00 - 1:00__ |  | Shift1, Shift2 | Shift1, Shift2 | Shift1, Shift2 | Shift2 | Shift1, Shift2 | Shift1, Shift2 |
| __1:00 - 2:00__ |  | Shift1, Shift2 | Shift1, Shift2 | Shift1, Shift2 | Shift2 | Shift1, Shift2 | Shift1, Shift2 |
| __2:00 - 3:00__ |  | Shift1, Shift2 | Shift1, Shift2 | Shift1, Shift2 | Shift2 | Shift1, Shift2 | Shift1, Shift2 |
| __3:00 - 4:00__ |  | Shift1, Shift2 | Shift1, Shift2 | Shift1, Shift2 | Shift2 | Shift1, Shift2 | Shift1, Shift2 |
| __4:00 - 5:00__ |  | Shift1, Shift2 | Shift1, Shift2 | Shift1, Shift2 | Shift2 | Shift1, Shift2 | Shift1, Shift2 |
| __5:00 - 6:00__ |  | Shift1, Shift2 | Shift1, Shift2 | Shift1, Shift2 | Shift2 | Shift1, Shift2 | Shift1, Shift2 |
| __6:00 - 7:00__ |  | Shift1, Shift2 | Shift1, Shift2 | Shift1, Shift2 |  | Shift1, Shift2 | Shift1, Shift2 |
| __7:00 - 8:00__ |  | Shift1, Shift2 | Shift1, Shift2 | Shift1, Shift2 |  | Shift1, Shift2 | Shift1, Shift2 |
| __8:00 - 9:00__ | Shift1, Shift2 | Shift1, Shift2 | Shift1, Shift2 | Shift1, Shift2 |  | Shift1, Shift2 | Shift1, Shift2 |
| __9:00 - 10:00__ | Shift1, Shift2 | Shift1, Shift2 | Shift1, Shift2 | Shift1, Shift2 |  | Shift1, Shift2 | Shift1, Shift2 |
| __10:00 - 11:00__ | Shift1, Shift2 | Shift1, Shift2 | Shift1, Shift2 | Shift1, Shift2 |  | Shift1, Shift2 | Shift1, Shift2 |
| __11:00 - 12:00__ | Shift1, Shift2 | Shift1, Shift2 | Shift1, Shift2 | Shift1, Shift2 |  | Shift1, Shift2 | Shift1, Shift2 |
| __12:00 - 13:00__ | Shift1, Shift2 | Shift1, Shift2 | Shift1, Shift2 | Shift2 |  | Shift1, Shift2 | Shift1, Shift2 |
| __13:00 - 14:00__ | Shift1, Shift2 | Shift1, Shift2 | Shift1, Shift2 | Shift2 |  | Shift1, Shift2 | Shift1, Shift2 |
| __14:00 - 15:00__ | Shift1, Shift2 | Shift1, Shift2 | Shift1, Shift2 | Shift2 |  | Shift1, Shift2 | Shift1, Shift2 |
| __15:00 - 16:00__ | Shift1, Shift2 | Shift1, Shift2 | Shift1, Shift2 | Shift2 |  | Shift1, Shift2 | Shift1, Shift2 |
| __16:00 - 17:00__ | Shift1, Shift2 | Shift1, Shift2 | Shift1, Shift2 | Shift2 | Shift1, Shift2 | Shift1, Shift2 | Shift1, Shift2 |
| __17:00 - 18:00__ | Shift1, Shift2 | Shift1, Shift2 | Shift1, Shift2 | Shift2 | Shift1, Shift2 | Shift1, Shift2 | Shift1, Shift2 |
| __18:00 - 19:00__ | Shift1, Shift2 | Shift1, Shift2 | Shift1, Shift2 | Shift2 | Shift1, Shift2 | Shift1, Shift2 | Shift1, Shift2 |
| __19:00 - 20:00__ | Shift1, Shift2 | Shift1, Shift2 | Shift1, Shift2 | Shift2 | Shift1, Shift2 | Shift1, Shift2 | Shift1, Shift2 |
| __20:00 - 21:00__ | Shift1, Shift2 | Shift1, Shift2 | Shift1, Shift2 | Shift2 | Shift1, Shift2 | Shift1, Shift2 |  |
| __21:00 - 22:00__ | Shift1, Shift2 | Shift1, Shift2 | Shift1, Shift2 | Shift2 | Shift1, Shift2 | Shift1, Shift2 |  |
| __22:00 - 23:00__ | Shift1, Shift2 | Shift1, Shift2 | Shift1, Shift2 | Shift2 | Shift1, Shift2 | Shift1, Shift2 |  |
| __23:00 - 24:00__ | Shift1, Shift2 | Shift1, Shift2 | Shift1, Shift2 | Shift2 | Shift1, Shift2 | Shift1, Shift2 |  |
"""  # noqa E501
