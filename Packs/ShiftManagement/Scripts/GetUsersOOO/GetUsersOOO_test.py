from GetUsersOOO import main
import demistomock as demisto
from datetime import timedelta, date
import json

GET_USERS_RESULTS = [{'Type': 1, 'EntryContext': {'DemistoUsers': [{'username': 'batman'}, {'username': 'robin'}]}}]


def execute_command(name, args=None):
    if name == 'getList':
        tommorow_date = str(date.today() + timedelta(days=1))
        contents = [{'user': 'batman', 'offuntil': tommorow_date}]
        return [{'Type': 1, 'Contents': json.dumps(contents)}]
    elif name == 'getUsers':
        return GET_USERS_RESULTS
    else:
        return None


def test_get_users_ooo(mocker):
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)
    main()
    results = demisto.results.call_args[0]
    assert results[0]['EntryContext']['ShiftManagment.OOOUsers'] == [{'username': 'batman'}]
