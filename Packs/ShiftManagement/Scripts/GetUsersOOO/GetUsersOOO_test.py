from GetUsersOOO import main
import demistomock as demisto
from datetime import timedelta, date
import json

GET_USERS_RESULTS = [{'Type': 1, 'EntryContext': {'DemistoUsers': [{'username': 'batman'}, {'username': 'robin'}]}}]
GET_USERS_EMPTY_RESULTS = [{'Type': 1, 'EntryContext': {'DemistoUsers': []}}]


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


def execute_command_empty_list(name, args=None):
    if name == 'getList':
        return [{'Contents': "null"}]
    elif name == 'getUsers':
        return GET_USERS_EMPTY_RESULTS
    return None


def test_out_of_office_list_cleanup_list_create_empty_new_list(mocker):
    """
    Given:
    - A non-existing list of OOO(out of office) users.

    When:
    - running OutOfOfficeListCleanup script.

    Then:
    - Check if the list stays empty.
    """
    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command_empty_list)
    mocker.patch.object(demisto, 'results')
    main()
    results = demisto.results.call_args[0][0]
    assert results['Contents'] == 'Out of office Team members\nNo team members are out of office today.'
