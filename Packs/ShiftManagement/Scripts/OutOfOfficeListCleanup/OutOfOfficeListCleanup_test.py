import json
import datetime
import demistomock as demisto
from OutOfOfficeListCleanup import main


def execute_command(name, args=None):
    if name == 'getList':
        get_list_response = [{"user": "admin", "offuntil": "2020-04-20", "addedby": "admin"}]
        return [{'Contents': json.dumps(get_list_response)}]
    else:
        return None


def execute_command_with_ooo_user(name, args=None):
    if name == 'getList':
        tommorow = (datetime.date.today() + datetime.timedelta(days=1)).strftime("%Y-%m-%d")
        get_list_response = [{"user": "admin", "offuntil": tommorow, "addedby": "admin"}]
        return [{'Contents': json.dumps(get_list_response)}]
    else:
        return None


def test_out_of_office_list_cleanup_list_changed(mocker):
    """
    Given:
    - List of OOO(out of office) users with one user that should be removed.

    When:
    - running OutOfOfficeListCleanup script.

    Then:
    - Check if the list is now empty.
    """
    mocker.patch.object(demisto, 'args', return_value={'listname': 'OOO List'})
    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)
    mocker.patch.object(demisto, 'results')
    main()
    results = demisto.results.call_args[0][0]
    assert demisto.executeCommand.call_args[0][1]['listData'] == '[]'
    assert results == 'The following Users were removed from the Out of Office List OOO List:\nadmin'


def test_out_of_office_list_cleanup_list_not_changed(mocker):
    """
    Given:
    - List of OOO(out of office) users with one user that should be in vacation until tomorrow.

    When:
    - running OutOfOfficeListCleanup script.

    Then:
    - Check if the list stays the same.
    """
    mocker.patch.object(demisto, 'args', return_value={'listname': 'OOO List'})
    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command_with_ooo_user)
    mocker.patch.object(demisto, 'results')
    main()
    results = demisto.results.call_args[0][0]
    assert results == 'No users removed from the list OOO List'
