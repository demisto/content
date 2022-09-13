from CommonServerPython import *


def test_get_user(mocker):
    """
    Given:
     - an incident data from service now command

    When:
     - executing get_user function

    Then:
     - make sure the incident result key is being retrieved
    """
    from ServiceNowQueryIncident import get_user
    mocker.patch.object(demisto, 'executeCommand')
    mocker.patch.object(demisto, 'get', return_value={'result': 'test'})

    user = get_user('query')
    assert user == 'test'


def test_get_user_id(mocker):
    """
    Given:
     - an incident sys-id

    When:
     - executing get_user_id function

    Then:
     - make sure that the incident sys ID is retrieved.
    """
    from ServiceNowQueryIncident import get_user_id
    mocker.patch.object(demisto, 'executeCommand')
    mocker.patch.object(demisto, 'get', return_value={'result': [{'sys_id': '123'}]})
    incident_sys_id = get_user_id('user1 user2')
    assert incident_sys_id == '123'


def test_get_username(mocker):
    """
    Given:
     - an incident with first name and last name

    When:
     - executing get_user_name function

    Then:
     - make sure that the first name and last name are being returned.
    """
    from ServiceNowQueryIncident import get_user_name
    mocker.patch.object(demisto, 'executeCommand')
    mocker.patch.object(
        demisto, 'get', return_value={'result': [{'first_name': 'first-name', 'last_name': 'last-name'}]}
    )

    result = get_user_name('123')
    assert result == 'first-name last-name'


def test_main_flow_success(mocker):
    """
    Given:
     - result of the 'servicenow-query-table' executed command.

    When:
     - running the main flow

    Then:
     - make sure the main flow gets executed without errors.
    """
    from ServiceNowQueryIncident import main
    args_mock = {'number': 'INC0021211'}
    mocked_command_data = {'result': [{'number': 'INC0021211', 'sys_id': '123', 'priority': '1'}]}
    mocker.patch.object(demisto, 'executeCommand')
    mocker.patch.object(demisto, 'args', return_value=args_mock)
    mocker.patch.object(demisto, 'get', return_value=mocked_command_data)

    result = mocker.patch('demistomock.results')

    main()

    assert result.call_args.args[0] == {
        'Type': 1,
        'Contents': {'result': [{'number': 'INC0021211', 'sys_id': '123', 'priority': '1'}]},
        'ContentsFormat': 'json',
        'ReadableContentsFormat': 'markdown',
        'HumanReadable': '### ServiceNow Incidents\n|ID|Number|Priority|\n|---|---|---|'
                         '\n| 123 | INC0021211 | 1 - Critical |\n',
        'EntryContext': {
            'ServiceNow.Incident(val.ID===obj.ID)': [
                {'Number': 'INC0021211', 'ID': '123', 'Priority': '1 - Critical'}
            ]
        }
    }
