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
    from ServiceNowCreateIncident import get_user
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
    from ServiceNowCreateIncident import get_user_id
    mocker.patch.object(demisto, 'executeCommand')
    mocker.patch.object(demisto, 'get', return_value={'result': [{'sys_id': '123'}]})
    incident_sys_id = get_user_id('user1 user2')
    assert incident_sys_id == '123'


def test_get_group(mocker):
    """
    Given:
     - an incident data from service now command

    When:
     - executing get_user function

    Then:
     - make sure the incident result key is being retrieved
    """
    from ServiceNowCreateIncident import get_group
    mocker.patch.object(demisto, 'executeCommand')
    mocker.patch.object(demisto, 'get', return_value={'result': 'test'})

    user = get_group('query')
    assert user == 'test'


def test_get_group_id(mocker):
    """
    Given:
     - an incident sys-id

    When:
     - executing get_user_id function

    Then:
     - make sure that the incident sys ID is retrieved.
    """
    from ServiceNowCreateIncident import get_group_id
    mocker.patch.object(demisto, 'executeCommand')
    mocker.patch.object(demisto, 'get', return_value={'result': [{'sys_id': '123'}]})
    incident_sys_id = get_group_id('user1 user2')
    assert incident_sys_id == '123'


def test_main_flow_success(mocker):
    """
    Given:
     - result of the 'servicenow-create-record' executed command.

    When:
     - running the main flow

    Then:
     - make sure the main flow gets executed without errors.
    """
    from ServiceNowCreateIncident import main
    mocked_data = {'result': {'number': 'INC0021211', 'sys_id': '123'}}
    mocker.patch.object(demisto, 'executeCommand')
    mocker.patch.object(demisto, 'get', return_value=mocked_data)

    result = mocker.patch('demistomock.results')

    main()

    assert result.call_args.args[0] == {
        'Type': 1, 'Contents': {
            'result': {'number': 'INC0021211', 'sys_id': '123'}
        },
        'ContentsFormat': 'json', 'ReadableContentsFormat': 'markdown',
        'HumanReadable': '### Incident successfully created\n|ID|Number|\n|---|---|\n| 123 | INC0021211 |\n',
        'EntryContext': {'ServiceNow.Incident(val.ID===obj.ID)': {'Number': 'INC0021211', 'ID': '123'}}
    }
