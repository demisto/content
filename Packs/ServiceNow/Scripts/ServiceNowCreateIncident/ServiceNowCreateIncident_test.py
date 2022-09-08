from CommonServerPython import *


def test_get_incident(mocker):
    """
    Given:
     - an incident data from service now command

    When:
     - executing get_incident function

    Then:
     - make sure the incident result key is being retrieved
    """
    from ServiceNowUpdateIncident import get_incident
    mocker.patch.object(demisto, 'executeCommand')
    mocker.patch.object(demisto, 'get', return_value={'result': 'test'})

    result = get_incident('query')
    assert result == 'test'


def test_get_incident_id(mocker):
    """
    Given:
     - an incident sys-id

    When:
     - executing get_incident_id function

    Then:
     - make sure that the incident sys ID is retrieved.
    """
    from ServiceNowUpdateIncident import get_incident_id
    mocker.patch.object(demisto, 'executeCommand')
    mocker.patch.object(demisto, 'get', return_value={'result': [{'sys_id': '123'}]})
    incident_sys_id = get_incident_id('123')
    assert incident_sys_id == '123'


def test_get_user(mocker):
    """
    Given:
     - an incident data from service now command

    When:
     - executing get_user function

    Then:
     - make sure the incident result key is being retrieved
    """
    from ServiceNowUpdateIncident import get_user
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
