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
