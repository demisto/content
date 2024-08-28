import pytest
import demistomock as demisto
from CommonServerPython import entryTypes, DemistoException


FIND_INDICATORS_NORMAL = [
    {
        "Type": entryTypes["note"],
        "Contents": [{
            "value": "http://google.de",
            "indicator_type": "URL",
        }]
    }
]

ERROR = [
    {
        "Type": entryTypes["error"],
        "Contents": [{}]
    }
]

FIND_INDICATORS_EMPTY = [
    {
        "Type": entryTypes["note"],
        "Contents": []
    }
]


def executeCommand(find_indicators_result=FIND_INDICATORS_NORMAL,
                   find_indicators_error=False,
                   get_users_error=False,
                   create_new_incident_error=False,
                   investigate_error=False):
    def inner(command, args=None):
        if command == "findIndicators":
            if find_indicators_error:
                return ERROR
            return find_indicators_result
        elif command == "getUsers":
            if get_users_error:
                return ERROR
            return [
                {
                    "Type": entryTypes["note"],
                    "Contents": [{
                        "id": "admin",
                    }]
                }
            ]
        elif command == "createNewIncident":
            if create_new_incident_error:
                return ERROR
            return [
                {
                    "Type": entryTypes["note"],
                    "Contents": [{}],
                    "EntryContext": {
                        "CreatedIncidentID": "1234",
                    }
                }
            ]
        elif command == "investigate":
            if investigate_error:
                return ERROR
            return [
                {
                    "Type": entryTypes["note"],
                    "Contents": [{}],
                }
            ]
        return None

    return inner


@pytest.mark.parametrize("args, expected_incident", [
    (
        {},
        {"name": "Cyren Threat InDepth Threat Hunt", "type": "Hunt",
         "details": "indicator_type: URL\nvalue: http://google.de\n", "owner": "admin"}
    ),
    (
        {"assignee": "other.user"},
        {"name": "Cyren Threat InDepth Threat Hunt", "type": "Hunt",
         "details": "indicator_type: URL\nvalue: http://google.de\n", "owner": "other.user"}
    ),
    (
        {"assignee": "other.user", "incident_type": "My Type"},
        {"name": "Cyren Threat InDepth Threat Hunt", "type": "My Type",
         "details": "indicator_type: URL\nvalue: http://google.de\n", "owner": "other.user"}
    ),
    (
        {"indicator_type": "ip_reputation"},
        {"name": "Cyren Threat InDepth Threat Hunt", "type": "Hunt",
         "details": "indicator_type: URL\nvalue: http://google.de\n", "owner": "admin"}
    ),
    (
        {"incident_type": "My Type"},
        {"name": "Cyren Threat InDepth Threat Hunt", "type": "My Type",
         "details": "indicator_type: URL\nvalue: http://google.de\n", "owner": "admin"}
    ),
    (
        {"indicator_type": "ip_reputation", "incident_type": "My Type"},
        {"name": "Cyren Threat InDepth Threat Hunt", "type": "My Type",
         "details": "indicator_type: URL\nvalue: http://google.de\n", "owner": "admin"}
    ),
])
def test_create_random_hunt_incident(mocker, args, expected_incident):
    """
    Given: Different arg input
    When: Running create_random_hunt_incident command.
    Then: An incident has been created and a link is posted
    """
    from CyrenThreatInDepthRandomHunt import create_random_hunt_incident

    mocker.patch.object(demisto, "executeCommand", side_effect=executeCommand())
    result = create_random_hunt_incident(args)

    demisto.executeCommand.assert_any_call("createNewIncident", expected_incident)
    assert result.readable_output == ("Successfully created incident Cyren Threat InDepth Threat Hunt.\n"
                                      "Click here to investigate: [1234](#/incident/1234).")


def test_create_random_hunt_incident_find_indicators_error(mocker):
    """
    Given: Errors in findIndicators
    When: Running create_random_hunt_incident command.
    Then: An exception is thrown
    """
    from CyrenThreatInDepthRandomHunt import create_random_hunt_incident

    mocker.patch.object(demisto, "executeCommand", side_effect=executeCommand(find_indicators_error=True))
    with pytest.raises(DemistoException):
        create_random_hunt_incident({})


def test_create_random_hunt_incident_find_indicators_empty(mocker):
    """
    Given: No indicators according to query
    When: Running create_random_hunt_incident command.
    Then: An error message is printed
    """
    from CyrenThreatInDepthRandomHunt import create_random_hunt_incident

    mocker.patch.object(demisto, "executeCommand", side_effect=executeCommand(find_indicators_result=FIND_INDICATORS_EMPTY))
    result = create_random_hunt_incident({})

    assert "Could not find any indicators for " in result.readable_output


def test_create_random_hunt_incident_get_current_user_error(mocker):
    """
    Given: Getting current user produces an error
    When: Running create_random_hunt_incident command.
    Then: Incident is still created
    """
    from CyrenThreatInDepthRandomHunt import create_random_hunt_incident

    mocker.patch.object(demisto, "executeCommand", side_effect=executeCommand(get_users_error=True))
    result = create_random_hunt_incident({})

    assert result.readable_output == ("Successfully created incident Cyren Threat InDepth Threat Hunt.\n"
                                      "Click here to investigate: [1234](#/incident/1234).")


def test_create_random_hunt_incident_create_new_incident_error(mocker):
    """
    Given: Creating the incident will produce an error
    When: Running create_random_hunt_incident command.
    Then: An exception is thrown
    """
    from CyrenThreatInDepthRandomHunt import create_random_hunt_incident

    mocker.patch.object(demisto, "executeCommand", side_effect=executeCommand(create_new_incident_error=True))

    with pytest.raises(DemistoException):
        create_random_hunt_incident({})


def test_create_random_hunt_incident_investigate_error(mocker):
    """
    Given: Getting current user produces an error
    When: Running create_random_hunt_incident command.
    Then: Incident is still created
    """
    from CyrenThreatInDepthRandomHunt import create_random_hunt_incident

    mocker.patch.object(demisto, "executeCommand", side_effect=executeCommand(investigate_error=True))
    result = create_random_hunt_incident({})

    assert result.readable_output == ("Successfully created incident Cyren Threat InDepth Threat Hunt.\n"
                                      "Click here to investigate: [1234](#/incident/1234).\n"
                                      "(An investigation has not been started.)")
