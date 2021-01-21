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


def executeCommand(findIndicatorsResult=FIND_INDICATORS_NORMAL,
                   findIndicatorsError=False,
                   getUsersError=False,
                   createNewIncidentError=False,
                   investigateError=False):
    def inner(command, args=None):
        if command == "findIndicators":
            if findIndicatorsError:
                return ERROR
            return findIndicatorsResult
        elif command == "getUsers":
            if getUsersError:
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
            if createNewIncidentError:
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
            if investigateError:
                return ERROR
            return [
                {
                    "Type": entryTypes["note"],
                    "Contents": [{}],
                }
            ]

    return inner


@pytest.mark.parametrize("args", [
    dict(),
    dict(indicator_type="ip_reputation"),
    dict(incident_type="My Type"),
    dict(indicator_type="ip_reputation", incident_type="My Type"),
])
def test_create_random_hunt_incident(mocker, args):
    """
    Given: Different arg input
    When: Running create_random_hunt_incident command.
    Then: An incident has been created and a link is posted
    """
    from CyrenThreatInDepthRandomHunt import create_random_hunt_incident

    mocker.patch.object(demisto, "executeCommand", side_effect=executeCommand())
    result = create_random_hunt_incident(args)

    assert result.readable_output == ("Successfully created incident Cyren Threat InDepth Threat Hunt.\n"
                                      "Click here to investigate: [1234](#/incident/1234).")


def test_create_random_hunt_incident_find_indicators_error(mocker):
    """
    Given: Errors in findIndicators
    When: Running create_random_hunt_incident command.
    Then: An exception is thrown
    """
    from CyrenThreatInDepthRandomHunt import create_random_hunt_incident

    mocker.patch.object(demisto, "executeCommand", side_effect=executeCommand(findIndicatorsError=True))
    with pytest.raises(DemistoException):
        create_random_hunt_incident(dict())


def test_create_random_hunt_incident_find_indicators_empty(mocker):
    """
    Given: No indicators according to query
    When: Running create_random_hunt_incident command.
    Then: An error message is printed
    """
    from CyrenThreatInDepthRandomHunt import create_random_hunt_incident

    mocker.patch.object(demisto, "executeCommand", side_effect=executeCommand(findIndicatorsResult=FIND_INDICATORS_EMPTY))
    result = create_random_hunt_incident(dict())

    assert "Could not find any indicators for " in result.readable_output


def test_create_random_hunt_incident_get_current_user_error(mocker):
    """
    Given: Getting current user produces an error
    When: Running create_random_hunt_incident command.
    Then: Incident is still created
    """
    from CyrenThreatInDepthRandomHunt import create_random_hunt_incident

    mocker.patch.object(demisto, "executeCommand", side_effect=executeCommand(getUsersError=True))
    result = create_random_hunt_incident(dict())

    assert result.readable_output == ("Successfully created incident Cyren Threat InDepth Threat Hunt.\n"
                                      "Click here to investigate: [1234](#/incident/1234).")


def test_create_random_hunt_incident_create_new_incident_error(mocker):
    """
    Given: Creating the incident will produce an error
    When: Running create_random_hunt_incident command.
    Then: An exception is thrown
    """
    from CyrenThreatInDepthRandomHunt import create_random_hunt_incident

    mocker.patch.object(demisto, "executeCommand", side_effect=executeCommand(createNewIncidentError=True))

    with pytest.raises(DemistoException):
        create_random_hunt_incident(dict())


def test_create_random_hunt_incident_investigate_error(mocker):
    """
    Given: Getting current user produces an error
    When: Running create_random_hunt_incident command.
    Then: Incident is still created
    """
    from CyrenThreatInDepthRandomHunt import create_random_hunt_incident

    mocker.patch.object(demisto, "executeCommand", side_effect=executeCommand(investigateError=True))
    result = create_random_hunt_incident(dict())

    assert result.readable_output == ("Successfully created incident Cyren Threat InDepth Threat Hunt.\n"
                                      "Click here to investigate: [1234](#/incident/1234).\n"
                                      "(An investigation has not been started.)")
