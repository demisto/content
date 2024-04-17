"""RubrikSonarSetIncidentSeverityUsingUserRiskLevel Script for Cortex XSOAR - Unit Tests file."""
import pytest

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import RubrikSonarSetIncidentSeverityUsingUserRiskLevel


def test_set_incident_severity_using_risk_level_command_with_no_risk_levels_specified():
    """Tests set_incident_severity_using_risk_level command function when no risk levels specified.

    Checks the output of the command function with the expected output.
    """
    response = RubrikSonarSetIncidentSeverityUsingUserRiskLevel.set_incident_severity_using_risk_level_command({})

    assert response.readable_output == "No risk_levels specified to update the incident severity."


def test_set_incident_severity_using_risk_level_command_with_invalid_severity(mocker):
    """Tests set_incident_severity_using_risk_level command function when invalid severity found.

    Checks the output of the command function with the expected output.
    """
    # Mock the demisto.incident() function to return an incident with mocked values.
    mocker.patch.object(demisto, 'incident', return_value={
        'severity': 'invalid'
    })

    with pytest.raises(Exception) as e:
        RubrikSonarSetIncidentSeverityUsingUserRiskLevel.set_incident_severity_using_risk_level_command(
            {'risk_levels': 'HIGH_RISK'})

    assert 'Not able to get the correct value for the current incident severity.' in str(e.value)


def test_set_incident_severity_using_risk_level_command_with_success(mocker):
    """Tests set_incident_severity_using_risk_level command function with success.

    Checks the output of the command function with the expected output.
    """
    args = {'risk_levels': 'HIGH_RISK'}

    # Mock the demisto.incident() function to return an incident with mocked values.
    mocker.patch.object(demisto, 'incident', return_value={'severity': 1})

    response = RubrikSonarSetIncidentSeverityUsingUserRiskLevel.set_incident_severity_using_risk_level_command(args)
    # Mock the return_results() function to capture the output
    mocker.patch('RubrikSonarSetIncidentSeverityUsingUserRiskLevel.return_results', return_value=response)

    RubrikSonarSetIncidentSeverityUsingUserRiskLevel.main()

    assert RubrikSonarSetIncidentSeverityUsingUserRiskLevel.return_results.call_count == 1
    assert (RubrikSonarSetIncidentSeverityUsingUserRiskLevel.return_results.return_value.
            readable_output == 'Increased the incident severity to High.')


@pytest.mark.parametrize("risk_levels, severity", [('HIGH_RISK', 'High'), ('MEDIUM_RISK', 'Medium')])
def test_set_incident_severity_using_risk_level_command_with_success_using_command(mocker, risk_levels, severity):
    """Tests set_incident_severity_using_risk_level command function with success and using command function.

    Checks the output of the command function with the expected output.
    """
    # Mock the demisto.incident() function to return an incident with mocked values.
    mocker.patch.object(demisto, 'incident', return_value={
        'severity': 1
    })

    response = RubrikSonarSetIncidentSeverityUsingUserRiskLevel.set_incident_severity_using_risk_level_command(
        {'risk_levels': risk_levels})

    assert response.readable_output == f'Increased the incident severity to {severity}.'


def test_set_incident_severity_using_risk_level_command_with_high_incident_severity(mocker):
    """Tests set_incident_severity_using_risk_level command function when incident severity is set to high.

    Checks the output of the command function with the expected output.
    """
    # Mock the demisto.incident() function to return an incident with mocked values.
    mocker.patch.object(demisto, 'incident', return_value={
        'severity': 3
    })

    response = RubrikSonarSetIncidentSeverityUsingUserRiskLevel.set_incident_severity_using_risk_level_command(
        {'risk_levels': 'HIGH_RISK'})

    assert (response.readable_output == 'The current severity is already High, no need to update the severity.')


@pytest.mark.parametrize("risk_levels", ['LOW_RISK', 'NO_RISK'])
def test_set_incident_severity_using_risk_level_command_with_high_severity_compared_to_risk_level(mocker, risk_levels):
    """Tests set_incident_severity_using_risk_level function when incident severity is high compared to risk level.

    Checks the output of the command function with the expected output.
    """
    # Mock the demisto.incident() function to return an incident with mocked values.
    mocker.patch.object(demisto, 'incident', return_value={
        'severity': 2
    })

    response = RubrikSonarSetIncidentSeverityUsingUserRiskLevel.set_incident_severity_using_risk_level_command(
        {'risk_levels': risk_levels})

    assert response.readable_output == 'No users with a risk level higher than the current incident severity (Medium).'
