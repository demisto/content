"""RubrikSonarSetIncidentSeverityUsingUserRiskLevel Script for Cortex XSOAR - Unit Tests file."""
from unittest.mock import patch
import pytest

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


from RubrikSetIncidentSeverityUsingWorkLoadRiskLevel import set_incident_severity_using_risk_level_command, main


@pytest.fixture
def mock_execute_command():
    '''Fixture to mock the `executeCommand` function from the `demisto` module.'''
    with patch('RubrikSetIncidentSeverityUsingWorkLoadRiskLevel.demisto.executeCommand') as mock:
        yield mock


def test_set_incident_severity_using_risk_level_command_with_no_workload_data_specified(capfd):
    """Tests set_incident_severity_using_risk_level command function when no workload data specified.

    Checks the output of the command function with the expected output.
    """
    capfd.disabled()
    with pytest.raises(Exception) as e:
        set_incident_severity_using_risk_level_command({})

    assert str(e.value) == 'No data specified to update the incident severity.'


@pytest.mark.parametrize("increase_severity_by", [0, 5])
def test_set_incident_severity_using_risk_level_command_with_invalid_increase_severity_by_value(increase_severity_by, capfd):
    args = {'increase_severity_by': increase_severity_by}

    with capfd.disabled():
        with pytest.raises(Exception) as e:
            set_incident_severity_using_risk_level_command(args)

        assert str(e.value) == 'Increase severity by value must be between 1 and 4.'


def test_set_incident_severity_using_risk_level_command_with_invalid_severity(mocker, capfd):
    """Tests set_incident_severity_using_risk_level command function when invalid severity found.

    Checks the output of the command function with the expected output.
    """
    # Mock the demisto.incident() function to return an incident with mocked values.
    mocker.patch.object(demisto, 'incident', return_value={
        'severity': 'invalid'
    })

    with capfd.disabled():
        with pytest.raises(Exception) as e:
            set_incident_severity_using_risk_level_command({'risk_levels': 'High'})

        assert str(e.value) == 'Not able to get the correct value for the current incident severity.'


@pytest.mark.parametrize("args,severity", [
    ({'risk_levels': ['High', 'Low'], 'increase_severity_by': 1}, 'High'),
    ({'risk_levels': ['Medium', 'Low'], 'increase_severity_by': 1}, 'Medium'),
    ({'risk_levels': ['Low'], 'increase_severity_by': 1}, 'Low'),
    ({'risk_levels': ['No Risk'], 'increase_severity_by': 1}, 'Low'),
    ({'risk_levels': ['High', 'Low'], 'anomaly_severities': ['Critical'], 'increase_severity_by': 1}, 'Critical'),
    ({'threat_hunt_malicious': ['Matches Found'], 'anomaly_severities': ['Warning'], 'increase_severity_by': 2}, 'Medium'),
    ({'threat_monitoring_malicious': ['Matches Found'], 'increase_severity_by': 4}, 'Critical'),
])
def test_set_incident_severity_using_risk_level_command_with_success(mocker, args, severity):
    """Tests set_incident_severity_using_risk_level command function with success.

    Checks the output of the command function with the expected output.
    """

    # Mock the demisto.incident() function to return an incident with mocked values.
    mocker.patch.object(demisto, 'incident', return_value={'severity': 0})

    response = set_incident_severity_using_risk_level_command(args)

    assert response.readable_output == f'Increased the incident severity to {severity}.'


@pytest.mark.parametrize("args,incident_severity,severity", [
    ({'threat_hunt_malicious': ['Matches Found'], 'increase_severity_by': None}, 2, 'High'),
    ({'threat_hunt_malicious': ['Matches Found'], 'increase_severity_by': 2}, 0, 'Medium'),
    ({'threat_hunt_malicious': ['Matches Found'], 'increase_severity_by': 3}, 0.5, 'High'),
    ({'threat_hunt_malicious': ['Matches Found'], 'increase_severity_by': 4}, 2, 'Critical'),
    ({'threat_hunt_malicious': ['Matches Found'], 'increase_severity_by': 1}, 3, 'Critical'),
    ({'threat_hunt_malicious': ['Matches Found'], 'anomaly_severities': ['Critical'], 'increase_severity_by': 1}, 2, 'Critical'),
    ({'anomaly_severities': ['Critical'], 'increase_severity_by': 1}, 2, 'Critical'),
    ({'anomaly_severities': ['Warning'], 'increase_severity_by': 1}, 1, 'Medium'),
    ({'anomaly_severities': ['Informational'], 'increase_severity_by': 1}, 0, 'Info')
])
def test_set_incident_severity_using_risk_level_command_with_success_using_command(mocker, args, incident_severity, severity):
    """Tests set_incident_severity_using_risk_level command function with success and using command function.

    Checks the output of the command function with the expected output.
    """

    # Mock the demisto.incident() function to return an incident with mocked values.
    mocker.patch.object(demisto, 'incident', return_value={
        'severity': incident_severity
    })

    response = set_incident_severity_using_risk_level_command(
        args)

    assert response.readable_output == f'Increased the incident severity to {severity}.'


def test_set_incident_severity_using_risk_level_command_with_high_current_severity_compared_to_new_severity(mocker):
    """Tests set_incident_severity_using_risk_level function when current incident severity is higher than the new severity.

    Checks the output of the command function with the expected output.
    """
    # Mock the demisto.incident() function to return an incident with mocked values.
    mocker.patch.object(demisto, 'incident', return_value={
        'severity': 3
    })

    response = set_incident_severity_using_risk_level_command(
        {'risk_levels': 'Low'})

    assert (response.readable_output == 'No workload data with a risk level higher than the current incident severity (High).')


def test_main_with_exception(mock_execute_command, mocker, capfd):
    '''Test case scenario for successful execution of the `main` function when an exception is raised.'''
    # Test case: When an exception is raised
    # Arrange
    mocker.patch.object(demisto, 'incident', return_value={
        'severity': 1
    })
    mocker.patch.object(demisto, 'args', return_value={'risk_levels': ['High', 'Low'], 'increase_severity_by': 1})
    mock_execute_command.side_effect = Exception('Some error message')

    # Mock the return_results() function to capture the output
    mock_return_results = mocker.patch('RubrikSetIncidentSeverityUsingWorkLoadRiskLevel.return_results')

    # Act and Assert
    with capfd.disabled(), pytest.raises(SystemExit) as err:
        main()

    assert err.value.code == 0
    mock_execute_command.assert_called_once_with('setIncident', {"severity": 3})
    mock_return_results.assert_not_called()
