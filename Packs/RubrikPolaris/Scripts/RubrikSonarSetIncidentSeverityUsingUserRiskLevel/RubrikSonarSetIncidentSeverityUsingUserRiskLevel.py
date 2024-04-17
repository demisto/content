
import demistomock as demisto
from CommonServerPython import *

INCIDENT_SEVERITY_INT_TO_NAME = {
    0: 'Unknown',
    0.5: 'Info',
    1: 'Low',
    2: 'Medium',
    3: 'High',
    4: 'Critical'
}

''' COMMAND FUNCTION '''


def set_incident_severity_using_risk_level_command(args: dict[str, Any]) -> CommandResults:
    """Set the incident severity using the provided risk levels.

    :type args: ``Dict[str, Any]``
    :param args: Arguments provided by user.

    :rtype: ``CommandResults``
    :return: Standard command result.
    """
    risk_levels: list = argToList(args.get('risk_levels'))

    # If there are no risk levels are available in the argument, we will only show a message to user.
    if not risk_levels:
        return CommandResults(readable_output='No risk_levels specified to update the incident severity.')

    # Get current incident severity.
    current_severity: int = demisto.incident().get('severity', 0)
    if not isinstance(current_severity, float) and not isinstance(current_severity, int):
        raise DemistoException('Not able to get the correct value for the current incident severity.')
    if current_severity > 2:
        return CommandResults(
            readable_output=f'The current severity is already {INCIDENT_SEVERITY_INT_TO_NAME[current_severity]}, '
                            'no need to update the severity.')

    if 'HIGH_RISK' in risk_levels:
        new_severity = 3
    elif 'MEDIUM_RISK' in risk_levels:
        new_severity = 2
    elif 'LOW_RISK' in risk_levels:
        new_severity = 1
    else:
        new_severity = current_severity

    if new_severity > current_severity:
        demisto.executeCommand("setIncident", {"severity": new_severity})
        return CommandResults(
            readable_output=f"Increased the incident severity to {INCIDENT_SEVERITY_INT_TO_NAME[new_severity]}.")
    else:
        return CommandResults(readable_output="No users with a risk level higher than the current incident "
                                              f"severity ({INCIDENT_SEVERITY_INT_TO_NAME[current_severity]}).")


''' MAIN FUNCTION '''


def main():
    try:
        return_results(set_incident_severity_using_risk_level_command(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(
            f'Failed to execute RubrikSonarSetIncidentSeverityUsingUserRiskLevel-RubrikPolaris. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
