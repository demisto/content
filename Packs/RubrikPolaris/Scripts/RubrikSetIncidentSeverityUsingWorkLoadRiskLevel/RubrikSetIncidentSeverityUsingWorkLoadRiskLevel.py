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
MATCHES_FOUND = 'Matches Found'

ANOMALY_SEVERITY_TO_INCIDENT_SEVERITY = {
    'critical': 4,
    'warning': 2,
    'informational': 0.5
}

RISK_LEVEL_TO_INCIDENT_SEVERITY = {
    'high': 3,
    'medium': 2,
    'low': 1,
    'no risk': 1
}

''' COMMAND FUNCTION '''


def set_incident_severity_using_risk_level_command(args: dict[str, Any]) -> CommandResults:
    """Set the incident severity using the provided workload data.

    :type args: ``Dict[str, Any]``
    :param args: Arguments provided by user.

    :rtype: ``CommandResults``
    :return: Standard command result.
    """
    remove_nulls_from_dictionary(args)

    anomaly_severities: list = argToList(args.get('anomaly_severities'))
    threat_hunt_malicious: list = argToList(args.get('threat_hunt_malicious'))
    threat_monitoring_malicious: list = argToList(args.get('threat_monitoring_malicious'))
    risk_levels: list = argToList(args.get('risk_levels'))
    increase_severity_by: int = arg_to_number(args.get('increase_severity_by', 1),
                                              arg_name='increase_severity_by')  # type: ignore

    # If increase severity by value is not between 1 and 4, we will only show a message to user.
    if increase_severity_by < 1 or increase_severity_by > 4:
        raise DemistoException('Increase severity by value must be between 1 and 4.')

    # If there are no workload data are available in the argument, we will only show a message to user.
    if not risk_levels and not anomaly_severities and not threat_hunt_malicious and not threat_monitoring_malicious:
        raise DemistoException('No data specified to update the incident severity.')

    # Get current incident severity.
    current_severity: int = demisto.incident().get('severity', 0)

    if not isinstance(current_severity, float | int):
        raise DemistoException('Not able to get the correct value for the current incident severity.')

    anomaly_severity, threat_hunt_severity, risk_level_severity = 0, 0, 0

    for anomaly in anomaly_severities:
        severity_value = ANOMALY_SEVERITY_TO_INCIDENT_SEVERITY.get(anomaly.lower(), 0)
        anomaly_severity = max(anomaly_severity, severity_value)  # type: ignore

    for risk_level in risk_levels:
        severity_value = RISK_LEVEL_TO_INCIDENT_SEVERITY.get(risk_level.lower(), 0)
        risk_level_severity = max(risk_level_severity, severity_value)  # type: ignore

    if MATCHES_FOUND in threat_hunt_malicious or MATCHES_FOUND in threat_monitoring_malicious:
        threat_hunt_severity = int(min(4, current_severity + increase_severity_by))

    new_severity = max(risk_level_severity, anomaly_severity, threat_hunt_severity)

    if new_severity > current_severity:
        demisto.executeCommand("setIncident", {"severity": new_severity})
        return CommandResults(
            readable_output=f"Increased the incident severity to {INCIDENT_SEVERITY_INT_TO_NAME[new_severity]}.")
    else:
        return CommandResults(readable_output="No workload data with a risk level higher than the current incident "
                                              f"severity ({INCIDENT_SEVERITY_INT_TO_NAME[current_severity]}).")


''' MAIN FUNCTION '''


def main():
    try:
        return_results(set_incident_severity_using_risk_level_command(demisto.args()))
    except Exception as ex:
        return_error(
            f'Failed to execute RubrikSonarSetIncidentSeverityUsingWorkLoadRiskLevel-RubrikSecurityCloud. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
