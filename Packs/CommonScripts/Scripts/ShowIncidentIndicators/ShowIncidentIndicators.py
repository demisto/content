import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def group_by_type(indicators):
    """
    Gets the indicators of the current incident.

    Returns:
        A list of the indicator types followed by the corresponding indicator values.
    """

    grouped = {}
    for indicator in indicators:
        if indicator['indicator_type'] not in grouped:
            grouped[indicator['indicator_type']] = [indicator['value']]
        else:
            grouped[indicator['indicator_type']].append(indicator['value'])
    result = []
    for indicator_header, indicator_values in grouped.items():
        result.append("--- " + indicator_header + " ---")
        result.extend(indicator_values)
        result.append('')
    return result


def get_indicators_from_incident():
    """
    Returns:
        List of the indicators from the incident.
    """
    incident_id = demisto.incident()['id']
    indicators_query = {
        "investigationIDs": incident_id
    }

    find_indicators_args = {'query': indicators_query}
    all_indicator_data = execute_command('findIndicators', args=find_indicators_args)
    return {"hidden": False, "options": group_by_type(all_indicator_data)}


def main():
    return_results(get_indicators_from_incident())


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
