import demistomock as demisto
from typing import Any
from CommonServerPython import *
import json
from collections import defaultdict

INTEGRATION = 'ServiceNow v2'
NOTE_INCIDENTS = ("### Note: The active incidents, created 30 days ago and listed in the tables for both enabled and"
                  " disabled instances, are still being mirrored.\n ### If the issue is no longer relevant and does not"
                  " require further attention, it is recommended to close related incidents promptly to prevent"
                  " potential system overload.")


def http_request_wrapper(method: str, url: str, body: dict | None = None):
    """
    Sends an internal HTTP request using Demisto's `internalHttpRequest` and returns the parsed JSON response.

    Args:
        method (str): HTTP method (e.g., 'GET', 'POST').
        url (str): Request URL.
        body (dict | None, optional): Request payload.

    Returns:
        dict: Parsed JSON response or an empty dictionary if parsing fails.
    """
    http_result = demisto.internalHttpRequest(method, url, body=json.dumps(body))
    http_result_body_raw_response = cast(dict, http_result).get('body', '{}')
    try:
        http_result_body_response = json.loads(http_result_body_raw_response)
    except json.JSONDecodeError as e:
        raise DemistoException(f'Unable to load response {http_result_body_raw_response}: {str(e)}')
    return http_result_body_response


def get_integrations_details() -> dict[str, Any]:
    """
    Retrieve details of the integrations, including their health status.

    :return: A Dictionary containing the details of the integrations and their health status.
    :rtype: Dict[str, Any]
    """
    integrations_search_response = http_request_wrapper(method='POST', url='settings/integration/search')
    instances, health = integrations_search_response.get('instances', {}), integrations_search_response.get('health', {})
    instances_health = {}
    for instance in instances:
        instance_name = instance.get('name')
        if instance.get('brand') == INTEGRATION:
            instances_health[instance_name] = instance
            if instance_name in health:
                instances_health[instance_name].update({"health": health[instance_name]})
    return instances_health


def filter_instances_data(instances_data: dict[str, Any]) -> tuple[dict, list]:
    """
    Filter the instances data to separate enabled instances and disabled instances with active incidents.

    :param instances_data: A Dictionary containing data for each instance.
    :type instances_data: Dict

    :return: A Tuple containing the filtered data for enabled instances and a list of disabled instances with active incidents.
    :rtype: Tuple[Dict, list]
    """
    filtered_data = {}
    disabled_instances = []
    for instance_name, data in instances_data.items():
        if data.get('enabled') == 'true':
            filtered_data[instance_name] = data
            continue
        if (int(data.get('health', {}).get('incidentsPulled', 0)) > 0
                and data.get('configvalues', {}).get('mirror_direction', '') != 'None'):
            disabled_instances.append(instance_name)
        else:
            filtered_data[instance_name] = data
    return filtered_data, disabled_instances


def categorize_active_incidents(disabled_instances: list[str]) -> tuple[dict, dict]:
    """
    Retrieve incidents from ServiceNow instances and filter them based on whether the created instance is enabled or disabled.

    Filter the instances data to separate enabled instances and disabled instances with active incidents.

    :param disabled_instances: A list containing names of disabled instances.
    :type disabled_instances: list

    :return: A Tuple containing the active incidents for enabled instances and for disabled instances.
    :rtype: Tuple[Dict, list]
    """
    query = {
        'filter': {
            'query': f'sourceBrand: "{INTEGRATION}" and status: Active and created: >="30 days ago"'
        }
    }
    incidents_response = http_request_wrapper(method='POST', url='incidents/search', body=query)
    categorized_incidents: dict[str, Any] = {"enabled": defaultdict(list), "disabled": defaultdict(list)}

    for incident in incidents_response.get('data', {}):
        source_instance = incident.get("sourceInstance")
        incident_name = incident.get("name")

        if source_instance and incident_name:
            category = "disabled" if source_instance in disabled_instances else "enabled"
            categorized_incidents[category][source_instance].append(incident_name)

    return categorized_incidents.get("enabled", {}), categorized_incidents.get("disabled", {})


def parse_disabled_instances(disabled_incidents_instances: dict[str, Any]) -> str:
    """
    Parse the list of disabled instances to find those with active incidents
    and generate a Markdown table summarizing the results.

    :param disabled_incidents_instances: A Dictionary containing active incidents that were created 30 days ago
                                        of disabled instances.

    :return: A Markdown table summarizing the disabled instances and their active incidents,
             or an error message if the response is invalid.
    :rtype: ``str``
    """
    markdown_data = [
        {'Instance': instance,
         "Total": len(incidents),
         "Active incidents more than created 30 days ago": "\n".join(incidents
                                                                     )}
        for instance, incidents in disabled_incidents_instances.items()
    ]
    return tableToMarkdown(
        name="Disabled instances with active incidents created more than 30 days ago",
        t=markdown_data,
    )


def parse_enabled_instances(enabled_instances_health: dict[str, Any], enabled_incidents_instances: dict[str, Any]) -> str:
    """
    Parse the health information of enabled instances and generate a Markdown table.

    :param enabled_instances_health: A Dictionary containing health information for enabled instances.
    :type enabled_instances_health: Dict[str, Any]
    :param enabled_incidents_instances: A Dictionary containing active incidents that were created 30 days ago
                                        of enabled instances.
    :type enabled_instances_health: Dict[str, Any]

    :return: A Markdown table summarizing the health information of enabled instances.
    :rtype: str
    """
    human_readable_dict = []
    for instance_name, instance_data in enabled_instances_health.items():
        filtered_data = {
            'Instance Name': instance_name,
            'Size In Bytes': instance_data.get('sizeInBytes', ''),
            'Number of Incidents Pulled in Last Fetch': instance_data.get('health', {}).get('incidentsPulled', ''),
            'Last Pull Time': instance_data.get('health').get('lastPullTime', ''),
            'Query': instance_data.get('configvalues').get('sysparm_query', ''),
            'Last Error': instance_data.get('health').get('lastError', ''),
        }
        if instance_name in enabled_incidents_instances:
            filtered_data["Names of Active Incidents Created 30 days ago"] = enabled_incidents_instances[instance_name]
            filtered_data["Total Active Incidents Created 30 days ago"] = len(enabled_incidents_instances[instance_name])
        human_readable_dict.append(filtered_data)
    return tableToMarkdown(name="Enabled Instances Health Information", t=human_readable_dict,
                           removeNull=True)


def main():
    try:
        instances = get_integrations_details()
        enabled_instances_health, disabled_instances = filter_instances_data(instances)
        enabled_incidents_instances, disabled_incidents_instances = categorize_active_incidents(disabled_instances)
        disabled_instances_hr = parse_disabled_instances(disabled_incidents_instances)
        enabled_instances_hr = parse_enabled_instances(enabled_instances_health, enabled_incidents_instances)
        return_results(CommandResults(
            readable_output=f'{enabled_instances_hr} \n --- \n {disabled_instances_hr}\n{NOTE_INCIDENTS}'))

    except Exception as e:
        return_error(f'Failed to execute ServiceNowTroubleshoot. Error: {str(e)}')


if __name__ in ["__builtin__", "builtins", '__main__']:
    main()
