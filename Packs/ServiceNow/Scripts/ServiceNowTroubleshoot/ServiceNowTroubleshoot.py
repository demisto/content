import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from Packs.Base.Scripts.CommonServerPython.CommonServerPython import CommandResults, tableToMarkdown, return_error, \
    return_results
import json
from collections import defaultdict

INTEGRATION = 'ServiceNow v2'
HEADERS_TO_EXTRACTED = ['sizeInBytes',
                        'incidentsPulled',
                        'lastPullTime',
                        'lastError']


def get_active_incidents_by_instances() -> dict[str, Any]:
    """
        Find active incidents created 30 days ago of 'ServiceNow v2'.
        and generate a Markdown table summarizing the results.

        :return: A Dict summarizing the instances and their active incidents,
        :rtype: `dict
    """

    response = demisto.internalHttpRequest('POST', 'incidents/search', body=json.dumps(query))
    query = {
        'filter': {
            'query': f'sourceBrand:"{INTEGRATION}" and status:Active and created:>="30 days ago"'
        }
    }
    response = demisto.internalHttpRequest('POST', 'incidents/search', body=json.dumps(query))
    return json.loads(response.get('body', '{}'))


def get_integrations_details() -> dict[str, Any]:
    """
    Retrieve details of the integrations, including their health status.

    :return: A dictionary containing the details of the integrations and their health status.
    :rtype: dict[str, Any]
    """
    http_result = json.loads(demisto.internalHttpRequest('POST', 'settings/integration/search').get('body'))
    instances, health = http_result['instances'], http_result['health']
    instances_health = {}
    for instance in instances:
        instance_name = instance.get('name')
        if instance.get('brand') == INTEGRATION:
            instances_health[instance_name] = instance
            if instance_name in health:
                instances_health[instance_name].update({"health": health[instance_name]})
    return instances_health


def filter_instances_data(instances_data) -> tuple[dict, list]:
    """
    Filter the instances data to separate enabled instances and disabled instances with active incidents.

    :param instances_data: A dictionary containing data for each instance.
    :type instances_data: dict

    :return: A tuple containing the filtered data for enabled instances and a list of disabled instances with active incidents.
    :rtype: tuple[dict, list]
    """
    filtered_data = {}
    disabled_instances = []

    for instance_name, data in instances_data.items():
        if data['enabled'] == 'true':
            filtered_data[instance_name] = data
            continue
        if int(data['health']['incidentsPulled']) > 0 and data['configvalues']['mirror_direction'] != 'None':
            disabled_instances.append(instance_name)
        else:
            filtered_data[instance_name] = data
    return filtered_data, disabled_instances


def active_incidents_data(disabled_instances: list[str]) -> tuple[dict, dict]:
    """
    Retrieve incidents from ServiceNow instances and filter them based on whether the created instance is enabled or disabled.

    Filter the instances data to separate enabled instances and disabled instances with active incidents.

    :param disabled_instances: A list containing names of disabled instances.
    :type disabled_instances: list

    :return: A tuple containing the active incidents for enabled instances and for disabled instances.
    :rtype: tuple[dict, list]
    """
    response = get_active_incidents_by_instances()
    disabled_incidents_instances, enabled_incidents_instances = defaultdict(list), defaultdict(list)
    data = response.get('data', {})
    for incident in data:
        source_instance = incident.get("sourceInstance")
        incident_name = incident.get("name")
        if source_instance and incident_name:
            if source_instance in disabled_instances:
                disabled_incidents_instances[source_instance].append(incident_name)
            else:
                enabled_incidents_instances[source_instance].append(incident_name)
    return enabled_incidents_instances, disabled_incidents_instances


def parse_disabled_instances(disabled_incidents_instances: Dict[str, Any]) -> str:
    """
    Parse the list of disabled instances to find those with active incidents
    and generate a Markdown table summarizing the results.

    :param disabled_incidents_instances: A dictionary containing active incidents that were created 30 days ago
                                        of disabled instances.

    :return: A Markdown table summarizing the disabled instances and their active incidents,
             or an error message if the response is invalid.
    :rtype: ``str``
    """
    markdown_data = [
        {'Instance': instance, 'Incidents': "\n".join(incidents)}
        for instance, incidents in disabled_incidents_instances.items()
    ]

    return tableToMarkdown(
        name="Closed instances with open incidents",
        t=markdown_data,
    )


def parse_enabled_instances(enabled_instances_health: Dict[str, Any], enabled_incidents_instances: Dict[str, Any]) -> str:
    """
    Parse the health information of enabled instances and generate a Markdown table.

    :param enabled_instances_health: A dictionary containing health information for enabled instances.
    :type enabled_instances_health: Dict[str, Any]
    :param enabled_incidents_instances: A dictionary containing active incidents that were created 30 days ago
                                        of enabled instances.
    :type enabled_instances_health: Dict[str, Any]

    :return: A Markdown table summarizing the health information of enabled instances.
    :rtype: str
    """
    human_readable_dict = []
    for instance_name, instance_data in enabled_instances_health.items():
        filtered_data = {
            'Instance Name': instance_name,
            'Size In Bytes': instance_data['sizeInBytes'],
            'Number of Incidents Pulled': instance_data['health']['incidentsPulled'],
            'Last Pull Time': instance_data['health']['lastPullTime'],
            'Query': instance_data['configvalues']['sysparm_query'],
            'Last Error': instance_data['health']['lastError'],
        }
        if instance_name in enabled_incidents_instances:
            filtered_data["Open Incidents> 30 days"] = enabled_incidents_instances[instance_name]
        human_readable_dict.append(filtered_data)
    return tableToMarkdown(name="Open Instances Health Information", t=human_readable_dict,
                           removeNull=True)


def main():
    try:
        instances = get_integrations_details()
        enabled_instances_health, disabled_instances = filter_instances_data(instances)
        enabled_incidents_instances, disabled_incidents_instances = active_incidents_data(disabled_instances)
        disabled_instances_hr = parse_disabled_instances(disabled_incidents_instances)
        enabled_instances_hr = parse_enabled_instances(enabled_instances_health, enabled_incidents_instances)
        return_results(CommandResults(readable_output=f'{enabled_instances_hr} \n --- \n\n\n {disabled_instances_hr}'))

    except Exception as ex2:
        return_error(f'Failed to execute ServiceNowAddComment. Error: {str(ex2)}')


if __name__ in ["__builtin__", "builtins", '__main__']:
    main()
