import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import time

QUERY_TYPE_TO_KEY = {
    'Categories': 'PaloAltoNetworksXDR.Incident.alerts.category',
    'Users': 'PaloAltoNetworksXDR.Incident.users',
    'Hosts': 'PaloAltoNetworksXDR.Incident.hosts',
    'Alerts': 'PaloAltoNetworksXDR.Incident.alerts.name',
    'MitreTactic': 'PaloAltoNetworksXDR.Incident.alerts.mitre_tactic_id_and_name',
    'MitreTechnique': 'PaloAltoNetworksXDR.Incident.alerts.mitre_technique_id_and_name',
    'FileSHA2': 'PaloAltoNetworksXDR.Incident.file_artifacts.file_sha256',
    'File': 'PaloAltoNetworksXDR.Incident.file_artifacts.file_name'
}


def get_xdr_incidents(include_closed_incidents: bool) -> list:
    """
    Returns Cortex XDR incident with status Active or Pending using GetIncidentsByQuery script.
    :param include_closed_incidents: Whether to query closed incidents or not.
    :return: Cortex XDR incident objects
    """
    query = 'status:Active or status:Pending and type:"Cortex XDR Incident"'
    if include_closed_incidents:
        query = 'type:"Cortex XDR Incident"'

    get_incidents_args = {
        'query': query,
        'includeContext': True,
        'limit': 3000
    }

    incidents_res = demisto.executeCommand('GetIncidentsByQuery', get_incidents_args)
    if isError(incidents_res):
        return_error(f'Error occurred while trying to get incidents: {get_error(incidents_res)}')

    incidents = []
    try:
        incidents = json.loads(incidents_res[0].get('Contents'))
    except json.JSONDecodeError:
        demisto.error(f'Failed to parse incidents response from GetIncidentsByQuery, result = {incidents_res}')
        pass
    return incidents


def update_xdr_list(context: list, xdr_list: list, query_type: str, created_date: str):
    """
    Updated the given xdr list with the values from the incident context.
    :param context: List of values from the incident context key.
    :param xdr_list: The data list to update.
    :param query_type: The item to gets the result in the incident(users/hosts/alarms/e.g).
    :param created_date: The incident creation time.
    """
    tmp_dict = {}  # type:dict
    for val in context:
        if not val:
            continue

        if 'This alert from content' in val:
            continue

        try:
            if query_type == 'Users' and val.partition('\\')[2]:
                val = val.partition('\\')[2]

            if query_type == 'Hosts':
                val = val.partition(':')[0]
        except Exception as err:
            demisto.error(f'Could not parse value: {val}, error: {err}')
            pass
        if not val:
            continue

        val = val.capitalize()

        if tmp_dict.get(val):
            tmp_dict[val] = tmp_dict[val] + 1
        else:
            tmp_dict[val] = 1

    if created_date and tmp_dict:
        xdr_list.append({'created': created_date, 'data': tmp_dict})


def main():
    try:
        start_time = time.time()
        date_pattern = re.compile('\d{4}[-/]\d{2}[-/]\d{2}T\d{2}:\d{2}:\d{2}')
        include_closed_incidents = argToBoolean(demisto.getArg('includeClosedIncidents'))

        # initialize xdr data lists
        xdr_data_lists = {}  # type:dict
        for key in QUERY_TYPE_TO_KEY.keys():
            xdr_data_lists[key] = []

        # get the xdr incidents
        incidents = get_xdr_incidents(include_closed_incidents)

        for incident in incidents:
            context = incident.get('context')
            # gets the created time of the incidents in format %Y-%m-%dT%H:%M:%S
            created_date = incident.get('created')
            created_date = date_pattern.findall(created_date)[0]

            # update all the lists for each incident
            for key, val in QUERY_TYPE_TO_KEY.items():
                key_values = demisto.dt(context, val)  # type:list
                if key_values:
                    update_xdr_list(key_values, xdr_data_lists[key], key, created_date)

        created_lists = []
        # create demisto list for each list item
        for key in QUERY_TYPE_TO_KEY.keys():
            list_name = f'xdrIncidents_{key}'
            res = demisto.executeCommand('createList', {'listName': list_name, 'listData': xdr_data_lists[key]})
            if isError(res):
                return_error(f'Error occurred while trying to create the list {list_name}: {get_error(res)}')
            created_lists.append({'List name': list_name, 'Items': len(xdr_data_lists[key])})

        end_time = time.time()
        elapsed = round(end_time - start_time, 2)
        return_results(CommandResults(
            readable_output=f'Collecting data for {len(incidents)} XDR incidents successfully in {elapsed} seconds.'
                            f'\nthe script created the following lists:'
                            f'\n{tableToMarkdown("", created_lists, ["List name", "Items"])}'
        ))

    except Exception as e:
        return_error(str(e))


if __name__ in ['builtins', '__main__']:
    main()
