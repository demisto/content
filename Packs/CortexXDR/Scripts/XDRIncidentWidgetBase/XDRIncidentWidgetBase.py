import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

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


def get_xdr_incidents(limit: int, to_date: str, from_date: str) -> []:
    """
    Returns Cortex XDR incident with status Active or Pending using GetIncidentsByQuery script.
    :param limit: The maximum number of incidents to fetch
    :param to_date: The end date by which to filter incidents.
    :param from_date: The start date by which to filter incidents.
    :return: Cortex XDR incident objects
    """
    get_incidents_args = {
        'query': 'status:Active or status:Pending and type:"Cortex XDR Incident"',
        'includeContext': True,
        'limit': limit,
        'toDate': to_date,
        'fromDate': from_date
    }

    incidents_res = demisto.executeCommand('GetIncidentsByQuery', get_incidents_args)
    if isError(incidents_res):
        return_error(f'Error occurred while trying to get incidents: {get_error(incidents_res)}')

    return json.loads(incidents_res[0].get('Contents'))


def update_result_dict(context: list, res_dict: dict, query_type: str):
    """
    Updated the result dict counters with the current context values.
    :param context: List of values from the incident context key.
    :param res_dict: The result dictionary that contains the counters of the query.
    :param query_type: The item to gets the result in the incident(users/hosts/alarms/e.g).
    """
    for val in context:
        if not val:
            continue

        if 'This alert from content' in val:
            continue
        if query_type == 'Users' and val.partition('\\')[2]:
            val = val.partition('\\')[2]

        if query_type == 'Hosts':
            val = val.partition(':')[0]

        if not val:
            continue

        val = val.capitalize()

        if res_dict.get(val):
            res_dict[val] = res_dict[val] + 1
        else:
            res_dict[val] = 1


def main():
    try:
        args = demisto.args()

        res_type = args.get('reultType')
        query_type = args.get('queryType')
        to_date = args.get('toDate')
        from_date = args.get('fromDate')

        try:
            limit = int(args.get('limit'))
        except ValueError:
            limit = 3000
        incidents = get_xdr_incidents(limit, to_date, from_date)

        res_dict = {}  # type:dict
        for incident in incidents:
            context = incident.get('context')

            val = demisto.dt(context, QUERY_TYPE_TO_KEY[query_type])
            if val:
                update_result_dict(val, res_dict, query_type)

        if res_type == 'Top10':
            res = sorted(res_dict.items(), key=lambda x: x[1], reverse=True)[:10]

            data = []
            for item in res:
                data.append({'name': item[0], 'data': [item[1]]})

            return_results(json.dumps(data))
        elif res_type == 'DistinctCount':
            return_results(str(len(res_dict.keys())))

    except Exception as e:
        return_error(str(e))


if __name__ in ['builtins', '__main__']:
    main()
