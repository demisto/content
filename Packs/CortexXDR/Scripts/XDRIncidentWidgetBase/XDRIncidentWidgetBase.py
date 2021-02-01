import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

QUERY_TYPE_TO_PATH = {
    'Categories': 'PaloAltoNetworksXDR.Incident.alerts.category',
    'Users': 'PaloAltoNetworksXDR.Incident.users',
    'Hosts': 'PaloAltoNetworksXDR.Incident.hosts',
    'Alerts': 'PaloAltoNetworksXDR.Incident.alerts.name',
    'MitreTactic': 'PaloAltoNetworksXDR.Incident.alerts.mitre_tactic_id_and_name',
    'MitreTechnique': 'PaloAltoNetworksXDR.Incident.alerts.mitre_technique_id_and_name',
    'FileSHA2': 'PaloAltoNetworksXDR.Incident.file_artifacts.file_sha256',
    'File': 'PaloAltoNetworksXDR.Incident.file_artifacts.file_name'
}


def get_path_value(context, path):
    path = path.split('.')
    for item in path:
        if isinstance(context, list):
            res = []
            for val in context:
                res.append(val[item])
            return res
        elif context.get(item):
            context = context[item]
            continue
        return []
    return context


def get_context(incident_id, path):
    res = demisto.executeCommand("getContext", {'id': incident_id})
    try:
        context = res[0]['Contents'].get('context') or {}
    except Exception:
        return []

    return get_path_value(context, path)


def main():
    try:
        args = demisto.args()

        limit = int(args.get('limit'))
        res_type = args.get('reultType')
        query_type = args.get('queryType')
        to_date = args.get('to')
        from_date = args.get('from')

        get_incidents_args = {
            'query': 'status:Active or status:Pending and type:"Cortex XDR Incident"',
            'limit': limit,
            'toDate': to_date,
            'fromDate': from_date
        }

        incidents_res = demisto.executeCommand('GetIncidentsByQuery', get_incidents_args)
        if isError(incidents_res[0]):
            return_error(f'Error occurred while trying to get incidents: {incidents_res[0].get("Contents")}')

        incidents = json.loads(incidents_res[0].get('Contents'))
        incidents_ids = [inc.get('id') for inc in incidents]

        res_dict = {}  # type:dict
        for incident in incidents_ids:
            context = get_context(incident, QUERY_TYPE_TO_PATH[query_type])

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

        if res_type == 'Top10':
            res = sorted(res_dict.items(), key=lambda x: x[1], reverse=True)[:10]

            data = []
            for item in res:
                data.append({'name': item[0], 'data': [item[1]]})

            demisto.results(json.dumps(data))
        elif res_type == 'DistinctCount':
            demisto.results(len(res_dict.keys()))

    except Exception as e:
        return_error(str(e))


if __name__ in ['builtins', '__main__']:
    main()
