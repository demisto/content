from dateutil import parser

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

QUERY_TYPE_TO_FIELD = {
    'Categories': {'cliName': 'xdralerts', 'fieldName': 'category'},
    'Users': {'cliName': 'xdralerts', 'fieldName': 'username'},
    'Hosts': {'cliName': 'xdralerts', 'fieldName': 'hostname'},
    'Alerts': {'cliName': 'xdralerts', 'fieldName': 'name'},
    'MitreTactic': {'cliName': 'xdralerts', 'fieldName': 'mitretacticidandname'},
    'MitreTechnique': {'cliName': 'xdralerts', 'fieldName': 'mitretechniqueidandname'},
    'FileSHA2': {'cliName': 'xdrfileartifacts', 'fieldName': 'file_sha256'},
    'File': {'cliName': 'xdrfileartifacts', 'fieldName': 'file_name'},
}


def update_result_dict(val: str, res_dict: dict, query_type: str):
    """
    Updated the result dict counters with the current context values.
    :param context: List of values from the incident context key.
    :param res_dict: The result dictionary that contains the counters of the query.
    :param query_type: The item to gets the result in the incident(users/hosts/alarms/e.g).
    """

    if val == 'null':
        return

    if 'This alert from content' in val:
        return

    if query_type == 'Users' and val.partition('\\')[2]:
        val = val.partition('\\')[2]

    if query_type == 'Hosts':
        val = val.partition(':')[0]

    if not val:
        return

    val = val.capitalize()

    if res_dict.get(val):
        res_dict[val] = res_dict[val] + 1
    else:
        res_dict[val] = 1


def main():
    try:
        args = demisto.args()
        res_dict = {}  # type:dict
        res_type = args.get('reultType')
        query_type = args.get('queryType')
        from_date = args.get('from')
        to_date = args.get('to')

        incidents_args = {}
        incidents_args['type'] = 'Cortex XDR Incident'
        incidents_args['size'] = args.get('limit')
        incidents_args['status'] = 'Active or Pending'

        if from_date:
            incidents_args['fromdate'] = from_date
        if to_date:
            incidents_args['todate'] = to_date
        incidents_res = demisto.executeCommand("getIncidents", incidents_args)

        incidents = incidents_res[0]['Contents'].get('data') or []

        if QUERY_TYPE_TO_FIELD.get(query_type):
            cli_name = QUERY_TYPE_TO_FIELD[query_type]['cliName']
            field_name = QUERY_TYPE_TO_FIELD[query_type]['fieldName']
            for incident in incidents:
                for item in incident['CustomFields'][cli_name]:
                    val = item.get(field_name)
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
