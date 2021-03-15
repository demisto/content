from dateutil import parser

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

INCIDENTS_QUERY = 'status:Active or status:Pending and type:"Cortex XDR Incident"'

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


def get_demisto_datetme_format(date_string):
    if date_string:
        date_object = None
        # try to parse date string
        try:
            date_object = parser.parse(date_string)
        except Exception:
            pass
        # try to parse relative time
        if date_object is None and date_string.strip().endswith("ago"):
            date_object = parse_relative_time(date_string)

        if date_object:
            return date_object.astimezone().isoformat('T')
        else:
            return None


def get_incidents_by_page(args, page):
    args['page'] = page
    incidents_res = demisto.executeCommand("getIncidents", args)
    return incidents_res[0]['Contents'].get('data') or []


def get_incidents(args, limit):
    incident_list = []
    page = 0
    while len(incident_list) < limit:
        incidents = get_incidents_by_page(args, page)
        if not incidents:
            break
        incident_list += incidents
        page += 1
    return incident_list[:limit]


def main():

    try:
        args = demisto.args()
        res_dict = {}  # type:dict
        res_type = args.get('reultType')
        query_type = args.get('queryType')
        from_date = args.get('from')
        to_date = args.get('to')
        page_size = args.get('pageSize')
        limit = int(args.get('limit'))

        incidents_args = {}
        incidents_args['type'] = 'Cortex XDR Incident'
        incidents_args['size'] = int(page_size)
        incidents_args['status'] = 'Active or Pending'

        if from_date:
            from_datetime = get_demisto_datetme_format(from_date)
            if from_datetime:
                incidents_args['fromdate'] = from_datetime
            else:
                demisto.results("did not set from date due to a wrong format: " + from_date)

        if to_date:
            to_datetime = get_demisto_datetme_format(to_date)
            if to_datetime:
                incidents_args['todate'] = to_datetime
            else:
                demisto.results("did not set to date due to a wrong format: " + from_date)

        incidents = get_incidents(incidents_args, limit)

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
            return_results(len(res_dict))

    except Exception as e:
        return_error(str(e))


if __name__ in ['builtins', '__main__']:
    main()
