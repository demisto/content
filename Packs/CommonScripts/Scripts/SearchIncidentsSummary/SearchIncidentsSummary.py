import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


special = ['n', 't', '\\', '"', '\'', '7', 'r']


def check_if_found_incident(res: list):
    if res and isinstance(res, list) and isinstance(res[0].get('Contents'), dict):
        if 'data' not in res[0]['Contents']:
            raise DemistoException(res[0].get('Contents'))
        elif res[0]['Contents']['data'] is None:
            return False
        return True
    else:
        raise DemistoException(f'failed to get incidents from xsoar.\nGot: {res}')


def is_valid_args(args: dict):
    array_args: list[str] = ['id', 'name', 'status', 'notstatus', 'reason', 'level', 'owner', 'type', 'query']
    error_msg: list[str] = []
    for _key, value in args.items():
        if _key in array_args:
            try:
                if _key == 'id':
                    if not isinstance(value, (int, str, list)):
                        error_msg.append(
                            f'Error while parsing the incident id with the value: {value}. The given type: '
                            f'{type(value)} is not a valid type for an ID. The supported id types are: int, list and str')
                    elif isinstance(value, str):
                        _ = bytes(value, "utf-8").decode("unicode_escape")
                else:
                    _ = bytes(value, "utf-8").decode("unicode_escape")
            except UnicodeDecodeError as ex:
                error_msg.append(f'Error while parsing the argument: "{_key}" '
                                 f'\nError:\n- "{str(ex)}"')

    if len(error_msg) != 0:
        raise DemistoException('\n'.join(error_msg))

    return True


def apply_filters(incidents: list, args: dict):
    names_to_filter = set(argToList(args.get('name')))
    types_to_filter = set(argToList(args.get('type')))
    filtered_incidents = []
    fields = ['id', 'name', 'type', 'severity', 'status', 'owner', 'created', 'closed']
    if args.get("add_fields_to_context"):
        fields = fields + args.get("add_fields_to_context", '').split(",")
        fields = [x.strip() for x in fields]  # clear out whitespace
    for incident in incidents:
        if names_to_filter and incident['name'] not in names_to_filter:
            continue
        if types_to_filter and incident['type'] not in types_to_filter:
            continue

        style_incident = {}
        for field in fields:
            style_incident[field] = incident.get(field, incident["CustomFields"].get(field, "n/a"))
        filtered_incidents.append(style_incident)

    return filtered_incidents


def add_incidents_link(data: list):
    server_url = demisto.demistoUrls().get('server')
    for incident in data:
        incident_link = urljoin(server_url, f'#/Details/{incident.get("id")}')
        incident['incidentLink'] = incident_link
    return data


def search_incidents(args: dict):   # pragma: no cover
    if not is_valid_args(args):
        return None

    if fromdate := arg_to_datetime(args.get('fromdate')):
        from_date = fromdate.isoformat()
        args['fromdate'] = from_date
    if todate := arg_to_datetime(args.get('todate')):
        to_date = todate.isoformat()
        args['todate'] = to_date

    if args.get('trimevents') == '0':
        args.pop('trimevents')

    # handle list of ids
    if args.get('id'):
        args['id'] = ','.join(argToList(args.get('id'), transform=str))

    res: list = execute_command('getIncidents', args, extract_contents=False)
    incident_found: bool = check_if_found_incident(res)
    if incident_found is False:
        return 'Incidents not found.', {}, {}

    data = apply_filters(res[0]['Contents']['data'], args)
    data = add_incidents_link(data)
    headers: list[str] = ['id', 'name', 'severity', 'status', 'owner', 'created', 'closed', 'incidentLink']
    if args.get("add_fields_to_context"):
        add_headers: list[str] = args.get("add_fields_to_context", '').split(",")
        headers = headers + add_headers
    md: str = tableToMarkdown(name="Incidents found", t=data, headers=headers)
    return md, data, res


def main():  # pragma: no cover
    args: dict = demisto.args()
    try:
        readable_output, outputs, raw_response = search_incidents(args)
        if search_results_label := args.get('searchresultslabel'):
            for output in outputs:
                output['searchResultsLabel'] = search_results_label
        results = CommandResults(
            outputs_prefix='foundIncidents',
            outputs_key_field='id',
            readable_output=readable_output,
            outputs=outputs,
            raw_response=raw_response,
            ignore_auto_extract=True
        )
        return_results(results)
    except DemistoException as error:
        return_error(str(error), error)


if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    main()
