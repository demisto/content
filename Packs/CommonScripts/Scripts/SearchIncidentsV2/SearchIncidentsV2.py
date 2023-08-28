import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from enum import Enum

special = ['n', 't', '\\', '"', '\'', '7', 'r']
DEFAULT_LIMIT = 100
DEFAULT_PAGE_SIZE = 100
STARTING_PAGE_NUMBER = 1


class AlertSeverity(Enum):
    UNKNOWN = 0
    INFO = 0.5
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class AlertStatus(Enum):
    PENDING = 0
    ACTIVE = 1
    DONE = 2
    ARCHIVE = 3


def check_if_found_incident(res: List):
    if res and isinstance(res, list) and isinstance(res[0].get('Contents'), dict):
        if 'data' not in res[0]['Contents']:
            raise DemistoException(res[0].get('Contents'))
        elif res[0]['Contents']['data'] is None:
            return False
        return True
    else:
        raise DemistoException(f'failed to get incidents from xsoar.\nGot: {res}')


def is_valid_args(args: Dict):
    array_args: List[str] = ['id', 'name', 'status', 'notstatus', 'reason', 'level', 'owner', 'type', 'query']
    error_msg: List[str] = []
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


def apply_filters(incidents: List, args: Dict):
    names_to_filter = set(argToList(args.get('name')))
    types_to_filter = set(argToList(args.get('type')))

    filtered_incidents = []
    for incident in incidents:
        incident_id, incident_type = incident.get('id'), incident.get('type')
        if names_to_filter and incident['name'] not in names_to_filter:
            continue
        demisto.debug(f'{incident_id=}, {incident_type=}')
        if types_to_filter and incident['type'] not in types_to_filter:
            continue
        filtered_incidents.append(incident)

    return filtered_incidents


def summarize_incidents(args, incidents):
    summerized_fields = ['id', 'name', 'type', 'severity', 'status', 'owner', 'created', 'closed', 'incidentLink']
    if args.get("add_fields_to_summarize_context"):
        summerized_fields = summerized_fields + args.get("add_fields_to_summarize_context", '').split(",")
        summerized_fields = [x.strip() for x in summerized_fields]  # clear out whitespace
    summarized_incidents = []
    for incident in incidents:
        summarizied_incident = {}
        for field in summerized_fields:
            summarizied_incident[field] = incident.get(field, incident["CustomFields"].get(field, "n/a"))
        summarized_incidents.append(summarizied_incident)
    return summarized_incidents


def add_incidents_link(data: List, platform: str):
    # For XSIAM links
    if platform == 'x2':
        server_url = 'https://' + demisto.getLicenseCustomField('Http_Connector.url')
        for incident in data:
            incident_link = urljoin(server_url,
                                    f'alerts?action:openAlertDetails={incident.get("id")}-investigation')
            incident['alertLink'] = incident_link
    # For XSOAR links
    else:
        server_url = demisto.demistoUrls().get('server')
        for incident in data:
            incident_link = urljoin(server_url, f'#/Details/{incident.get("id")}')
            incident['incidentLink'] = incident_link
    return data


def transform_to_alert_data(incidents: List):
    for incident in incidents:
        incident['hostname'] = incident.get('CustomFields', {}).get('hostname')
        incident['initiatedby'] = incident.get('CustomFields', {}).get('initiatedby')
        incident['targetprocessname'] = incident.get('CustomFields', {}).get('targetprocessname')
        incident['username'] = incident.get('CustomFields', {}).get('username')
        incident['status'] = AlertStatus(incident.get('status')).name
        incident['severity'] = AlertSeverity(incident.get('severity')).name

    return incidents


def search_incidents(args: Dict):   # pragma: no cover
    is_summarized_version = argToBoolean(args.get('summarizedversion', False))
    if not is_valid_args(args):
        return

    if fromdate := arg_to_datetime(args.get('fromdate', '30 days ago' if is_summarized_version else None)):
        from_date = fromdate.isoformat()
        args['fromdate'] = from_date

    if todate := arg_to_datetime(args.get('todate')):
        to_date = todate.isoformat()
        args['todate'] = to_date

    if args.get('trimevents'):
        platform = demisto.demistoVersion().get('platform', 'xsoar')
        if platform == 'xsoar' or platform == 'xsoar_hosted':
            raise ValueError('The trimevents argument is not supported in XSOAR.')

        if args.get('trimevents') == '0':
            args.pop('trimevents')

    platform = get_demisto_version().get('platform')

    # handle list of ids
    if args.get('id'):
        args['id'] = ','.join(argToList(args.get('id'), transform=str))

    res: List = execute_command('getIncidents', args, extract_contents=False)
    incident_found: bool = check_if_found_incident(res)
    if incident_found is False:
        if platform == 'x2':
            return 'Alerts not found.', {}, {}
        return 'Incidents not found.', {}, {}

    limit = arg_to_number(args.get('limit')) or DEFAULT_LIMIT
    all_found_incidents = res[0]["Contents"]["data"]
    demisto.debug(
        f'Amount of incidents before filtering = {len(all_found_incidents)} with args {args} before pagination'
    )
    all_found_incidents = add_incidents_link(apply_filters(all_found_incidents, args), platform)
    demisto.debug(
        f'Amount of incidents after filtering = {len(all_found_incidents)} before pagination'
    )
    # adding 1 here because the default page number start from 0
    max_page = (res[0]["Contents"]["total"] // DEFAULT_PAGE_SIZE) + 1
    demisto.debug(f'{max_page=}')

    page = STARTING_PAGE_NUMBER
    while len(all_found_incidents) < limit and page < max_page:
        args['page'] = page
        current_page_found_incidents = execute_command('getIncidents', args).get('data') or []
        demisto.debug(
            f'before filtering {len(current_page_found_incidents)=} '
            f' {args=} {page=}'
        )
        current_page_found_incidents = add_incidents_link(apply_filters(current_page_found_incidents, args), platform)
        demisto.debug(f'after filtering = {len(current_page_found_incidents)=}')
        all_found_incidents.extend(current_page_found_incidents)
        page += 1

    all_found_incidents = all_found_incidents[:limit]
    headers: List[str]
    if platform == 'x2':
        headers = ['id', 'name', 'severity', 'details', 'hostname', 'initiatedby', 'status',
                   'owner', 'targetprocessname', 'username', 'alertLink']
        all_found_incidents = transform_to_alert_data(all_found_incidents)
        md = tableToMarkdown(name="Alerts found", t=all_found_incidents, headers=headers, removeNull=True, url_keys=['alertLink'])
    else:
        headers = ['id', 'name', 'severity', 'status', 'owner', 'created', 'closed', 'incidentLink']
        if is_summarized_version:
            all_found_incidents = summarize_incidents(args, all_found_incidents)
            if args.get("add_fields_to_summarize_context"):
                add_headers: List[str] = args.get("add_fields_to_summarize_context", '').split(",")
                headers = headers + add_headers
        md = tableToMarkdown(name="Incidents found", t=all_found_incidents, headers=headers)
    demisto.debug(f'amount of all the incidents that were found {len(all_found_incidents)}')
    return md, all_found_incidents, res


def main():  # pragma: no cover
    args: Dict = demisto.args()
    is_summarized_version = argToBoolean(args.get('summarizedversion', False))
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
            # in summerized version, ignore auto extract
            ignore_auto_extract=is_summarized_version
        )
        return_results(results)
    except DemistoException as error:
        return_error(str(error), error)


if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    main()
