from datetime import timezone
import secrets
import string
import hashlib
from typing import Any, Dict
import dateparser
import urllib3
import traceback
from CommonServerPython import *

# Disable insecure warnings
urllib3.disable_warnings()

TIME_FORMAT = "%Y-%m-%dT%H:%M:%S"
NONCE_LENGTH = 64
API_KEY_LENGTH = 128

INTEGRATION_CONTEXT_BRAND = 'PaloAltoNetworksXDR'


def convert_epoch_to_milli(timestamp):
    if timestamp is None:
        return None
    if 9 < len(str(timestamp)) < 13:
        timestamp = int(timestamp) * 1000
    return int(timestamp)


def convert_datetime_to_epoch(the_time=0):
    if the_time is None:
        return None
    try:
        if isinstance(the_time, datetime):
            return int(the_time.strftime('%s'))
    except Exception as err:
        print(err)
        return 0


def convert_datetime_to_epoch_millis(the_time=0):
    return convert_epoch_to_milli(convert_datetime_to_epoch(the_time=the_time))


def generate_current_epoch_utc():
    return convert_datetime_to_epoch_millis(datetime.now(timezone.utc))


def generate_key():
    return "".join([secrets.choice(string.ascii_letters + string.digits) for _ in range(API_KEY_LENGTH)])


def create_auth(api_key):
    nonce = "".join([secrets.choice(string.ascii_letters + string.digits) for _ in range(NONCE_LENGTH)])
    timestamp = str(generate_current_epoch_utc())  # Get epoch time utc millis
    hash_ = hashlib.sha256()
    hash_.update((api_key + nonce + timestamp).encode("utf-8"))
    return nonce, timestamp, hash_.hexdigest()


def clear_trailing_whitespace(res):
    index = 0
    while index < len(res):
        for key, value in res[index].items():
            if isinstance(value, str):
                res[index][key] = value.rstrip()
        index += 1
    return res


class Client(BaseClient):
    def test_module(self, first_fetch_time):
        """
            Performs basic get request to get item samples
        """
        last_one_day, _ = parse_date_range(first_fetch_time, TIME_FORMAT)
        self.get_incidents(lte_creation_time=last_one_day, limit=1)

    def get_incidents(self, incident_id_list=None, lte_modification_time=None, gte_modification_time=None,
                      lte_creation_time=None, gte_creation_time=None, sort_by_modification_time=None,
                      sort_by_creation_time=None, page_number=0, limit=100, gte_creation_time_milliseconds=0):
        """
        Filters and returns incidents

        :param incident_id_list: List of incident ids - must be list
        :param lte_modification_time: string of time format "2019-12-31T23:59:00"
        :param gte_modification_time: string of time format "2019-12-31T23:59:00"
        :param lte_creation_time: string of time format "2019-12-31T23:59:00"
        :param gte_creation_time: string of time format "2019-12-31T23:59:00"
        :param sort_by_modification_time: optional - enum (asc,desc)
        :param sort_by_creation_time: optional - enum (asc,desc)
        :param page_number: page number
        :param limit: maximum number of incidents to return per page
        :param gte_creation_time_milliseconds: greater than time in milliseconds
        :return:
        """
        search_from = page_number * limit
        search_to = search_from + limit

        request_data = {
            'search_from': search_from,
            'search_to': search_to
        }

        if sort_by_creation_time and sort_by_modification_time:
            raise ValueError('Should be provide either sort_by_creation_time or '
                             'sort_by_modification_time. Can\'t provide both')
        if sort_by_creation_time:
            request_data['sort'] = {
                'field': 'creation_time',
                'keyword': sort_by_creation_time
            }
        elif sort_by_modification_time:
            request_data['sort'] = {
                'field': 'modification_time',
                'keyword': sort_by_modification_time
            }

        filters = []
        if incident_id_list is not None and len(incident_id_list) > 0:
            filters.append({
                'field': 'incident_id_list',
                'operator': 'in',
                'value': incident_id_list
            })

        if lte_creation_time:
            filters.append({
                'field': 'creation_time',
                'operator': 'lte',
                'value': date_to_timestamp(lte_creation_time, TIME_FORMAT)
            })

        if gte_creation_time:
            filters.append({
                'field': 'creation_time',
                'operator': 'gte',
                'value': date_to_timestamp(gte_creation_time, TIME_FORMAT)
            })

        if lte_modification_time:
            filters.append({
                'field': 'modification_time',
                'operator': 'lte',
                'value': date_to_timestamp(lte_modification_time, TIME_FORMAT)
            })

        if gte_modification_time:
            filters.append({
                'field': 'modification_time',
                'operator': 'gte',
                'value': date_to_timestamp(gte_modification_time, TIME_FORMAT)
            })

        if gte_creation_time_milliseconds > 0:
            filters.append({
                'field': 'creation_time',
                'operator': 'gte',
                'value': gte_creation_time_milliseconds
            })

        if len(filters) > 0:
            request_data['filters'] = filters

        res = self._http_request(
            method='POST',
            url_suffix='/incidents/get_incidents/',
            json_data={'request_data': request_data}
        )
        incidents = res.get('reply').get('incidents', [])

        return incidents

    def get_incident_extra_data(self, incident_id, alerts_limit=1000):
        """
        Returns incident by id

        :param incident_id: The id of incident
        :param alerts_limit: Maximum number alerts to get
        :return:
        """
        request_data = {
            'incident_id': incident_id,
            'alerts_limit': alerts_limit
        }

        reply = self._http_request(
            method='POST',
            url_suffix='/incidents/get_incident_extra_data/',
            json_data={'request_data': request_data}
        )

        incident = reply.get('reply')

        return incident

    def update_incident(self, incident_id, assigned_user_mail, assigned_user_pretty_name, status, severity,
                        resolve_comment, unassign_user):
        update_data = {}

        if unassign_user and (assigned_user_mail or assigned_user_pretty_name):
            raise ValueError("Can't provide both assignee_email/assignee_name and unassign_user")
        if unassign_user:
            update_data['assigned_user_mail'] = 'none'

        if assigned_user_mail:
            update_data['assigned_user_mail'] = assigned_user_mail

        if assigned_user_pretty_name:
            update_data['assigned_user_pretty_name'] = assigned_user_pretty_name

        if status:
            update_data['status'] = status

        if severity:
            update_data['manual_severity'] = severity

        if resolve_comment:
            update_data['resolve_comment'] = resolve_comment

        request_data = {
            'incident_id': incident_id,
            'update_data': update_data
        }

        self._http_request(
            method='POST',
            url_suffix='/incidents/update_incident/',
            json_data={'request_data': request_data}
        )

    def get_endpoints(self,
                      endpoint_id_list=None,
                      dist_name=None,
                      ip_list=None,
                      group_name=None,
                      platform=None,
                      alias_name=None,
                      isolate=None,
                      hostname=None,
                      page_number=0,
                      limit=30,
                      first_seen_gte=None,
                      first_seen_lte=None,
                      last_seen_gte=None,
                      last_seen_lte=None,
                      sort_by_first_seen=None,
                      sort_by_last_seen=None,
                      no_filter=False
                      ):

        search_from = page_number * limit
        search_to = search_from + limit

        request_data = {
            'search_from': search_from,
            'search_to': search_to
        }

        if no_filter:
            reply = self._http_request(
                method='POST',
                url_suffix='/endpoints/get_endpoints/',
                json_data={}
            )
            endpoints = reply.get('reply')[search_from:search_to]
            for endpoint in endpoints:
                if not endpoint.get('endpoint_id'):
                    endpoint['endpoint_id'] = endpoint.get('agent_id')

        else:
            filters = []
            if endpoint_id_list:
                filters.append({
                    'field': 'endpoint_id_list',
                    'operator': 'in',
                    'value': endpoint_id_list
                })

            if dist_name:
                filters.append({
                    'field': 'dist_name',
                    'operator': 'in',
                    'value': dist_name
                })

            if ip_list:
                filters.append({
                    'field': 'ip_list',
                    'operator': 'in',
                    'value': ip_list
                })

            if group_name:
                filters.append({
                    'field': 'group_name',
                    'operator': 'in',
                    'value': group_name
                })

            if platform:
                filters.append({
                    'field': 'platform',
                    'operator': 'in',
                    'value': platform
                })

            if alias_name:
                filters.append({
                    'field': 'alias_name',
                    'operator': 'in',
                    'value': alias_name
                })

            if isolate:
                filters.append({
                    'field': 'isolate',
                    'operator': 'in',
                    'value': [isolate]
                })

            if hostname:
                filters.append({
                    'field': 'hostname',
                    'operator': 'in',
                    'value': hostname
                })

            if first_seen_gte:
                filters.append({
                    'field': 'first_seen',
                    'operator': 'gte',
                    'value': first_seen_gte
                })

            if first_seen_lte:
                filters.append({
                    'field': 'first_seen',
                    'operator': 'lte',
                    'value': first_seen_lte
                })

            if last_seen_gte:
                filters.append({
                    'field': 'last_seen',
                    'operator': 'gte',
                    'value': last_seen_gte
                })

            if last_seen_lte:
                filters.append({
                    'field': 'last_seen',
                    'operator': 'lte',
                    'value': last_seen_lte
                })

            if search_from:
                request_data['search_from'] = search_from

            if search_to:
                request_data['search_to'] = search_to

            if sort_by_first_seen:
                request_data['sort'] = {
                    'field': 'first_seen',
                    'keyword': sort_by_first_seen
                }
            elif sort_by_last_seen:
                request_data['sort'] = {
                    'field': 'last_seen',
                    'keyword': sort_by_last_seen
                }

            request_data['filters'] = filters

            reply = self._http_request(
                method='POST',
                url_suffix='/endpoints/get_endpoint/',
                json_data={'request_data': request_data}
            )

            endpoints = reply.get('reply').get('endpoints', [])
        return endpoints

    def isolate_endpoint(self, endpoint_id):
        self._http_request(
            method='POST',
            url_suffix='/endpoints/isolate',
            json_data={
                'request_data': {
                    'endpoint_id': endpoint_id
                }
            }
        )

    def unisolate_endpoint(self, endpoint_id):
        self._http_request(
            method='POST',
            url_suffix='/endpoints/unisolate',
            json_data={
                'request_data': {
                    'endpoint_id': endpoint_id
                }
            }
        )

    def insert_alerts(self, alerts):
        self._http_request(
            method='POST',
            url_suffix='/alerts/insert_parsed_alerts/',
            json_data={
                'request_data': {
                    'alerts': alerts
                }
            }
        )

    def insert_cef_alerts(self, alerts):
        self._http_request(
            method='POST',
            url_suffix='/alerts/insert_cef_alerts/',
            json_data={
                'request_data': {
                    'alerts': alerts
                }
            }
        )

    def get_distribution_url(self, distribution_id, package_type):
        reply = self._http_request(
            method='POST',
            url_suffix='/distributions/get_dist_url/',
            json_data={
                'request_data': {
                    'distribution_id': distribution_id,
                    'package_type': package_type
                }
            }
        )

        return reply.get('reply').get('distribution_url')

    def get_distribution_status(self, distribution_id):
        reply = self._http_request(
            method='POST',
            url_suffix='/distributions/get_status/',
            json_data={
                'request_data': {
                    'distribution_id': distribution_id
                }
            }
        )

        return reply.get('reply').get('status')

    def get_distribution_versions(self):
        reply = self._http_request(
            method='POST',
            url_suffix='/distributions/get_versions/',
            json_data={}
        )

        return reply.get('reply')

    def create_distribution(self, name, platform, package_type, agent_version, description):
        if package_type == 'standalone':
            request_data = {
                'name': name,
                'platform': platform,
                'package_type': package_type,
                'agent_version': agent_version,
                'description': description
            }
        elif package_type == 'upgrade':
            request_data = {
                'name': name,
                'package_type': package_type,
                'description': description
            }

            if platform == 'windows':
                request_data['windows_version'] = agent_version
            elif platform == 'linux':
                request_data['linux_version'] = agent_version
            elif platform == 'macos':
                request_data['macos_version'] = agent_version

        reply = self._http_request(
            method='POST',
            url_suffix='/distributions/create/',
            json_data={
                'request_data': request_data
            }
        )

        return reply.get('reply').get('distribution_id')

    def audit_management_logs(self, email, result, _type, sub_type, search_from, search_to, timestamp_gte,
                              timestamp_lte, sort_by, sort_order):

        request_data: Dict[str, Any] = {}
        filters = []
        if email:
            filters.append({
                'field': 'email',
                'operator': 'in',
                'value': email
            })
        if result:
            filters.append({
                'field': 'result',
                'operator': 'in',
                'value': result
            })
        if _type:
            filters.append({
                'field': 'type',
                'operator': 'in',
                'value': _type
            })
        if sub_type:
            filters.append({
                'field': 'sub_type',
                'operator': 'in',
                'value': sub_type
            })
        if timestamp_gte:
            filters.append({
                'field': 'timestamp',
                'operator': 'gte',
                'value': timestamp_gte
            })
        if timestamp_lte:
            filters.append({
                'field': 'timestamp',
                'operator': 'lte',
                'value': timestamp_lte
            })

        if filters:
            request_data['filters'] = filters

        if search_from > 0:
            request_data['search_from'] = search_from

        if search_to:
            request_data['search_to'] = search_to

        if sort_by:
            request_data['sort'] = {
                'field': sort_by,
                'keyword': sort_order
            }

        reply = self._http_request(
            method='POST',
            url_suffix='/audits/management_logs/',
            json_data={'request_data': request_data}
        )

        return reply.get('reply').get('data', [])

    def get_audit_agent_reports(self, endpoint_ids, endpoint_names, result, _type, sub_type, search_from, search_to,
                                timestamp_gte, timestamp_lte, sort_by, sort_order):
        request_data: Dict[str, Any] = {}
        filters = []
        if endpoint_ids:
            filters.append({
                'field': 'endpoint_id',
                'operator': 'in',
                'value': endpoint_ids
            })
        if endpoint_names:
            filters.append({
                'field': 'endpoint_name',
                'operator': 'in',
                'value': endpoint_names
            })
        if result:
            filters.append({
                'field': 'result',
                'operator': 'in',
                'value': result
            })
        if _type:
            filters.append({
                'field': 'type',
                'operator': 'in',
                'value': _type
            })
        if sub_type:
            filters.append({
                'field': 'sub_type',
                'operator': 'in',
                'value': sub_type
            })
        if timestamp_gte:
            filters.append({
                'field': 'timestamp',
                'operator': 'gte',
                'value': timestamp_gte
            })
        if timestamp_lte:
            filters.append({
                'field': 'timestamp',
                'operator': 'lte',
                'value': timestamp_lte
            })

        if filters:
            request_data['filters'] = filters

        if search_from > 0:
            request_data['search_from'] = search_from

        if search_to:
            request_data['search_to'] = search_to

        if sort_by:
            request_data['sort'] = {
                'field': sort_by,
                'keyword': sort_order
            }

        reply = self._http_request(
            method='POST',
            url_suffix='/audits/agents_reports/',
            json_data={'request_data': request_data}
        )

        return reply.get('reply').get('data', [])


def get_incidents_command(client, args):
    """
    Retrieve a list of incidents from XDR, filtered by some filters.
    """

    # sometimes incident id can be passed as integer from the playbook
    incident_id_list = args.get('incident_id_list')
    if isinstance(incident_id_list, int):
        incident_id_list = str(incident_id_list)

    incident_id_list = argToList(incident_id_list)
    # make sure all the ids passed are strings and not integers
    for index, id_ in enumerate(incident_id_list):
        if isinstance(id_, (int, float)):
            incident_id_list[index] = str(id_)

    lte_modification_time = args.get('lte_modification_time')
    gte_modification_time = args.get('gte_modification_time')
    since_modification_time = args.get('since_modification_time')

    if since_modification_time and gte_modification_time:
        raise ValueError('Can\'t set both since_modification_time and lte_modification_time')
    if since_modification_time:
        gte_modification_time, _ = parse_date_range(since_modification_time, TIME_FORMAT)

    lte_creation_time = args.get('lte_creation_time')
    gte_creation_time = args.get('gte_creation_time')
    since_creation_time = args.get('since_creation_time')

    if since_creation_time and gte_creation_time:
        raise ValueError('Can\'t set both since_creation_time and lte_creation_time')
    if since_creation_time:
        gte_creation_time, _ = parse_date_range(since_creation_time, TIME_FORMAT)

    sort_by_modification_time = args.get('sort_by_modification_time')
    sort_by_creation_time = args.get('sort_by_creation_time')

    page = int(args.get('page', 0))
    limit = int(args.get('limit', 100))

    # If no filters were given, return a meaningful error message
    if not incident_id_list and (not lte_modification_time and not gte_modification_time and not since_modification_time
                                 and not lte_creation_time and not gte_creation_time and not since_creation_time):
        raise ValueError("Specify a query for the incidents.\nFor example:"
                         " !xdr-get-incidents since_creation_time=\"1 year\" sort_by_creation_time=\"desc\" limit=10")

    raw_incidents = client.get_incidents(
        incident_id_list=incident_id_list,
        lte_modification_time=lte_modification_time,
        gte_modification_time=gte_modification_time,
        lte_creation_time=lte_creation_time,
        gte_creation_time=gte_creation_time,
        sort_by_creation_time=sort_by_creation_time,
        sort_by_modification_time=sort_by_modification_time,
        page_number=page,
        limit=limit
    )

    return (
        tableToMarkdown('Incidents', raw_incidents),
        {
            f'{INTEGRATION_CONTEXT_BRAND}.Incident(val.incident_id==obj.incident_id)': raw_incidents
        },
        raw_incidents
    )


def get_incident_extra_data_command(client, args):
    incident_id = args.get('incident_id')
    alerts_limit = int(args.get('alerts_limit', 1000))

    raw_incident = client.get_incident_extra_data(incident_id, alerts_limit)

    incident = raw_incident.get('incident')
    incident_id = incident.get('incident_id')
    raw_alerts = raw_incident.get('alerts').get('data')
    alerts = clear_trailing_whitespace(raw_alerts)
    file_artifacts = raw_incident.get('file_artifacts').get('data')
    network_artifacts = raw_incident.get('network_artifacts').get('data')

    readable_output = [tableToMarkdown('Incident {}'.format(incident_id), incident)]

    if len(alerts) > 0:
        readable_output.append(tableToMarkdown('Alerts', alerts))
    else:
        readable_output.append(tableToMarkdown('Alerts', []))

    if len(network_artifacts) > 0:
        readable_output.append(tableToMarkdown('Network Artifacts', network_artifacts))
    else:
        readable_output.append(tableToMarkdown('Network Artifacts', []))

    if len(file_artifacts) > 0:
        readable_output.append(tableToMarkdown('File Artifacts', file_artifacts))
    else:
        readable_output.append(tableToMarkdown('File Artifacts', []))

    incident.update({
        'alerts': alerts,
        'file_artifacts': file_artifacts,
        'network_artifacts': network_artifacts
    })
    return (
        '\n'.join(readable_output),
        {
            f'{INTEGRATION_CONTEXT_BRAND}.Incident(val.incident_id==obj.incident_id)': incident
        },
        raw_incident
    )


def update_incident_command(client, args):
    incident_id = args.get('incident_id')
    assigned_user_mail = args.get('assigned_user_mail')
    assigned_user_pretty_name = args.get('assigned_user_pretty_name')
    status = args.get('status')
    severity = args.get('manual_severity')
    unassign_user = args.get('unassign_user') == 'true'
    resolve_comment = args.get('resolve_comment')

    client.update_incident(
        incident_id=incident_id,
        assigned_user_mail=assigned_user_mail,
        assigned_user_pretty_name=assigned_user_pretty_name,
        unassign_user=unassign_user,
        status=status,
        severity=severity,
        resolve_comment=resolve_comment
    )

    return f'Incident {incident_id} has been updated', None, None


def arg_to_int(arg, arg_name: str, required: bool = False):
    if arg is None:
        if required is True:
            raise ValueError(f'Missing "{arg_name}"')
        return None
    if isinstance(arg, str):
        if arg.isdigit():
            return int(arg)
        raise ValueError(f'Invalid number: "{arg_name}"="{arg}"')
    if isinstance(arg, int):
        return arg
    return ValueError(f'Invalid number: "{arg_name}"')


def get_endpoints_command(client, args):
    page_number = arg_to_int(
        arg=args.get('page'),
        arg_name='Failed to parse "page". Must be a number.',
        required=True
    )

    limit = arg_to_int(
        arg=args.get('limit'),
        arg_name='Failed to parse "limit". Must be a number.',
        required=True
    )

    if list(args.keys()) == ['limit', 'page', 'sort_order']:
        endpoints = client.get_endpoints(page_number=page_number, limit=limit, no_filter=True)
    else:
        endpoint_id_list = argToList(args.get('endpoint_id_list'))
        dist_name = argToList(args.get('dist_name'))
        ip_list = argToList(args.get('ip_list'))
        group_name = argToList(args.get('group_name'))
        platform = argToList(args.get('platform'))
        alias_name = argToList(args.get('alias_name'))
        isolate = args.get('isolate')
        hostname = argToList(args.get('hostname'))

        first_seen_gte = arg_to_timestamp(
            arg=args.get('first_seen_gte'),
            arg_name='first_seen_gte'
        )

        first_seen_lte = arg_to_timestamp(
            arg=args.get('first_seen_lte'),
            arg_name='first_seen_lte'
        )

        last_seen_gte = arg_to_timestamp(
            arg=args.get('last_seen_gte'),
            arg_name='last_seen_gte'
        )

        last_seen_lte = arg_to_timestamp(
            arg=args.get('last_seen_lte'),
            arg_name='last_seen_lte'
        )

        sort_by_first_seen = args.get('sort_by_first_seen')
        sort_by_last_seen = args.get('sort_by_last_seen')

        endpoints = client.get_endpoints(
            endpoint_id_list=endpoint_id_list,
            dist_name=dist_name,
            ip_list=ip_list,
            group_name=group_name,
            platform=platform,
            alias_name=alias_name,
            isolate=isolate,
            hostname=hostname,
            page_number=page_number,
            limit=limit,
            first_seen_gte=first_seen_gte,
            first_seen_lte=first_seen_lte,
            last_seen_gte=last_seen_gte,
            last_seen_lte=last_seen_lte,
            sort_by_first_seen=sort_by_first_seen,
            sort_by_last_seen=sort_by_last_seen
        )

    return (
        tableToMarkdown('Endpoints', endpoints),
        {f'{INTEGRATION_CONTEXT_BRAND}.Endpoint(val.endpoint_id == obj.endpoint_id)': endpoints},
        endpoints
    )


def create_parsed_alert(product, vendor, local_ip, local_port, remote_ip, remote_port, event_timestamp, severity,
                        alert_name, alert_description):
    alert = {
        "product": product,
        "vendor": vendor,
        "local_ip": local_ip,
        "local_port": local_port,
        "remote_ip": remote_ip,
        "remote_port": remote_port,
        "event_timestamp": event_timestamp,
        "severity": severity,
        "alert_name": alert_name,
        "alert_description": alert_description
    }

    return alert


def insert_parsed_alert_command(client, args):
    product = args.get('product')
    vendor = args.get('vendor')
    local_ip = args.get('local_ip')
    local_port = arg_to_int(
        arg=args.get('local_port'),
        arg_name='local_port'
    )
    remote_ip = args.get('remote_ip')
    remote_port = arg_to_int(
        arg=args.get('remote_port'),
        arg_name='remote_port'
    )

    severity = args.get('severity')
    alert_name = args.get('alert_name')
    alert_description = args.get('alert_description', '')

    if args.get('event_timestamp') is None:
        # get timestamp now if not provided
        event_timestamp = int(round(time.time() * 1000))
    else:
        event_timestamp = int(args.get('event_timestamp'))

    alert = create_parsed_alert(
        product=product,
        vendor=vendor,
        local_ip=local_ip,
        local_port=local_port,
        remote_ip=remote_ip,
        remote_port=remote_port,
        event_timestamp=event_timestamp,
        severity=severity,
        alert_name=alert_name,
        alert_description=alert_description
    )

    client.insert_alerts([alert])

    return (
        'Alert inserted successfully',
        None,
        None
    )


def insert_cef_alerts_command(client, args):
    # parsing alerts list. the reason we don't use argToList is because cef_alerts could contain comma (,) so
    # we shouldn't split them by comma
    alerts = args.get('cef_alerts')
    if isinstance(alerts, list):
        pass
    elif isinstance(alerts, str):
        if alerts[0] == '[' and alerts[-1] == ']':
            # if the string contains [] it means it is a list and must be parsed
            alerts = json.loads(alerts)
        else:
            # otherwise it is a single alert
            alerts = [alerts]
    else:
        raise ValueError('Invalid argument "cef_alerts". It should be either list of strings (cef alerts), '
                         'or single string')

    client.insert_cef_alerts(alerts)

    return (
        'Alerts inserted successfully',
        None,
        None
    )


def isolate_endpoint_command(client, args):
    endpoint_id = args.get('endpoint_id')

    endpoint = client.get_endpoints(endpoint_id_list=[endpoint_id])
    if len(endpoint) == 0:
        raise ValueError(f'Error: Endpoint {endpoint_id} was not found')

    endpoint = endpoint[0]
    endpoint_status = endpoint.get('endpoint_status')
    is_isolated = endpoint.get('is_isolated')
    if is_isolated == 'AGENT_ISOLATED':
        return (
            f'Endpoint {endpoint_id} already isolated.',
            None,
            None
        )
    if is_isolated == 'AGENT_PENDING_ISOLATION':
        return (
            f'Endpoint {endpoint_id} pending isolation.',
            None,
            None
        )
    if endpoint_status == 'DISCONNECTED':
        raise ValueError(
            f'Error: Endpoint {endpoint_id} is disconnected and therefore can not be isolated.'
        )
    if is_isolated == 'AGENT_PENDING_ISOLATION_CANCELLATION':
        raise ValueError(
            f'Error: Endpoint {endpoint_id} is pending isolation cancellation and therefore can not be isolated.'
        )
    client.isolate_endpoint(endpoint_id)

    return (
        f'The isolation request has been submitted successfully on Endpoint {endpoint_id}.\n'
        f'To check the endpoint isolation status please run: !xdr-get-endpoints endpoint_id_list={endpoint_id}'
        f' and look at the [is_isolated] field.',
        {f'{INTEGRATION_CONTEXT_BRAND}.Isolation.endpoint_id(val.endpoint_id == obj.endpoint_id)': endpoint_id},
        None
    )


def unisolate_endpoint_command(client, args):
    endpoint_id = args.get('endpoint_id')

    endpoint = client.get_endpoints(endpoint_id_list=[endpoint_id])
    if len(endpoint) == 0:
        raise ValueError(f'Error: Endpoint {endpoint_id} was not found')

    endpoint = endpoint[0]
    endpoint_status = endpoint.get('endpoint_status')
    is_isolated = endpoint.get('is_isolated')
    if is_isolated == 'AGENT_UNISOLATED':
        return (
            f'Endpoint {endpoint_id} already unisolated.',
            None,
            None
        )
    if is_isolated == 'AGENT_PENDING_ISOLATION_CANCELLATION':
        return (
            f'Endpoint {endpoint_id} pending isolation cancellation.',
            None,
            None
        )
    if endpoint_status == 'DISCONNECTED':
        raise ValueError(
            f'Error: Endpoint {endpoint_id} is disconnected and therefore can not be un-isolated.'
        )
    if is_isolated == 'AGENT_PENDING_ISOLATION':
        raise ValueError(
            f'Error: Endpoint {endpoint_id} is pending isolation and therefore can not be un-isolated.'
        )
    client.unisolate_endpoint(endpoint_id)

    return (
        f'The un-isolation request has been submitted successfully on Endpoint {endpoint_id}.\n'
        f'To check the endpoint isolation status please run: !xdr-get-endpoints endpoint_id_list={endpoint_id}'
        f' and look at the [is_isolated] field.',
        {f'{INTEGRATION_CONTEXT_BRAND}.UnIsolation.endpoint_id(val.endpoint_id == obj.endpoint_id)': endpoint_id},
        None
    )


def arg_to_timestamp(arg, arg_name: str, required: bool = False):
    if arg is None:
        if required is True:
            raise ValueError(f'Missing "{arg_name}"')
        return None

    if isinstance(arg, str) and arg.isdigit():
        # timestamp that str - we just convert it to int
        return int(arg)
    if isinstance(arg, str):
        # if the arg is string of date format 2019-10-23T00:00:00 or "3 days", etc
        date = dateparser.parse(arg, settings={'TIMEZONE': 'UTC'})
        if date is None:
            # if d is None it means dateparser failed to parse it
            raise ValueError(f'Invalid date: {arg_name}')

        return int(date.timestamp() * 1000)
    if isinstance(arg, (int, float)):
        return arg


def get_audit_management_logs_command(client, args):
    email = argToList(args.get('email'))
    result = argToList(args.get('result'))
    _type = argToList(args.get('type'))
    sub_type = argToList(args.get('sub_type'))

    timestamp_gte = arg_to_timestamp(
        arg=args.get('timestamp_gte'),
        arg_name='timestamp_gte'
    )

    timestamp_lte = arg_to_timestamp(
        arg=args.get('timestamp_lte'),
        arg_name='timestamp_lte'
    )

    page_number = arg_to_int(
        arg=args.get('page', 0),
        arg_name='Failed to parse "page". Must be a number.',
        required=True
    )
    limit = arg_to_int(
        arg=args.get('limit', 20),
        arg_name='Failed to parse "limit". Must be a number.',
        required=True
    )
    search_from = page_number * limit
    search_to = search_from + limit

    sort_by = args.get('sort_by')
    sort_order = args.get('sort_order', 'asc')

    audit_logs = client.audit_management_logs(
        email=email,
        result=result,
        _type=_type,
        sub_type=sub_type,
        timestamp_gte=timestamp_gte,
        timestamp_lte=timestamp_lte,
        search_from=search_from,
        search_to=search_to,
        sort_by=sort_by,
        sort_order=sort_order
    )

    return (
        tableToMarkdown('Audit Management Logs', audit_logs, [
            'AUDIT_ID',
            'AUDIT_RESULT',
            'AUDIT_DESCRIPTION',
            'AUDIT_OWNER_NAME',
            'AUDIT_OWNER_EMAIL',
            'AUDIT_ASSET_JSON',
            'AUDIT_ASSET_NAMES',
            'AUDIT_HOSTNAME',
            'AUDIT_REASON',
            'AUDIT_ENTITY',
            'AUDIT_ENTITY_SUBTYPE',
            'AUDIT_SESSION_ID',
            'AUDIT_CASE_ID',
            'AUDIT_INSERT_TIME'
        ]),
        {
            f'{INTEGRATION_CONTEXT_BRAND}.AuditManagementLogs(val.AUDIT_ID == obj.AUDIT_ID)': audit_logs
        },
        audit_logs
    )


def get_audit_agent_reports_command(client, args):
    endpoint_ids = argToList(args.get('endpoint_ids'))
    endpoint_names = argToList(args.get('endpoint_names'))
    result = argToList(args.get('result'))
    _type = argToList(args.get('type'))
    sub_type = argToList(args.get('sub_type'))

    timestamp_gte = arg_to_timestamp(
        arg=args.get('timestamp_gte'),
        arg_name='timestamp_gte'
    )

    timestamp_lte = arg_to_timestamp(
        arg=args.get('timestamp_lte'),
        arg_name='timestamp_lte'
    )

    page_number = arg_to_int(
        arg=args.get('page', 0),
        arg_name='Failed to parse "page". Must be a number.',
        required=True
    )
    limit = arg_to_int(
        arg=args.get('limit', 20),
        arg_name='Failed to parse "limit". Must be a number.',
        required=True
    )
    search_from = page_number * limit
    search_to = search_from + limit

    sort_by = args.get('sort_by')
    sort_order = args.get('sort_order', 'asc')

    audit_logs = client.get_audit_agent_reports(
        endpoint_ids=endpoint_ids,
        endpoint_names=endpoint_names,
        result=result,
        _type=_type,
        sub_type=sub_type,
        timestamp_gte=timestamp_gte,
        timestamp_lte=timestamp_lte,

        search_from=search_from,
        search_to=search_to,
        sort_by=sort_by,
        sort_order=sort_order
    )

    return (
        tableToMarkdown('Audit Agent Reports', audit_logs),
        {
            f'{INTEGRATION_CONTEXT_BRAND}.AuditAgentReports': audit_logs
        },
        audit_logs
    )


def get_distribution_url_command(client, args):
    distribution_id = args.get('distribution_id')
    package_type = args.get('package_type')

    url = client.get_distribution_url(distribution_id, package_type)

    return (
        f'[Distribution URL]({url})',
        {
            'PaloAltoNetworksXDR.Distribution(val.id == obj.id)': {
                'id': distribution_id,
                'url': url
            }
        },
        url
    )


def get_distribution_status_command(client, args):
    distribution_ids = argToList(args.get('distribution_ids'))

    distribution_list = []
    for distribution_id in distribution_ids:
        status = client.get_distribution_status(distribution_id)

        distribution_list.append({
            'id': distribution_id,
            'status': status
        })

    return (
        tableToMarkdown('Distribution Status', distribution_list, ['id', 'status']),
        {
            f'{INTEGRATION_CONTEXT_BRAND}.Distribution(val.id == obj.id)': distribution_list
        },
        distribution_list
    )


def get_distribution_versions_command(client):
    versions = client.get_distribution_versions()

    readable_output = []
    for operation_system in versions.keys():
        os_versions = versions[operation_system]

        readable_output.append(
            tableToMarkdown(operation_system, os_versions or [], ['versions'])
        )

    return (
        '\n\n'.join(readable_output),
        {
            f'{INTEGRATION_CONTEXT_BRAND}.DistributionVersions': versions
        },
        versions
    )


def create_distribution_command(client, args):
    name = args.get('name')
    platform = args.get('platform')
    package_type = args.get('package_type')
    description = args.get('description')
    agent_version = args.get('agent_version')
    if not platform == 'android' and not agent_version:
        # agent_version must be provided for all the platforms except android
        raise ValueError(f'Missing argument "agent_version" for platform "{platform}"')

    distribution_id = client.create_distribution(
        name=name,
        platform=platform,
        package_type=package_type,
        agent_version=agent_version,
        description=description
    )

    distribution = {
        'id': distribution_id,
        'name': name,
        'platform': platform,
        'package_type': package_type,
        'agent_version': agent_version,
        'description': description
    }

    return (
        f'Distribution {distribution_id} created successfully',
        {
            f'{INTEGRATION_CONTEXT_BRAND}.Distribution(val.id == obj.id)': distribution
        },
        distribution
    )


def fetch_incidents(client, first_fetch_time, last_run: dict = None):
    # Get the last fetch time, if exists
    last_fetch = last_run.get('time') if isinstance(last_run, dict) else None

    # Handle first time fetch, fetch incidents retroactively
    if last_fetch is None:
        last_fetch, _ = parse_date_range(first_fetch_time, to_timestamp=True)

    incidents = []
    raw_incidents = client.get_incidents(gte_creation_time_milliseconds=last_fetch,
                                         limit=50, sort_by_creation_time='asc')

    for raw_incident in raw_incidents:
        incident_id = raw_incident.get('incident_id')
        description = raw_incident.get('description')
        occurred = timestamp_to_datestring(raw_incident['creation_time'], TIME_FORMAT + 'Z')
        incident = {
            'name': f'#{incident_id} - {description}',
            'occurred': occurred,
            'rawJSON': json.dumps(raw_incident)
        }

        # Update last run and add incident if the incident is newer than last fetch
        if raw_incident['creation_time'] > last_fetch:
            last_fetch = raw_incident['creation_time']

        incidents.append(incident)

    next_run = {'time': last_fetch + 1}
    return next_run, incidents


def main():
    """
    Executes an integration command
    """
    LOG(f'Command being called is {demisto.command()}')

    api_key = demisto.params().get('apikey')
    api_key_id = demisto.params().get('apikey_id')
    first_fetch_time = demisto.params().get('fetch_time', '3 days')
    base_url = urljoin(demisto.params().get('url'), '/public_api/v1')
    proxy = demisto.params().get('proxy')
    verify_cert = not demisto.params().get('insecure', False)

    # nonce, timestamp, auth = create_auth(API_KEY)
    nonce = "".join([secrets.choice(string.ascii_letters + string.digits) for _ in range(64)])
    timestamp = str(int(datetime.now(timezone.utc).timestamp()) * 1000)
    auth_key = "%s%s%s" % (api_key, nonce, timestamp)
    auth_key = auth_key.encode("utf-8")
    api_key_hash = hashlib.sha256(auth_key).hexdigest()

    headers = {
        "x-xdr-timestamp": timestamp,
        "x-xdr-nonce": nonce,
        "x-xdr-auth-id": str(api_key_id),
        "Authorization": api_key_hash
    }

    client = Client(
        base_url=base_url,
        proxy=proxy,
        verify=verify_cert,
        headers=headers
    )

    try:
        if demisto.command() == 'test-module':
            client.test_module(first_fetch_time)
            demisto.results('ok')

        elif demisto.command() == 'fetch-incidents':
            next_run, incidents = fetch_incidents(client, first_fetch_time, demisto.getLastRun())
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif demisto.command() == 'xdr-get-incidents':
            return_outputs(*get_incidents_command(client, demisto.args()))

        elif demisto.command() == 'xdr-get-incident-extra-data':
            return_outputs(*get_incident_extra_data_command(client, demisto.args()))

        elif demisto.command() == 'xdr-update-incident':
            return_outputs(*update_incident_command(client, demisto.args()))

        elif demisto.command() == 'xdr-get-endpoints':
            return_outputs(*get_endpoints_command(client, demisto.args()))

        elif demisto.command() == 'xdr-insert-parsed-alert':
            return_outputs(*insert_parsed_alert_command(client, demisto.args()))

        elif demisto.command() == 'xdr-insert-cef-alerts':
            return_outputs(*insert_cef_alerts_command(client, demisto.args()))

        elif demisto.command() == 'xdr-isolate-endpoint':
            return_outputs(*isolate_endpoint_command(client, demisto.args()))

        elif demisto.command() == 'xdr-unisolate-endpoint':
            return_outputs(*unisolate_endpoint_command(client, demisto.args()))

        elif demisto.command() == 'xdr-get-distribution-url':
            return_outputs(*get_distribution_url_command(client, demisto.args()))

        elif demisto.command() == 'xdr-get-create-distribution-status':
            return_outputs(*get_distribution_status_command(client, demisto.args()))

        elif demisto.command() == 'xdr-get-distribution-versions':
            return_outputs(*get_distribution_versions_command(client))

        elif demisto.command() == 'xdr-create-distribution':
            return_outputs(*create_distribution_command(client, demisto.args()))

        elif demisto.command() == 'xdr-get-audit-management-logs':
            return_outputs(*get_audit_management_logs_command(client, demisto.args()))

        elif demisto.command() == 'xdr-get-audit-agent-reports':
            return_outputs(*get_audit_agent_reports_command(client, demisto.args()))

    except Exception as err:
        if demisto.command() == 'fetch-incidents':
            LOG(str(err))
            raise

        demisto.error(traceback.format_exc())
        return_error(str(err))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
