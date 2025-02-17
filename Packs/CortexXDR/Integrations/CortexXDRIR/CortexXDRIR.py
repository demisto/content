import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import hashlib
import secrets
import string
from itertools import zip_longest
from datetime import datetime, timedelta

from CoreIRApiModule import *


TIME_FORMAT = "%Y-%m-%dT%H:%M:%S"
NONCE_LENGTH = 64
API_KEY_LENGTH = 128

INTEGRATION_CONTEXT_BRAND = 'PaloAltoNetworksXDR'
XDR_INCIDENT_TYPE_NAME = 'Cortex XDR Incident Schema'
INTEGRATION_NAME = 'Cortex XDR - IR'
ALERTS_LIMIT_PER_INCIDENTS: int = -1
REMOVE_ALERTS_NULL_VALUES = 'null_values'
FIELDS_TO_EXCLUDE = [
    'network_artifacts',
    'file_artifacts'
]

XDR_INCIDENT_FIELDS = {
    "status": {"description": "Current status of the incident: \"new\",\"under_"
                              "investigation\",\"resolved_known_issue\","
                              "\"resolved_duplicate\",\"resolved_false_positive\","
                              "\"resolved_true_positive\",\"resolved_security_testing\",\"resolved_other\"",
               "xsoar_field_name": 'xdrstatusv2'},
    "assigned_user_mail": {"description": "Email address of the assigned user.",
                           'xsoar_field_name': "xdrassigneduseremail"},
    "assigned_user_pretty_name": {"description": "Full name of the user assigned to the incident.",
                                  "xsoar_field_name": "xdrassigneduserprettyname"},
    "resolve_comment": {"description": "Comments entered by the user when the incident was resolved.",
                        "xsoar_field_name": "xdrresolvecomment"},
    "manual_severity": {"description": "Incident severity assigned by the user. "
                                       "This does not affect the calculated severity low medium high",
                        "xsoar_field_name": "severity"},
    "close_reason": {"description": "The close reason of the XSOAR incident",
                     "xsoar_field_name": "closeReason"}
}

MIRROR_DIRECTION = {
    'None': None,
    'Incoming': 'In',
    'Outgoing': 'Out',
    'Both': 'Both'
}

XSOAR_TO_XDR = "XSOAR -> XDR"
XDR_TO_XSOAR = "XDR -> XSOAR"

XDR_OPEN_STATUS_TO_XSOAR = ['under_investigation', 'new']


def convert_epoch_to_milli(timestamp):
    if timestamp is None:
        return None
    if 9 < len(str(timestamp)) < 13:
        timestamp = int(timestamp) * 1000
    return int(timestamp)


def convert_datetime_to_epoch(the_time: (int | datetime) = 0):
    if the_time is None:
        return None
    try:
        if isinstance(the_time, datetime):
            return int(the_time.strftime('%s'))
    except Exception as err:
        demisto.debug(err)
        return 0


def convert_datetime_to_epoch_millis(the_time: (int | datetime) = 0):
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


def filter_and_save_unseen_incident(incidents: List, limit: int, number_of_already_filtered_incidents: int) -> List:
    """
    Filters incidents that were seen already and saves the unseen incidents to LastRun object.
    :param incidents: List of incident - must be list
    :param limit: the maximum number of incident per fetch
    :param number_of_already_filtered_incidents: number of incidents that were fetched already
    :return: the filtered incidents.
    """
    last_run_obj = demisto.getLastRun()
    fetched_starred_incidents = last_run_obj.pop('fetched_starred_incidents', {})
    filtered_incidents = []
    for incident in incidents:
        incident_id = incident.get('incident_id')
        if incident_id in fetched_starred_incidents:
            demisto.debug(f'incident (ID {incident_id}) was already fetched in the past.')
            continue
        fetched_starred_incidents[incident_id] = True
        filtered_incidents.append(incident)
        number_of_already_filtered_incidents += 1
        if number_of_already_filtered_incidents >= limit:
            break

    last_run_obj['fetched_starred_incidents'] = fetched_starred_incidents
    demisto.setLastRun(last_run_obj)
    return filtered_incidents


def get_xsoar_close_reasons():
    """
     Get the default XSOAR close-reasons in addition to custom close-reasons from server configuration.
    """
    default_xsoar_close_reasons = list(XSOAR_RESOLVED_STATUS_TO_XDR.keys())
    custom_close_reasons: List[str] = []
    try:
        server_config = get_server_config()
        demisto.debug(f'get_xsoar_close_reasons server-config: {str(server_config)}')
        if server_config:
            custom_close_reasons = argToList(server_config.get('incident.closereasons', ''))
    except Exception as e:
        demisto.error(f"Could not get server configuration: {e}")
    return default_xsoar_close_reasons + custom_close_reasons


def validate_custom_close_reasons_mapping(mapping: str, direction: str):
    """ Check validity of provided custom close-reason mappings. """

    xdr_statuses = [status.replace("resolved_", "").replace("_", " ").title() for status in XDR_RESOLVED_STATUS_TO_XSOAR]
    xsoar_statuses = get_xsoar_close_reasons()

    exception_message = ('Improper custom mapping ({direction}) provided: "{key_or_value}" is not a valid Cortex '
                         '{xsoar_or_xdr} close-reason. Valid Cortex {xsoar_or_xdr} close-reasons are: {statuses}')

    def to_xdr_status(status):
        return "resolved_" + "_".join(status.lower().split(" "))

    custom_mapping = comma_separated_mapping_to_dict(mapping)

    valid_key = valid_value = True  # If no mapping was provided.

    for key, value in custom_mapping.items():
        if direction == XSOAR_TO_XDR:
            xdr_close_reason = to_xdr_status(value)
            valid_key = key in xsoar_statuses
            valid_value = xdr_close_reason in XDR_RESOLVED_STATUS_TO_XSOAR
        elif direction == XDR_TO_XSOAR:
            xdr_close_reason = to_xdr_status(key)
            valid_key = xdr_close_reason in XDR_RESOLVED_STATUS_TO_XSOAR
            valid_value = value in xsoar_statuses

        if not valid_key:
            raise DemistoException(
                exception_message.format(direction=direction,
                                         key_or_value=key,
                                         xsoar_or_xdr="XSOAR" if direction == XSOAR_TO_XDR else "XDR",
                                         statuses=xsoar_statuses
                                         if direction == XSOAR_TO_XDR else xdr_statuses))
        elif not valid_value:
            raise DemistoException(
                exception_message.format(direction=direction,
                                         key_or_value=value,
                                         xsoar_or_xdr="XDR" if direction == XSOAR_TO_XDR else "XSOAR",
                                         statuses=xdr_statuses
                                         if direction == XSOAR_TO_XDR else xsoar_statuses))


def handle_excluded_data_from_alerts_param(excluded_alert_fields: list = []) -> Tuple[list, bool]:
    """handles the excluded_alert_fields parameter

    Args:
        excluded_alert_fields (list, optional): the fields from alerts to exclude. Defaults to [].

    Returns:
        (list, bool): (Which fields of alerts should be excluded from the response,
        and whether null values should be excluded from the response)
    """
    remove_nulls_from_alerts = REMOVE_ALERTS_NULL_VALUES in excluded_alert_fields
    demisto.debug(f"handle_excluded_data_from_alerts_param {remove_nulls_from_alerts=}, {excluded_alert_fields=}")
    formatted_excluded_data = [field for field in excluded_alert_fields if field != REMOVE_ALERTS_NULL_VALUES]
    return formatted_excluded_data, remove_nulls_from_alerts


class Client(CoreClient):
    def __init__(self, base_url, proxy, verify, timeout, params=None):
        if not params:
            params = {}
        self._params = params
        super().__init__(base_url=base_url, proxy=proxy, verify=verify, headers=self.headers, timeout=timeout)

    @property
    def headers(self):
        return get_headers(self._params)

    def test_module(self, first_fetch_time):
        """
            Performs basic get request to get item samples
        """
        last_one_day, _ = parse_date_range(first_fetch_time, TIME_FORMAT)
        try:
            self.get_incidents(lte_creation_time=last_one_day, limit=1)
        except Exception as err:
            if 'API request Unauthorized' in str(err):
                # this error is received from the XDR server when the client clock is not in sync to the server
                raise DemistoException(f'{str(err)} please validate that your both '
                                       f'XSOAR and XDR server clocks are in sync')
            else:
                raise

        # XSOAR -> XDR
        validate_custom_close_reasons_mapping(mapping=self._params.get("custom_xsoar_to_xdr_close_reason_mapping"),
                                              direction=XSOAR_TO_XDR)

        # XDR -> XSOAR
        validate_custom_close_reasons_mapping(mapping=self._params.get("custom_xdr_to_xsoar_close_reason_mapping"),
                                              direction=XDR_TO_XSOAR)

    def handle_fetch_starred_incidents(self, limit: int, page_number: int, request_data: dict) -> List:
        """
        handles pagination and filter of starred incidents that were fetched.
        :param limit: the maximum number of incident per fetch
        :param page_number: page number
        :param request_data: the api call request data
        :return: the filtered starred incidents.
        """
        res = self._http_request(
            method='POST',
            url_suffix='/incidents/get_incidents/',
            json_data={'request_data': request_data},
            headers=self.headers,
            timeout=self.timeout
        )
        raw_incidents = res.get('reply', {}).get('incidents', [])

        # we want to avoid duplications of starred incidents in the fetch-incident command (we fetch all incidents
        # in the fetch window).
        filtered_incidents = filter_and_save_unseen_incident(raw_incidents, limit, 0)

        # we want to support pagination on starred incidents.
        while len(filtered_incidents) < limit:
            page_number += 1
            search_from = page_number * limit
            search_to = search_from + limit
            request_data['search_from'] = search_from
            request_data['search_to'] = search_to

            res = self._http_request(
                method='POST',
                url_suffix='/incidents/get_incidents/',
                json_data={'request_data': request_data},
                headers=self.headers,
                timeout=self.timeout
            )
            raw_incidents = res.get('reply', {}).get('incidents', [])
            if not raw_incidents:
                break
            filtered_incidents += filter_and_save_unseen_incident(raw_incidents, limit, len(filtered_incidents))

        return filtered_incidents

    def update_incident(self, incident_id, status=None, assigned_user_mail=None, assigned_user_pretty_name=None, severity=None,
                        resolve_comment=None, unassign_user=None, add_comment=None):
        update_data: dict[str, Any] = {}

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

        if add_comment:
            update_data['comment'] = {'comment_action': 'add', 'value': add_comment}

        request_data = {
            'incident_id': incident_id,
            'update_data': update_data,
        }

        self._http_request(
            method='POST',
            url_suffix='/incidents/update_incident/',
            json_data={'request_data': request_data},
            headers=self.headers,
            timeout=self.timeout
        )

    def get_incident_extra_data(self, incident_id, alerts_limit=1000,
                                exclude_artifacts: bool = False,
                                excluded_alert_fields: List = [],
                                remove_nulls_from_alerts: bool = False):
        """
        Returns incident by id

        :param incident_id: The id of incident
        :param alerts_limit: Maximum number alerts to get
        :return:
        """
        request_data = {
            'incident_id': incident_id,
            'alerts_limit': alerts_limit,
        }
        if excluded_alert_fields:
            request_data['alert_fields_to_exclude'] = excluded_alert_fields
        if remove_nulls_from_alerts:
            request_data['drop_nulls'] = True

        reply = self._http_request(
            method='POST',
            url_suffix='/incidents/get_incident_extra_data/',
            json_data={'request_data': request_data},
            headers=self.headers,
            timeout=self.timeout
        )

        incident = reply.get('reply')
        # workaround for excluding fields which is not supported with the get_incident_extra_data endpoint
        if exclude_artifacts:
            for field in FIELDS_TO_EXCLUDE:
                incident.pop(field, None)
        return incident

    def save_modified_incidents_to_integration_context(self):
        last_modified_incidents = self.get_incidents(limit=100, sort_by_modification_time='desc')
        modified_incidents_context = {}
        for incident in last_modified_incidents:
            incident_id = incident.get('incident_id')
            modified_incidents_context[incident_id] = incident.get('modification_time')

        set_integration_context({'modified_incidents': modified_incidents_context})

    def get_contributing_event_by_alert_id(self, alert_id: int) -> dict:
        request_data = {
            "request_data": {
                "alert_id": alert_id,
            }
        }

        reply = self._http_request(
            method='POST',
            url_suffix='/alerts/get_correlation_alert_data/',
            json_data=request_data,
            headers=self.headers,
            timeout=self.timeout,
        )

        return reply.get('reply', {})

    def replace_featured_field(self, field_type: str, fields: list[dict]) -> dict:
        request_data = {
            'request_data': {
                'fields': fields
            }
        }

        reply = self._http_request(
            method='POST',
            url_suffix=f'/featured_fields/replace_{field_type}',
            json_data=request_data,
            timeout=self.timeout,
            headers=self.headers,
            raise_on_status=True
        )

        return reply.get('reply')

    def get_tenant_info(self):
        reply = self._http_request(
            method='POST',
            url_suffix='/system/get_tenant_info/',
            json_data={'request_data': {}},
            headers=self.headers,
            timeout=self.timeout
        )
        return reply.get('reply', {})

    def get_multiple_incidents_extra_data(self, exclude_artifacts, incident_id_list=[],
                                          gte_creation_time_milliseconds=0, statuses=[],
                                          starred=None, starred_incidents_fetch_window=None,
                                          page_number=0, limit=100, excluded_alert_fields=[],
                                          remove_nulls_from_alerts=False):
        """
        Returns incident by id
        :param incident_id_list: The list ids of incidents
        :return:
        Maximum number alerts to get in Maximum number alerts to get in "get_multiple_incidents_extra_data" is 50, not sorted
        """
        global ALERTS_LIMIT_PER_INCIDENTS
        request_data = {
            'search_to': limit,
            'sort': {
                'field': 'creation_time',
                'keyword': 'asc',
            }
        }
        filters: list[dict] = []
        if incident_id_list:
            incident_id_list = argToList(incident_id_list, transform=str)
            filters.append({"field": "incident_id_list", "operator": "in", "value": incident_id_list})
        if statuses:
            filters.append({
                'field': 'status',
                'operator': 'in',
                'value': statuses
            })
        demisto.debug(f"{excluded_alert_fields=}, {remove_nulls_from_alerts=}, {exclude_artifacts=}")
        if exclude_artifacts:
            request_data['fields_to_exclude'] = FIELDS_TO_EXCLUDE
        if excluded_alert_fields:
            request_data['alert_fields_to_exclude'] = excluded_alert_fields
        if remove_nulls_from_alerts:
            request_data['drop_nulls'] = True

        if starred and starred_incidents_fetch_window:
            filters.append({
                'field': 'starred',
                'operator': 'eq',
                'value': True
            })
            filters.append({
                'field': 'creation_time',
                'operator': 'gte',
                'value': starred_incidents_fetch_window
            })
            if demisto.command() == 'fetch-incidents':
                if len(filters) > 0:
                    request_data['filters'] = filters
                incidents = self.handle_fetch_starred_incidents(limit, page_number, request_data)
                return incidents
        elif gte_creation_time_milliseconds:
            filters.append({
                'field': 'creation_time',
                'operator': 'gte',
                'value': gte_creation_time_milliseconds
            })
        if len(filters) > 0:
            request_data['filters'] = filters

        demisto.debug(f'before fetch: {request_data=}')
        res = self._http_request(
            method='POST',
            url_suffix='/incidents/get_multiple_incidents_extra_data/',
            json_data={'request_data': request_data},
            headers=self.headers,
            timeout=self.timeout,
        )
        reply = res.get('reply', {})

        if ALERTS_LIMIT_PER_INCIDENTS < 0:
            ALERTS_LIMIT_PER_INCIDENTS = arg_to_number(reply.get('alerts_limit_per_incident')) or 50
            demisto.debug(f'Setting alerts limit per incident to {ALERTS_LIMIT_PER_INCIDENTS}')

        # pop the incidents and then log the reply data so as not to overload the logs
        incidents = reply.pop('incidents', []) if isinstance(reply, dict) else reply  # type: ignore
        demisto.debug(f'reply data: {reply}')
        demisto.debug(f'Incidents fetched: {[i.get("incident", i).get("incident_id") for i in incidents]}')
        return incidents

    def update_alerts_in_xdr_request(self, alerts_ids, severity, status, comment) -> List[Any]:
        request_data = {"request_data": {
            "alert_id_list": alerts_ids,
        }}
        update_data = assign_params(severity=severity, status=status, comment=comment)
        request_data['request_data']['update_data'] = update_data
        response = self._http_request(
            method='POST',
            url_suffix='/alerts/update_alerts',
            json_data=request_data,
            headers=self.headers,
            timeout=self.timeout,
        )
        if "reply" not in response or "alerts_ids" not in response["reply"]:
            raise DemistoException(f"Parse Error. Response not in format, can't find reply key. The response {response}.")
        return response['reply']['alerts_ids']


def get_headers(params: dict) -> dict:
    api_key = params.get('apikey_creds', {}).get('password', '') or params.get('apikey', '')
    api_key_id = params.get('apikey_id_creds', {}).get('password', '') or params.get('apikey_id')
    nonce: str = "".join([secrets.choice(string.ascii_letters + string.digits) for _ in range(64)])
    timestamp: str = str(int(datetime.now(timezone.utc).timestamp()) * 1000)
    auth_key = f"{api_key}{nonce}{timestamp}"
    auth_key = auth_key.encode("utf-8")
    api_key_hash: str = hashlib.sha256(auth_key).hexdigest()

    if argToBoolean(params.get("prevent_only", False)):
        api_key_hash = api_key

    headers: dict = {
        "x-xdr-timestamp": timestamp,
        "x-xdr-nonce": nonce,
        "x-xdr-auth-id": str(api_key_id),
        "Authorization": api_key_hash,
    }

    return headers


def get_tenant_info_command(client: Client):
    tenant_info = client.get_tenant_info()
    readable_output = tableToMarkdown(
        'Tenant Information', tenant_info, headerTransform=pascalToSpace, removeNull=True, is_auto_json_transform=True
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_CONTEXT_BRAND}.TenantInformation',
        outputs=tenant_info,
        raw_response=tenant_info
    )


def update_incident_command(client, args):
    incident_id = args.get('incident_id')
    assigned_user_mail = args.get('assigned_user_mail')
    assigned_user_pretty_name = args.get('assigned_user_pretty_name')
    status = args.get('status')
    demisto.debug(f"this_is_the_status {status}")
    severity = args.get('manual_severity')
    unassign_user = args.get('unassign_user') == 'true'
    resolve_comment = args.get('resolve_comment')
    add_comment = args.get('add_comment')
    resolve_alerts = argToBoolean(args.get('resolve_alerts', False))

    if assigned_user_pretty_name and not assigned_user_mail:
        raise DemistoException('To set a new assigned_user_pretty_name, '
                               'you must also provide a value for the "assigned_user_mail" argument.')

    client.update_incident(
        incident_id=incident_id,
        assigned_user_mail=assigned_user_mail,
        assigned_user_pretty_name=assigned_user_pretty_name,
        unassign_user=unassign_user,
        status=status,
        severity=severity,
        resolve_comment=resolve_comment,
        add_comment=add_comment,
    )
    is_closed = resolve_comment or (status and argToList(status, '_')[0] == 'RESOLVED')
    if resolve_alerts and is_closed:
        args['status'] = args['status'].lower()
        update_related_alerts(client, args)

    return f'Incident {incident_id} has been updated', None, None


def check_if_incident_was_modified_in_xdr(incident_id, last_mirrored_in_time_timestamp, last_modified_incidents_dict):
    if incident_id in last_modified_incidents_dict:  # search the incident in the dict of modified incidents
        incident_modification_time_in_xdr = int(str(last_modified_incidents_dict[incident_id]))

        demisto.debug(f"XDR incident {incident_id}\n"
                      f"modified time:         {incident_modification_time_in_xdr}\n"
                      f"last mirrored in time: {last_mirrored_in_time_timestamp}")

        if incident_modification_time_in_xdr > last_mirrored_in_time_timestamp:  # need to update this incident
            demisto.info(f"Incident '{incident_id}' was modified. performing extra-data request.")
            return True
        # the incident was not modified
    return False


def get_last_mirrored_in_time(args):
    demisto_incidents = demisto.get_incidents()  # type: ignore

    if demisto_incidents:  # handling 5.5 version
        demisto_incident = demisto_incidents[0]
        last_mirrored_in_time = demisto_incident.get('CustomFields', {}).get('lastmirroredintime')
        if not last_mirrored_in_time:  # this is an old incident, update anyway
            return 0
        last_mirrored_in_timestamp = arg_to_timestamp(last_mirrored_in_time, 'last_mirrored_in_time')

    else:  # handling 6.0 version
        last_mirrored_in_time = arg_to_timestamp(args.get('last_update'), 'last_update')
        last_mirrored_in_timestamp = (last_mirrored_in_time - (120 * 1000))

    return last_mirrored_in_timestamp


def sort_incident_data(raw_incident):
    """
    Sorts and processes the raw incident data into a cleaned incident dict.

    Parameters:
    -  raw_incident (dict): The raw incident data as provided by the API.

    Returns:
    - dict: A dictionary containing the processed incident data with:
            - organized alerts.
            - file artifact
            - network artifacts.
    """
    incident = raw_incident.get('incident', {})
    raw_alerts = raw_incident.get('alerts', {}).get('data', [])
    file_artifacts = raw_incident.get('file_artifacts', {}).get('data', [])
    network_artifacts = raw_incident.get('network_artifacts', {}).get('data', [])
    context_alerts = clear_trailing_whitespace(raw_alerts)
    if context_alerts:
        for alert in context_alerts:
            alert['host_ip_list'] = alert.get('host_ip').split(',') if alert.get('host_ip') else []
    incident.update({
        'alerts': context_alerts,
        'file_artifacts': file_artifacts,
        'network_artifacts': network_artifacts
    })
    return incident


def get_incident_extra_data_command(client, args):
    global ALERTS_LIMIT_PER_INCIDENTS
    incident_id = args.get('incident_id')
    alerts_limit = int(args.get('alerts_limit', 1000))
    exclude_artifacts = argToBoolean(args.get('excluding_artifacts', 'False'))
    alert_fields_to_exclude = args.get('alert_fields_to_exclude', [])
    drop_nulls = args.get('drop_nulls', False)
    demisto.debug(f"{exclude_artifacts=} , {alert_fields_to_exclude=}, {drop_nulls=}")
    return_only_updated_incident = argToBoolean(args.get('return_only_updated_incident', 'False'))
    if return_only_updated_incident:
        last_mirrored_in_time = get_last_mirrored_in_time(args)
        last_modified_incidents_dict = get_integration_context().get('modified_incidents', {})

        if check_if_incident_was_modified_in_xdr(incident_id, last_mirrored_in_time, last_modified_incidents_dict):
            pass  # the incident was modified. continue to perform extra-data request

        else:  # the incident was not modified
            return "The incident was not modified in XDR since the last mirror in.", {}, {}
    raw_incident = client.get_multiple_incidents_extra_data(incident_id_list=[incident_id],
                                                            exclude_artifacts=exclude_artifacts,
                                                            excluded_alert_fields=alert_fields_to_exclude,
                                                            remove_nulls_from_alerts=drop_nulls)
    if not raw_incident:
        raise DemistoException(f'Incident {incident_id} is not found')
    if isinstance(raw_incident, list):
        raw_incident = raw_incident[0]
    if raw_incident.get('incident', {}).get('alert_count') > ALERTS_LIMIT_PER_INCIDENTS:
        demisto.debug(f'for incident:{incident_id} using the old call since "\
            "alert_count:{raw_incident.get("incident", {}).get("alert_count")} >" \
            "limit:{ALERTS_LIMIT_PER_INCIDENTS}')
        raw_incident = client.get_incident_extra_data(
            incident_id, alerts_limit, exclude_artifacts=exclude_artifacts,
            excluded_alert_fields=alert_fields_to_exclude, remove_nulls_from_alerts=drop_nulls)
    readable_output = [tableToMarkdown(f'Incident {incident_id}', raw_incident.get('incident'), removeNull=True)]

    incident = sort_incident_data(raw_incident)

    if incident_alerts := incident.get('alerts'):
        readable_output.append(tableToMarkdown('Alerts', incident_alerts,
                                               headers=[key for key in incident_alerts[0]
                                                        if key != 'host_ip'], removeNull=True))
    readable_output.append(tableToMarkdown('Network Artifacts', incident.get('network_artifacts'), removeNull=True))
    readable_output.append(tableToMarkdown('File Artifacts', incident.get('file_artifacts'), removeNull=True))

    account_context_output = assign_params(
        Username=incident.get('users', '')
    )
    endpoint_context_output = []

    for alert in incident.get('alerts') or []:
        alert_context = {}
        if hostname := alert.get('host_name'):
            alert_context['Hostname'] = hostname
        if endpoint_id := alert.get('endpoint_id'):
            alert_context['ID'] = endpoint_id
        if alert_context:
            endpoint_context_output.append(alert_context)
    context_output = {f'{INTEGRATION_CONTEXT_BRAND}.Incident(val.incident_id==obj.incident_id)': incident}
    if account_context_output:
        context_output['Account(val.Username==obj.Username)'] = account_context_output
    if endpoint_context_output:
        context_output['Endpoint(val.Hostname==obj.Hostname)'] = endpoint_context_output
    file_context, process_context, domain_context, ip_context = get_indicators_context(incident)
    if file_context:
        context_output[Common.File.CONTEXT_PATH] = file_context
    if domain_context:
        context_output[Common.Domain.CONTEXT_PATH] = domain_context
    if ip_context:
        context_output[Common.IP.CONTEXT_PATH] = ip_context
    if process_context:
        context_output['Process(val.Name && val.Name == obj.Name)'] = process_context

    return (
        '\n'.join(readable_output),
        context_output,
        raw_incident
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

    event_timestamp = int(round(time.time() * 1000)) if args.get("event_timestamp") is None else int(args.get("event_timestamp"))

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
        alerts = json.loads(alerts) if alerts[0] == "[" and alerts[-1] == "]" else [alerts]
    else:
        raise ValueError('Invalid argument "cef_alerts". It should be either list of strings (cef alerts), '
                         'or single string')

    client.insert_cef_alerts(alerts)

    return (
        'Alerts inserted successfully',
        None,
        None
    )


def sort_all_list_incident_fields(incident_data):
    """Sorting all lists fields in an incident - without this, elements may shift which results in false
    identification of changed fields"""
    if incident_data.get('hosts', []):
        incident_data['hosts'] = sorted(incident_data.get('hosts', []))
        incident_data['hosts'] = [host.upper() for host in incident_data.get('hosts', [])]

    if incident_data.get('users', []):
        incident_data['users'] = sorted(incident_data.get('users', []))
        incident_data['users'] = [user.upper() for user in incident_data.get('users', [])]

    if incident_data.get('incident_sources', []):
        incident_data['incident_sources'] = sorted(incident_data.get('incident_sources', []))
    format_sublists = not argToBoolean(demisto.params().get('dont_format_sublists', False))
    if incident_data.get('alerts', []):
        incident_data['alerts'] = sort_by_key(incident_data.get('alerts', []), main_key='alert_id', fallback_key='name')
        if format_sublists:
            reformat_sublist_fields(incident_data['alerts'])

    if incident_data.get('file_artifacts', []):
        incident_data['file_artifacts'] = sort_by_key(incident_data.get('file_artifacts', []), main_key='file_name',
                                                      fallback_key='file_sha256')
        if format_sublists:
            reformat_sublist_fields(incident_data['file_artifacts'])

    if incident_data.get('network_artifacts', []):
        incident_data['network_artifacts'] = sort_by_key(incident_data.get('network_artifacts', []),
                                                         main_key='network_domain', fallback_key='network_remote_ip')
        if format_sublists:
            reformat_sublist_fields(incident_data['network_artifacts'])


def sync_incoming_incident_owners(incident_data):
    if incident_data.get('assigned_user_mail') and demisto.params().get('sync_owners'):
        user_info = demisto.findUser(email=incident_data.get('assigned_user_mail'))
        if user_info:
            demisto.debug(f"Syncing incident owners: XDR incident {incident_data.get('incident_id')}, "
                          f"owner {user_info.get('username')}")
            incident_data['owner'] = user_info.get('username')

        else:
            demisto.debug(f"The user assigned to XDR incident {incident_data.get('incident_id')} "
                          f"is not registered on XSOAR")


def handle_incoming_user_unassignment(incident_data):
    incident_data['assigned_user_mail'] = ''
    incident_data['assigned_user_pretty_name'] = ''
    if demisto.params().get('sync_owners'):
        demisto.debug(f'Unassigning owner from XDR incident {incident_data.get("incident_id")}')
        incident_data['owner'] = ''


def resolve_xsoar_close_reason(xdr_close_reason: str):
    """
    Resolving XSOAR close reason from possible custom XDR->XSOAR close-reason mapping or default mapping.
    :param xdr_close_reason: XDR raw status/close reason e.g. 'resolved_false_positive'.
    :return: XSOAR close reason.
    """
    possible_xsoar_close_reasons = get_xsoar_close_reasons()

    # Check if incoming XDR close-reason has a non-default mapping to XSOAR close-reason.
    if demisto.params().get("custom_xdr_to_xsoar_close_reason_mapping"):
        custom_xdr_to_xsoar_close_reason_mapping = comma_separated_mapping_to_dict(
            demisto.params().get("custom_xdr_to_xsoar_close_reason_mapping")
        )
        # XDR raw status/close-reason is prefixed with 'resolved_' and is given in snake_case format,
        # e.g. 'resolved_false_positive', whilst custom XDR->XSOAR close-reason mapping
        # is using title case format e.g. 'False Positive', therefore we need to adapt it accordingly.
        title_cased_xdr_close_reason = (
            xdr_close_reason.replace("resolved_", "").replace("_", " ").title()
        )
        xsoar_close_reason = custom_xdr_to_xsoar_close_reason_mapping.get(title_cased_xdr_close_reason)
        if xsoar_close_reason in possible_xsoar_close_reasons:
            demisto.debug(
                f"XDR->XSOAR custom close-reason exists, using {xdr_close_reason}={xsoar_close_reason}"
            )
            return xsoar_close_reason

    # Otherwise, we use default mapping.
    xsoar_close_reason = XDR_RESOLVED_STATUS_TO_XSOAR.get(xdr_close_reason)
    demisto.debug(
        f"XDR->XSOAR custom close-reason does not exists, using default mapping {xdr_close_reason}={xsoar_close_reason}"
    )
    return xsoar_close_reason


def close_incident_in_xsoar(incident_data):
    xsoar_close_reason = resolve_xsoar_close_reason(incident_data.get("status"))
    closing_entry: dict = {
        "Type": EntryType.NOTE,
        "Contents": {
            "dbotIncidentClose": True,
            "closeReason": xsoar_close_reason,
            "closeNotes": incident_data.get("resolve_comment", ""),
        },
        "ContentsFormat": EntryFormat.JSON,
    }
    incident_data["closeReason"] = closing_entry["Contents"]["closeReason"]
    incident_data["closeNotes"] = closing_entry["Contents"]["closeNotes"]
    demisto.debug(
        f"close_incident_in_xsoar {incident_data['closeReason']=} "
        f"{incident_data['closeNotes']=}"
    )

    if incident_data.get("status") == "resolved_known_issue":
        close_notes = f'Known Issue.\n{incident_data.get("closeNotes", "")}'
        closing_entry["Contents"]["closeNotes"] = close_notes
        incident_data["closeNotes"] = close_notes
        demisto.debug(
            f"close_incident_in_xsoar {close_notes=}"
        )
    demisto.debug(f"The closing entry, {closing_entry=}")
    return closing_entry


def reopen_incident_in_xsoar():
    opening_entry = {
        'Type': EntryType.NOTE,
        'Contents': {
            'dbotIncidentReopen': True
        },
        'ContentsFormat': EntryFormat.JSON
    }
    demisto.debug(f"The opening entry, {opening_entry=}")
    return opening_entry


def handle_incoming_incident(incident_data) -> dict:
    incident_id = incident_data.get("incident_id")
    incoming_incident_status = incident_data.get("status")
    demisto.debug(f"handle_incoming_incident {incoming_incident_status=}, {incident_id=}, {incident_data=}")
    if incoming_incident_status in XDR_RESOLVED_STATUS_TO_XSOAR:
        demisto.debug(f"handle_incoming_incident Incident is closed: {incident_id}")
        return close_incident_in_xsoar(incident_data)
    elif incoming_incident_status in XDR_OPEN_STATUS_TO_XSOAR:
        demisto.debug(f'handle_incoming_incident Incident is opened (or reopened): {incident_id}')
        return reopen_incident_in_xsoar()
    return {}


def get_mapping_fields_command():
    xdr_incident_type_scheme = SchemeTypeMapping(type_name=XDR_INCIDENT_TYPE_NAME)
    for field in XDR_INCIDENT_FIELDS:
        xdr_incident_type_scheme.add_field(name=field, description=XDR_INCIDENT_FIELDS[field].get('description'))

    mapping_response = GetMappingFieldsResponse()
    mapping_response.add_scheme_type(xdr_incident_type_scheme)

    return mapping_response


def get_modified_remote_data_command(client, args, mirroring_last_update: str = '', xdr_delay: int = 1):
    remote_args = GetModifiedRemoteDataArgs(args)
    last_update: str
    if mirroring_last_update:
        last_update = mirroring_last_update
        demisto.debug(f"using {mirroring_last_update=} for last_update")
    else:
        last_update = remote_args.last_update
        demisto.debug(f"using {remote_args.last_update=} for last_update")

    if not last_update:
        default_last_update = datetime_to_string(datetime.utcnow() - timedelta(minutes=xdr_delay + 1))
        demisto.debug(f'Mirror last update is: {last_update=} will set it to {default_last_update=}')
        last_update = default_last_update

    last_update_utc = dateparser.parse(last_update,
                                       settings={'TIMEZONE': 'UTC', 'RETURN_AS_TIMEZONE_AWARE': False})   # convert to utc format
    if not last_update_utc:
        raise DemistoException(f'Failed to parse {last_update=} got {last_update_utc=}')

    gte_modification_time_milliseconds = last_update_utc
    lte_modification_time_milliseconds = datetime.utcnow() - timedelta(minutes=xdr_delay)
    demisto.debug(
        f'Performing get-modified-remote-data command {last_update=} | {gte_modification_time_milliseconds=} |'
        f'{lte_modification_time_milliseconds=}'
    )
    raw_incidents = client.get_incidents(
        gte_modification_time_milliseconds=gte_modification_time_milliseconds,
        lte_modification_time_milliseconds=lte_modification_time_milliseconds,
        limit=100)
    last_run_mirroring = (lte_modification_time_milliseconds + timedelta(milliseconds=1))
    last_run_mirroring_str = last_run_mirroring.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]

    id_to_modification_time = {raw.get('incident_id'): raw.get('modification_time') for raw in raw_incidents}
    demisto.debug(f"{last_run_mirroring_str=}, modified incidents {id_to_modification_time=}")

    return GetModifiedRemoteDataResponse(list(id_to_modification_time.keys())), last_run_mirroring_str


def get_remote_data_command(client, args, excluded_alert_fields=[], remove_nulls_from_alerts=False):
    demisto.debug(f"{excluded_alert_fields=}, {remove_nulls_from_alerts=}")
    remote_args = GetRemoteDataArgs(args)
    demisto.debug(f'Performing get-remote-data command with incident id: {remote_args.remote_incident_id}')

    incident_data = {}
    try:
        # when Demisto version is 6.1.0 and above, this command will only be automatically executed on incidents
        # returned from get_modified_remote_data_command so we want to perform extra-data request on those incidents.
        return_only_updated_incident = not is_demisto_version_ge('6.1.0')  # True if version is below 6.1 else False
        requested_data = {"incident_id": remote_args.remote_incident_id,
                          "alerts_limit": 1000,
                          "return_only_updated_incident": return_only_updated_incident,
                          "last_update": remote_args.last_update}
        if excluded_alert_fields:
            requested_data['alert_fields_to_exclude'] = excluded_alert_fields
        if remove_nulls_from_alerts:
            requested_data['drop_nulls'] = True
        incident_data = get_incident_extra_data_command(client, requested_data)
        if 'The incident was not modified' not in incident_data[0]:
            demisto.debug(f"Updating XDR incident {remote_args.remote_incident_id}")

            incident_data = incident_data[2].get('incident')
            incident_data['id'] = incident_data.get('incident_id')

            sort_all_list_incident_fields(incident_data)

            # deleting creation time as it keeps updating in the system
            del incident_data['creation_time']

            # handle unasignment
            if incident_data.get('assigned_user_mail') is None:
                handle_incoming_user_unassignment(incident_data)

            else:
                # handle owner sync
                sync_incoming_incident_owners(incident_data)

            # handle closed issue in XDR and handle outgoing error entry
            entries = []
            if argToBoolean(client._params.get('close_xsoar_incident', True)):
                entries = [handle_incoming_incident(incident_data)]

            reformatted_entries = []
            for entry in entries:
                if entry:
                    reformatted_entries.append(entry)

            incident_data['in_mirror_error'] = ''

            return GetRemoteDataResponse(
                mirrored_object=incident_data,
                entries=reformatted_entries
            )

        else:  # no need to update this incident
            incident_data = {
                'id': remote_args.remote_incident_id,
                'in_mirror_error': ""
            }

            return GetRemoteDataResponse(
                mirrored_object=incident_data,
                entries=[]
            )

    except Exception as e:
        demisto.debug(f"Error in XDR incoming mirror for incident {remote_args.remote_incident_id} \n"
                      f"Error message: {str(e)}")

        if "Rate limit exceeded" in str(e):
            return_error("API rate limit")

        if incident_data:
            incident_data['in_mirror_error'] = str(e)
            sort_all_list_incident_fields(incident_data)

            # deleting creation time as it keeps updating in the system
            del incident_data['creation_time']

        else:
            incident_data = {
                'id': remote_args.remote_incident_id,
                'in_mirror_error': str(e)
            }

        return GetRemoteDataResponse(
            mirrored_object=incident_data,
            entries=[]
        )


def update_remote_system_command(client, args):
    parsed_args = UpdateRemoteSystemArgs(args)
    demisto.debug(f"update_remote_system_command command args are:"
                  f"id: {parsed_args.remote_incident_id}, "
                  f"data: {parsed_args.data}, "
                  f"entries: {parsed_args.entries}, "
                  f"incident_changed: {parsed_args.incident_changed}, "
                  f"remote_incident_id: {parsed_args.remote_incident_id}, "
                  f"inc_status: {parsed_args.inc_status}, "
                  f"delta: {parsed_args.delta}")

    try:
        if parsed_args.incident_changed:
            demisto.debug(
                f'For incident ID: {parsed_args.remote_incident_id} got the following'
                f' delta keys {str(list(parsed_args.delta.keys()))} to update.')
            xsoar_to_xdr_delta = get_update_args(parsed_args)
            demisto.debug(f"update_remote_system_command: After returning from get_update_args, {xsoar_to_xdr_delta=}")
            xsoar_to_xdr_delta['incident_id'] = parsed_args.remote_incident_id

            should_close_xdr_incident = argToBoolean(client._params.get("close_xdr_incident", True))
            status = ""
            # If the client does not want to close the incident in XDR, temporarily remove the status from the arguments
            # to update the incident, and add it back later to close the alerts.
            if not should_close_xdr_incident and (xsoar_to_xdr_delta.get('status') in XSOAR_RESOLVED_STATUS_TO_XDR.values()):
                status = xsoar_to_xdr_delta.pop('status')
                resolve_comment = xsoar_to_xdr_delta.pop('resolve_comment', None)
                demisto.debug(f"Popped status {status} and {resolve_comment=} from update_args,"
                              f" incident status won't be updated in XDR.")

            demisto.debug(f"update_remote_system_command: Update incident with the following delta {xsoar_to_xdr_delta}")
            update_incident_command(client, xsoar_to_xdr_delta)  # updating xdr with the delta

            should_close_alerts_in_xdr = argToBoolean(client._params.get("close_alerts_in_xdr", False))

            if should_close_alerts_in_xdr and xsoar_to_xdr_delta.get('status') in XDR_RESOLVED_STATUS_TO_XSOAR:
                if status:
                    xsoar_to_xdr_delta['status'] = status
                    demisto.debug(f'Restored {status=} in order to update the alerts status.')
                update_related_alerts(client, xsoar_to_xdr_delta)
                demisto.debug("update_remote_system_command: closed xdr alerts")
        else:
            demisto.debug(f'Skipping updating remote incident fields [{parsed_args.remote_incident_id}] '
                          f'as it is not new nor changed')
        return parsed_args.remote_incident_id

    except Exception as e:
        demisto.debug(f"Error in outgoing mirror for incident {parsed_args.remote_incident_id} \n"
                      f"Error message: {str(e)}")

        return parsed_args.remote_incident_id


def update_related_alerts(client: Client, args: dict):
    new_status = args.get('status')
    incident_id = args.get('incident_id')
    comment = f"Resolved by XSOAR, due to incident {incident_id} that has been resolved."
    demisto.debug(f"{new_status=}, {comment=}")
    if not new_status:
        raise DemistoException(f"Failed to update alerts related to incident {incident_id},"
                               "no status found")
    incident_extra_data = client.get_incident_extra_data(incident_id=incident_id)
    if 'alerts' in incident_extra_data and 'data' in incident_extra_data['alerts']:
        alerts_array = incident_extra_data['alerts']['data']
        related_alerts_ids_array = [str(alert['alert_id']) for alert in alerts_array if 'alert_id' in alert]
        demisto.debug(f"{related_alerts_ids_array=}")
        args_for_command = {'alert_ids': related_alerts_ids_array, 'status': new_status, 'comment': comment}
        return_results(update_alerts_in_xdr_command(client, args_for_command))


def fetch_incidents(client: Client, first_fetch_time, integration_instance, exclude_artifacts: bool,
                    last_run: dict, max_fetch: int = 10, statuses: list = [],
                    starred: Optional[bool] = None, starred_incidents_fetch_window: str = None,
                    excluded_alert_fields: list = [], remove_nulls_from_alerts: bool = True):
    global ALERTS_LIMIT_PER_INCIDENTS
    # Get the last fetch time, if exists
    last_fetch = last_run.get('time')
    incidents_from_previous_run = last_run.get('incidents_from_previous_run', [])

    next_dedup_incidents = dedup_incidents = last_run.get('dedup_incidents') or []

    demisto.debug(f"{incidents_from_previous_run=}")
    # Handle first time fetch, fetch incidents retroactively
    if last_fetch is None:
        last_fetch, _ = parse_date_range(first_fetch_time, to_timestamp=True)
        demisto.debug(f"last_fetch after parsing date range {last_fetch}")

    if starred:
        starred_incidents_fetch_window, _ = parse_date_range(starred_incidents_fetch_window, to_timestamp=True)
        demisto.debug(
            f"starred_incidents_fetch_window after parsing date range {starred_incidents_fetch_window}")

    if incidents_from_previous_run:
        demisto.debug('Using incidents from last run')
        raw_incidents = incidents_from_previous_run
        ALERTS_LIMIT_PER_INCIDENTS = last_run.get('alerts_limit_per_incident', -1)
        demisto.debug(f'{ALERTS_LIMIT_PER_INCIDENTS=}')
    else:
        demisto.debug('Fetching incidents')
        raw_incidents = client.get_multiple_incidents_extra_data(
            gte_creation_time_milliseconds=last_fetch,
            # adding len of deduped events so that we don't loop on the same incidents infinitely.
            # There might be a case where deduped incident doesn't come back and we are returning more than the limit.
            statuses=statuses, limit=max_fetch + len(dedup_incidents), starred=starred,
            starred_incidents_fetch_window=starred_incidents_fetch_window,
            exclude_artifacts=exclude_artifacts, excluded_alert_fields=excluded_alert_fields,
            remove_nulls_from_alerts=remove_nulls_from_alerts
        )

    # remove duplicate incidents
    raw_incidents = [
        inc for inc in raw_incidents
        if inc.get("incident", inc).get("incident_id") not in dedup_incidents
    ]

    # save the last 100 modified incidents to the integration context - for mirroring purposes
    client.save_modified_incidents_to_integration_context()

    # maintain a list of non created incidents in a case of a rate limit exception
    non_created_incidents: list = raw_incidents.copy()
    try:
        incidents = []
        for raw_incident in raw_incidents:
            incident_data: dict[str, Any] = sort_incident_data(raw_incident) if raw_incident.get('incident') else raw_incident
            incident_id = incident_data.get('incident_id')
            alert_count = arg_to_number(incident_data.get('alert_count')) or 0
            if alert_count > ALERTS_LIMIT_PER_INCIDENTS:
                demisto.debug(f'for incident:{incident_id} using the old call since alert_count:{alert_count} >" \
                              "limit:{ALERTS_LIMIT_PER_INCIDENTS}')
                raw_incident_ = client.get_incident_extra_data(incident_id=incident_id,
                                                               exclude_artifacts=exclude_artifacts,
                                                               excluded_alert_fields=excluded_alert_fields,
                                                               remove_nulls_from_alerts=remove_nulls_from_alerts)
                incident_data = sort_incident_data(raw_incident_)
            sort_all_list_incident_fields(incident_data)
            incident_data |= {
                'mirror_direction': MIRROR_DIRECTION.get(demisto.params().get('mirror_direction', 'None')),
                'mirror_instance': integration_instance,
                'last_mirrored_in': int(datetime.now().timestamp() * 1000),
            }
            description = incident_data.get('description')
            occurred = timestamp_to_datestring(incident_data['creation_time'], TIME_FORMAT + 'Z')
            incident: dict[str, Any] = {
                'name': f'XDR Incident {incident_id} - {description}',
                'occurred': occurred,
                'rawJSON': json.dumps(incident_data),
            }
            if demisto.params().get('sync_owners') and incident_data.get('assigned_user_mail'):
                incident['owner'] = demisto.findUser(email=incident_data['assigned_user_mail']).get('username')
            # Update last run and add incident if the incident is newer than last fetch
            creation_time = incident_data.get('creation_time', 0)
            demisto.debug(f'creation time for {incident_id=} {creation_time=}')
            if creation_time > last_fetch:
                demisto.debug(f'updating last_fetch,  {incident_id=}')
                last_fetch = incident_data['creation_time']
                next_dedup_incidents = [incident_id]
            elif creation_time == last_fetch:
                demisto.debug(f'got incident at same time for dedup, {incident_id=}')
                next_dedup_incidents.append(incident_id)
            else:
                demisto.debug(f"{incident_data['creation_time']=} < last_fetch; {incident_id=}")

            incidents.append(incident)
            non_created_incidents.remove(raw_incident)

    except Exception as e:
        if "Rate limit exceeded" in str(e):
            demisto.info(f"Cortex XDR - rate limit exceeded, number of non created incidents is: "
                         f"{len(non_created_incidents)!r}.\n The incidents will be created in the next fetch")
        else:
            raise

    next_run = {
        'incidents_from_previous_run': non_created_incidents,
        'time': last_fetch,
        'dedup_incidents': next_dedup_incidents
    }

    if non_created_incidents:
        next_run['alerts_limit_per_incident'] = ALERTS_LIMIT_PER_INCIDENTS  # type: ignore[assignment]

    demisto.debug(f'{next_run=}')
    return next_run, incidents


def get_endpoints_by_status_command(client: Client, args: Dict) -> CommandResults:
    status = args.get('status')

    status = argToList(status)
    last_seen_gte = arg_to_timestamp(
        arg=args.get('last_seen_gte'),
        arg_name='last_seen_gte'
    )

    last_seen_lte = arg_to_timestamp(
        arg=args.get('last_seen_lte'),
        arg_name='last_seen_lte'
    )

    endpoints_count, raw_res = client.get_endpoints_by_status(status, last_seen_gte=last_seen_gte,
                                                              last_seen_lte=last_seen_lte)

    ec = {'status': status, 'count': endpoints_count}

    return CommandResults(
        readable_output=f'{status} endpoints count: {endpoints_count}',
        outputs_prefix=f'{INTEGRATION_CONTEXT_BRAND}.EndpointsStatus',
        outputs_key_field='status',
        outputs=ec,
        raw_response=raw_res)


def file_details_results(client: Client, args: Dict, add_to_context: bool) -> None:
    return_entry, file_results = retrieve_file_details_command(client, args, add_to_context)
    demisto.results(return_entry)
    if file_results:
        demisto.results(file_results)


def get_contributing_event_command(client: Client, args: Dict) -> CommandResults:
    if alert_ids := argToList(args.get('alert_ids')):
        alerts = []

        for alert_id in alert_ids:
            if alert := client.get_contributing_event_by_alert_id(int(alert_id)):
                page_number = max(int(args.get('page_number', 1)), 1) - 1  # Min & default zero (First page)
                page_size = max(int(args.get('page_size', 50)), 0)  # Min zero & default 50
                offset = page_number * page_size
                limit = max(int(args.get('limit', 0)), 0) or offset + page_size

                alert_with_events = {
                    'alertID': str(alert_id),
                    'events': alert.get('events', [])[offset:limit],
                }
                alerts.append(alert_with_events)

        readable_output = tableToMarkdown(
            'Contributing events', alerts, headerTransform=pascalToSpace, removeNull=True, is_auto_json_transform=True
        )
        return CommandResults(
            readable_output=readable_output,
            outputs_prefix=f'{INTEGRATION_CONTEXT_BRAND}.ContributingEvent',
            outputs_key_field='alertID',
            outputs=alerts,
            raw_response=alerts
        )

    else:
        return CommandResults(readable_output='The alert_ids argument cannot be empty.')


def replace_featured_field_command(client: Client, args: Dict) -> CommandResults:
    field_type = args.get('field_type', '')
    values = argToList(args.get('values'))
    len_values = len(values)
    comments = argToList(args.get('comments'))[:len_values]
    ad_type = argToList(args.get('ad_type', 'group'))[:len_values]

    if field_type == 'ad_groups':
        fields = [
            {
                'value': field[0], 'comment': field[1], 'type': field[2]
            } for field in zip_longest(values, comments, ad_type, fillvalue='')
        ]
    else:
        fields = [
            {'value': field[0], 'comment': field[1]} for field in zip_longest(values, comments, fillvalue='')
        ]

    client.replace_featured_field(field_type, fields)

    result = {'fieldType': field_type, 'fields': fields}

    readable_output = tableToMarkdown(
        f'Replaced featured: {result.get("fieldType")}', result.get('fields'), headerTransform=pascalToSpace
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_CONTEXT_BRAND}.FeaturedField',
        outputs_key_field='fieldType',
        outputs=result,
        raw_response=result
    )


def update_alerts_in_xdr_command(client: Client, args: Dict) -> CommandResults:
    alerts_list = argToList(args.get('alert_ids'))
    array_of_all_ids = []
    severity = args.get('severity')
    status = args.get('status')
    comment = args.get('comment')
    if not severity and not status and not comment:
        raise DemistoException(
            f"Can not find a field to update for alerts {alerts_list}, please fill in severity/status/comment.")
    # API is limited to 100 alerts per request, doing the request in batches of 100.
    for index in range(0, len(alerts_list), 100):
        alerts_sublist = alerts_list[index:index + 100]
        demisto.debug(f'{alerts_sublist=}, {severity=}, {status=}, {comment=}')
        array_of_sublist_ids = client.update_alerts_in_xdr_request(alerts_sublist, severity, status, comment)
        array_of_all_ids += array_of_sublist_ids
    if not array_of_all_ids:
        raise DemistoException("Could not find alerts to update, please make sure you used valid alert IDs.")
    return CommandResults(readable_output="Alerts with IDs {} have been updated successfully.".format(",".join(array_of_all_ids))
                          )


def main():  # pragma: no cover
    """
    Executes an integration command
    """
    command = demisto.command()
    params = demisto.params()
    LOG(f'Command being called is {command}')
    # using two different credentials object as they both fields need to be encrypted
    first_fetch_time = params.get('fetch_time', '3 days')
    base_url = urljoin(params.get('url'), '/public_api/v1')
    proxy = params.get('proxy')
    verify_cert = not params.get('insecure', False)
    statuses = params.get('status')
    starred = True if params.get('starred') else None
    starred_incidents_fetch_window = params.get('starred_incidents_fetch_window', '3 days')
    exclude_artifacts = argToBoolean(params.get('exclude_fields', True))
    excluded_alert_fields = argToList(params.get('excluded_alert_fields'))
    excluded_alert_fields, remove_nulls_from_alerts = handle_excluded_data_from_alerts_param(excluded_alert_fields)
    xdr_delay = arg_to_number(params.get('xdr_delay')) or 1
    try:
        timeout = int(params.get('timeout', 120))
    except ValueError as e:
        demisto.debug(f'Failed casting timeout parameter to int, falling back to 120 - {e}')
        timeout = 120
    try:
        max_fetch = int(params.get('max_fetch', 10))
    except ValueError as e:
        demisto.debug(f'Failed casting max fetch parameter to int, falling back to 10 - {e}')
        max_fetch = 10

    client = Client(
        base_url=base_url,
        proxy=proxy,
        verify=verify_cert,
        timeout=timeout,
        params=params
    )

    args = demisto.args()
    args["integration_context_brand"] = INTEGRATION_CONTEXT_BRAND
    args["integration_name"] = INTEGRATION_NAME
    try:
        if command == 'test-module':
            client.test_module(first_fetch_time)
            demisto.results('ok')

        elif command == 'fetch-incidents':
            integration_instance = demisto.integrationInstance()
            last_run = demisto.getLastRun().get('next_run', {})
            demisto.debug(f"Before starting a new cycle of fetch incidents\n{last_run=}\n{integration_instance=}")
            next_run, incidents = fetch_incidents(client=client,
                                                  first_fetch_time=first_fetch_time,
                                                  integration_instance=integration_instance,
                                                  exclude_artifacts=exclude_artifacts,
                                                  last_run=last_run,
                                                  max_fetch=max_fetch,
                                                  statuses=statuses,
                                                  starred=starred,
                                                  starred_incidents_fetch_window=starred_incidents_fetch_window,
                                                  excluded_alert_fields=excluded_alert_fields,
                                                  remove_nulls_from_alerts=remove_nulls_from_alerts
                                                  )
            demisto.debug(f"Finished a fetch incidents cycle, {next_run=}."
                          f"Fetched {len(incidents)} incidents.")
            # demisto.debug(f"{incidents=}") # uncomment to debug, otherwise spams the log

            last_run_obj = demisto.getLastRun()
            last_run_obj['next_run'] = next_run
            demisto.debug(f'full next run: {last_run_obj=}')
            demisto.setLastRun(last_run_obj)
            demisto.incidents(incidents)

        elif command == 'xdr-get-incidents':
            return_outputs(*get_incidents_command(client, args))

        elif command == 'xdr-get-incident-extra-data':
            return_outputs(*get_incident_extra_data_command(client, args))

        elif command == 'xdr-update-incident':
            return_outputs(*update_incident_command(client, args))

        elif command == 'xdr-get-endpoints':
            return_results(get_endpoints_command(client, args))

        elif command == 'xdr-endpoint-alias-change':
            return_results(endpoint_alias_change_command(client, **args))

        elif command == 'xdr-insert-parsed-alert':
            return_outputs(*insert_parsed_alert_command(client, args))

        elif command == 'xdr-insert-cef-alerts':
            return_outputs(*insert_cef_alerts_command(client, args))

        elif command == 'xdr-isolate-endpoint':
            return_results(isolate_endpoint_command(client, args))

        elif command == 'xdr-endpoint-isolate':
            polling_args = {
                **args,
                "endpoint_id_list": args.get('endpoint_id')
            }
            return_results(run_polling_command(client=client,
                                               args=polling_args,
                                               cmd="xdr-endpoint-isolate",
                                               command_function=isolate_endpoint_command,
                                               command_decision_field="action_id",
                                               results_function=get_endpoints_command,
                                               polling_field="is_isolated",
                                               polling_value=["AGENT_ISOLATED"],
                                               stop_polling=True))

        elif command == 'xdr-unisolate-endpoint':
            return_results(unisolate_endpoint_command(client, args))

        elif command == 'xdr-endpoint-unisolate':
            polling_args = {
                **args,
                "endpoint_id_list": args.get('endpoint_id')
            }
            return_results(run_polling_command(client=client,
                                               args=polling_args,
                                               cmd="xdr-endpoint-unisolate",
                                               command_function=unisolate_endpoint_command,
                                               command_decision_field="action_id",
                                               results_function=get_endpoints_command,
                                               polling_field="is_isolated",
                                               polling_value=["AGENT_UNISOLATED",
                                                              "CANCELLED",
                                                              "ֿPENDING_ABORT",
                                                              "ABORTED",
                                                              "EXPIRED",
                                                              "COMPLETED_PARTIAL",
                                                              "COMPLETED_SUCCESSFULLY",
                                                              "FAILED",
                                                              "TIMEOUT"],
                                               stop_polling=True))

        elif command == 'xdr-get-distribution-url':
            return_results(get_distribution_url_command(client, args))

        elif command == 'xdr-get-create-distribution-status':
            return_outputs(*get_distribution_status_command(client, args))

        elif command == 'xdr-get-distribution-versions':
            return_outputs(*get_distribution_versions_command(client, args))

        elif command == 'xdr-create-distribution':
            return_outputs(*create_distribution_command(client, args))

        elif command == 'xdr-get-audit-management-logs':
            return_outputs(*get_audit_management_logs_command(client, args))

        elif command == 'xdr-get-audit-agent-reports':
            return_outputs(*get_audit_agent_reports_command(client, args))

        elif command == 'xdr-quarantine-files':
            return_results(quarantine_files_command(client, args))

        elif command == 'xdr-file-quarantine':
            return_results(run_polling_command(client=client,
                                               args=args,
                                               cmd="xdr-file-quarantine",
                                               command_function=quarantine_files_command,
                                               command_decision_field="action_id",
                                               results_function=action_status_get_command,
                                               polling_field="status",
                                               polling_value=["PENDING",
                                                              "IN_PROGRESS",
                                                              "PENDING_ABORT"]))

        elif command == 'core-quarantine-files':
            polling_args = {
                **args,
                "endpoint_id": argToList(args.get("endpoint_id_list"))[0]
            }
            return_results(run_polling_command(client=client,
                                               args=polling_args,
                                               cmd="core-quarantine-files",
                                               command_function=quarantine_files_command,
                                               command_decision_field="action_id",
                                               results_function=action_status_get_command,
                                               polling_field="status",
                                               polling_value=["PENDING",
                                                              "IN_PROGRESS",
                                                              "PENDING_ABORT"]))

        elif command == 'xdr-get-quarantine-status':
            return_results(get_quarantine_status_command(client, args))

        elif command == 'xdr-restore-file':
            return_results(restore_file_command(client, args))

        elif command == 'xdr-file-restore':
            return_results(run_polling_command(client=client,
                                               args=args,
                                               cmd="xdr-file-restore",
                                               command_function=restore_file_command,
                                               command_decision_field="action_id",
                                               results_function=action_status_get_command,
                                               polling_field="status",
                                               polling_value=["PENDING",
                                                              "IN_PROGRESS",
                                                              "PENDING_ABORT"]))

        elif command == 'xdr-endpoint-scan':
            return_results(endpoint_scan_command(client, args))

        elif command == 'xdr-endpoint-scan-execute':
            return_results(run_polling_command(client=client,
                                               args=args,
                                               cmd="xdr-endpoint-scan-execute",
                                               command_function=endpoint_scan_command,
                                               command_decision_field="action_id",
                                               results_function=action_status_get_command,
                                               polling_field="status",
                                               polling_value=["PENDING",
                                                              "IN_PROGRESS",
                                                              "PENDING_ABORT"]))

        elif command == 'xdr-endpoint-scan-abort':
            return_results(endpoint_scan_abort_command(client, args))

        elif command == 'get-mapping-fields':
            return_results(get_mapping_fields_command())

        elif command == 'get-remote-data':
            return_results(get_remote_data_command(client, args,
                                                   excluded_alert_fields,
                                                   remove_nulls_from_alerts))

        elif command == 'update-remote-system':
            return_results(update_remote_system_command(client, args))

        elif command == 'xdr-delete-endpoints':
            return_outputs(*delete_endpoints_command(client, args))

        elif command == 'xdr-get-policy':
            return_outputs(*get_policy_command(client, args))

        elif command == 'xdr-get-endpoint-device-control-violations':
            return_outputs(*get_endpoint_device_control_violations_command(client, args))

        elif command == 'xdr-retrieve-files':
            return_results(retrieve_files_command(client, args))

        elif command == 'xdr-file-retrieve':
            polling = run_polling_command(client=client,
                                          args=args,
                                          cmd="xdr-file-retrieve",
                                          command_function=retrieve_files_command,
                                          command_decision_field="action_id",
                                          results_function=action_status_get_command,
                                          polling_field="status",
                                          polling_value=["PENDING",
                                                         "IN_PROGRESS",
                                                         "PENDING_ABORT"])
            raw = polling.raw_response
            # raw is the response returned by the get-action-status
            if polling.scheduled_command:
                return_results(polling)
                return
            status = raw[0].get('status')  # type: ignore
            if status == 'COMPLETED_SUCCESSFULLY':
                file_details_results(client, args, True)
            else:  # status is not in polling value and operation was not COMPLETED_SUCCESSFULLY
                polling.outputs_prefix = f'{args.get("integration_context_brand", "CoreApiModule")}' \
                                         f'.RetrievedFiles(val.action_id == obj.action_id)'
                return_results(polling)

        elif command == 'xdr-retrieve-file-details':
            file_details_results(client, args, False)

        elif command == 'xdr-get-scripts':
            return_outputs(*get_scripts_command(client, args))

        elif command == 'xdr-get-script-metadata':
            return_outputs(*get_script_metadata_command(client, args))

        elif command == 'xdr-get-script-code':
            return_outputs(*get_script_code_command(client, args))

        elif command == 'xdr-action-status-get':
            return_results(action_status_get_command(client, args))

        elif command == 'get-modified-remote-data':
            last_run_mirroring: Dict[Any, Any] = get_last_mirror_run() or {}
            demisto.debug(f"before get-modified-remote-data, last run={last_run_mirroring}")

            modified_incidents, next_mirroring_time = get_modified_remote_data_command(
                client=client,
                args=demisto.args(),
                mirroring_last_update=last_run_mirroring.get('mirroring_last_update', ''),
                xdr_delay=xdr_delay,
            )
            last_run_mirroring['mirroring_last_update'] = next_mirroring_time
            set_last_mirror_run(last_run_mirroring)
            demisto.debug(f"after get-modified-remote-data, last run={last_run_mirroring}")
            demisto.debug(f"IDs of modified remote incidents {modified_incidents.modified_incident_ids=}")
            return_results(modified_incidents)

        elif command == 'xdr-script-run':  # used with polling = true always
            return_results(script_run_polling_command(args, client))

        elif command == 'xdr-run-script':
            return_results(run_script_command(client, args))

        elif command == 'xdr-run-snippet-code-script':
            return_results(run_snippet_code_script_command(client, args))

        elif command == 'xdr-snippet-code-script-execute':
            return_results(run_polling_command(client=client,
                                               args=args,
                                               cmd="xdr-snippet-code-script-execute",
                                               command_function=run_snippet_code_script_command,
                                               command_decision_field="action_id",
                                               results_function=action_status_get_command,
                                               polling_field="status",
                                               polling_value=["PENDING",
                                                              "IN_PROGRESS",
                                                              "PENDING_ABORT"]))

        elif command == 'xdr-get-script-execution-status':
            return_results(get_script_execution_status_command(client, args))

        elif command == 'xdr-get-script-execution-results':
            return_results(get_script_execution_results_command(client, args))

        elif command == 'xdr-get-script-execution-result-files':
            return_results(get_script_execution_result_files_command(client, args))

        elif command == 'xdr-get-cloud-original-alerts':
            return_results(get_original_alerts_command(client, args))

        elif command == 'xdr-get-alerts':
            return_results(get_alerts_by_filter_command(client, args))

        elif command == 'xdr-run-script-execute-commands':
            return_results(run_script_execute_commands_command(client, args))

        elif command == 'xdr-script-commands-execute':
            return_results(run_polling_command(client=client,
                                               args=args,
                                               cmd="xdr-script-commands-execute",
                                               command_function=run_script_execute_commands_command,
                                               command_decision_field="action_id",
                                               results_function=action_status_get_command,
                                               polling_field="status",
                                               polling_value=["PENDING",
                                                              "IN_PROGRESS",
                                                              "PENDING_ABORT"]))

        elif command == 'xdr-run-script-delete-file':
            return_results(run_script_delete_file_command(client, args))

        elif command == 'xdr-file-delete-script-execute':
            return_results(run_polling_command(client=client,
                                               args=args,
                                               cmd="xdr-file-delete-script-execute",
                                               command_function=run_script_delete_file_command,
                                               command_decision_field="action_id",
                                               results_function=action_status_get_command,
                                               polling_field="status",
                                               polling_value=["PENDING",
                                                              "IN_PROGRESS",
                                                              "PENDING_ABORT"]))

        elif command == 'xdr-run-script-file-exists':
            return_results(run_script_file_exists_command(client, args))

        elif command == 'xdr-file-exist-script-execute':
            return_results(run_polling_command(client=client,
                                               args=args,
                                               cmd="xdr-file-exist-script-execute",
                                               command_function=run_script_file_exists_command,
                                               command_decision_field="action_id",
                                               results_function=action_status_get_command,
                                               polling_field="status",
                                               polling_value=["PENDING",
                                                              "IN_PROGRESS",
                                                              "PENDING_ABORT"]))

        elif command == 'xdr-run-script-kill-process':
            return_results((client, args))

        elif command == 'xdr-kill-process-script-execute':
            return_results(run_polling_command(client=client,
                                               args=args,
                                               cmd="xdr-kill-process-script-execute",
                                               command_function=run_script_kill_process_command,
                                               command_decision_field="action_id",
                                               results_function=action_status_get_command,
                                               polling_field="status",
                                               polling_value=["PENDING",
                                                              "IN_PROGRESS",
                                                              "PENDING_ABORT"]))

        elif command == 'endpoint':
            return_results(endpoint_command(client, args))

        elif command == 'xdr-get-endpoints-by-status':
            return_results(get_endpoints_by_status_command(client, args))

        elif command == 'xdr-blocklist-files':
            return_results(blocklist_files_command(client, args))

        elif command == 'xdr-blacklist-files':
            args['prefix'] = 'blacklist'
            return_results(blocklist_files_command(client, args))

        elif command == 'xdr-allowlist-files':
            return_results(allowlist_files_command(client, args))

        elif command == 'xdr-whitelist-files':
            args['prefix'] = 'whitelist'
            return_results(allowlist_files_command(client, args))

        elif command == 'xdr-remove-blocklist-files':
            return_results(remove_blocklist_files_command(client, args))

        elif command == 'xdr-remove-allowlist-files':
            return_results(remove_allowlist_files_command(client, args))

        elif command == 'xdr-get-contributing-event':
            return_results(get_contributing_event_command(client, args))

        elif command == 'xdr-replace-featured-field':
            return_results(replace_featured_field_command(client, args))

        elif command == 'xdr-endpoint-tag-add':
            return_results(add_tag_to_endpoints_command(client, args))

        elif command == 'xdr-endpoint-tag-remove':
            return_results(remove_tag_from_endpoints_command(client, args))

        elif command == 'xdr-get-tenant-info':
            return_results(get_tenant_info_command(client))

        elif command == 'xdr-list-users':
            return_results(list_users_command(client, args))

        elif command == 'xdr-list-risky-users':
            return_results(list_risky_users_or_host_command(client, "user", args))

        elif command == 'xdr-list-risky-hosts':
            return_results(list_risky_users_or_host_command(client, "host", args))

        elif command == 'xdr-list-user-groups':
            return_results(list_user_groups_command(client, args))

        elif command == 'xdr-list-roles':
            return_results(list_roles_command(client, args))

        elif command in ('xdr-set-user-role', 'xdr-remove-user-role'):
            return_results(change_user_role_command(client, args))

        elif command == 'xdr-update-alert':
            return_results(update_alerts_in_xdr_command(client, args))

    except Exception as err:
        return_error(str(err))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
