import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
3

import hashlib
import secrets
import string
from itertools import zip_longest




from CoreIRApiModule import *

# Disable insecure warnings
urllib3.disable_warnings()

TIME_FORMAT = "%Y-%m-%dT%H:%M:%S"
NONCE_LENGTH = 64
API_KEY_LENGTH = 128

INTEGRATION_CONTEXT_BRAND = 'PaloAltoNetworksXDR'
XDR_INCIDENT_TYPE_NAME = 'Cortex XDR Incident'
INTEGRATION_NAME = 'Cortex XDR - IR'

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
}

XSOAR_RESOLVED_STATUS_TO_XDR = {
    'Other': 'resolved_other',
    'Duplicate': 'resolved_duplicate',
    'False Positive': 'resolved_false_positive',
    'Resolved': 'resolved_true_positive',
}

MIRROR_DIRECTION = {
    'None': None,
    'Incoming': 'In',
    'Outgoing': 'Out',
    'Both': 'Both'
}


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
        demisto.debug(err)
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


class Client(CoreClient):

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
                timeout=self.timeout
            )
            raw_incidents = res.get('reply', {}).get('incidents', [])
            if not raw_incidents:
                break
            filtered_incidents += filter_and_save_unseen_incident(raw_incidents, limit, len(filtered_incidents))

        return filtered_incidents

    def get_incidents(self, incident_id_list=None, lte_modification_time=None, gte_modification_time=None,
                      lte_creation_time=None, gte_creation_time=None, status=None, starred=None,
                      starred_incidents_fetch_window=None, sort_by_modification_time=None, sort_by_creation_time=None,
                      page_number=0, limit=1000, gte_creation_time_milliseconds=0):
        """
        Filters and returns incidents

        :param incident_id_list: List of incident ids - must be list
        :param lte_modification_time: string of time format "2019-12-31T23:59:00"
        :param gte_modification_time: string of time format "2019-12-31T23:59:00"
        :param lte_creation_time: string of time format "2019-12-31T23:59:00"
        :param gte_creation_time: string of time format "2019-12-31T23:59:00"
        :param starred_incidents_fetch_window: string of time format "2019-12-31T23:59:00"
        :param starred: True if the incident is starred, else False
        :param status: string of status
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
            'search_to': search_to,
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

        if status:
            filters.append({
                'field': 'status',
                'operator': 'eq',
                'value': status
            })

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

        else:
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
            json_data={'request_data': request_data},
            timeout=self.timeout
        )
        incidents = res.get('reply', {}).get('incidents', [])

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
            'alerts_limit': alerts_limit,
        }

        reply = self._http_request(
            method='POST',
            url_suffix='/incidents/get_incident_extra_data/',
            json_data={'request_data': request_data},
            timeout=self.timeout
        )

        incident = reply.get('reply')

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
            raise_on_status=True
        )

        return reply.get('reply')

    def get_tenant_info(self):
        reply = self._http_request(
            method='POST',
            url_suffix='/system/get_tenant_info/',
            json_data={'request_data': {}},
            timeout=self.timeout
        )
        return reply.get('reply', {})


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

    statuses = argToList(args.get('status', ''))

    starred = args.get('starred')
    starred_incidents_fetch_window = args.get('starred_incidents_fetch_window', '3 days')
    starred_incidents_fetch_window, _ = parse_date_range(starred_incidents_fetch_window, to_timestamp=True)

    sort_by_modification_time = args.get('sort_by_modification_time')
    sort_by_creation_time = args.get('sort_by_creation_time')

    page = int(args.get('page', 0))
    limit = int(args.get('limit', 100))

    # If no filters were given, return a meaningful error message
    if not incident_id_list and (not lte_modification_time and not gte_modification_time and not since_modification_time
                                 and not lte_creation_time and not gte_creation_time and not since_creation_time
                                 and not statuses and not starred):
        raise ValueError("Specify a query for the incidents.\nFor example:"
                         " !xdr-get-incidents since_creation_time=\"1 year\" sort_by_creation_time=\"desc\" limit=10")

    if statuses:
        raw_incidents = []

        for status in statuses:
            raw_incidents += client.get_incidents(
                incident_id_list=incident_id_list,
                lte_modification_time=lte_modification_time,
                gte_modification_time=gte_modification_time,
                lte_creation_time=lte_creation_time,
                gte_creation_time=gte_creation_time,
                sort_by_creation_time=sort_by_creation_time,
                sort_by_modification_time=sort_by_modification_time,
                page_number=page,
                limit=limit,
                status=status,
                starred=starred,
                starred_incidents_fetch_window=starred_incidents_fetch_window,
            )

        if len(raw_incidents) > limit:
            raw_incidents = raw_incidents[:limit]
    else:
        raw_incidents = client.get_incidents(
            incident_id_list=incident_id_list,
            lte_modification_time=lte_modification_time,
            gte_modification_time=gte_modification_time,
            lte_creation_time=lte_creation_time,
            gte_creation_time=gte_creation_time,
            sort_by_creation_time=sort_by_creation_time,
            sort_by_modification_time=sort_by_modification_time,
            page_number=page,
            limit=limit,
            starred=starred,
            starred_incidents_fetch_window=starred_incidents_fetch_window,
        )

    return (
        tableToMarkdown('Incidents', raw_incidents),
        {
            f'{INTEGRATION_CONTEXT_BRAND}.Incident(val.incident_id==obj.incident_id)': raw_incidents
        },
        raw_incidents
    )


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


def get_incident_extra_data_command(client, args):
    incident_id = args.get('incident_id')
    alerts_limit = int(args.get('alerts_limit', 1000))
    return_only_updated_incident = argToBoolean(args.get('return_only_updated_incident', 'False'))

    if return_only_updated_incident:
        last_mirrored_in_time = get_last_mirrored_in_time(args)
        last_modified_incidents_dict = get_integration_context().get('modified_incidents', {})

        if check_if_incident_was_modified_in_xdr(incident_id, last_mirrored_in_time, last_modified_incidents_dict):
            pass  # the incident was modified. continue to perform extra-data request

        else:  # the incident was not modified
            return "The incident was not modified in XDR since the last mirror in.", {}, {}

    demisto.debug(f"Performing extra-data request on incident: {incident_id}")
    raw_incident = {'incident': {'incident_id': '413', 'is_blocked': False, 'incident_name': None, 'creation_time': 1671731222757, 'modification_time': 1675721186878, 'detection_time': None, 'status': 'resolved_false_positive', 'severity': 'low', 'description': "'Possible external RDP Brute-Force' generated by XDR Analytics detected on host dc1env12apc05 involving user env12\\administrator", 'assigned_user_mail': None, 'assigned_user_pretty_name': None, 'alert_count': 1, 'low_severity_alert_count': 1, 'med_severity_alert_count': 0, 'high_severity_alert_count': 0, 'critical_severity_alert_count': 0, 'user_count': 1, 'host_count': 1, 'notes': None, 'resolve_comment': None, 'resolved_timestamp': 1675721186878, 'manual_severity': None, 'manual_description': None, 'xdr_url': 'https://mytenanet.xdr.us.paloaltonetworks.com/incident-view?caseId=413', 'starred': False, 'hosts': ['dc1env12apc05:f6ba1a18c35d416c8e27a319cc2fea09'], 'users': ['env12\\administrator'], 'incident_sources': ['XDR Analytics'], 'rule_based_score': None, 'predicted_score': None, 'manual_score': None, 'aggregated_score': None, 'wildfire_hits': 0, 'alerts_grouping_status': 'Disabled', 'mitre_tactics_ids_and_names': ['TA0006 - Credential Access'], 'mitre_techniques_ids_and_names': ['T1110.001 - Brute Force: Password Guessing'], 'alert_categories': ['Credential Access'], 'original_tags': ['DS:PANW/XDR Agent'], 'tags': ['DS:PANW/XDR Agent']}, 'alerts': {'total_count': 1, 'data': [{'external_id': '2a6a3f42-9d2d-4226-922f-28e4c2a3147f', 'severity': 'low', 'matching_status': 'MATCHED', 'end_match_attempt_ts': None, 'local_insert_ts': 1671731192490, 'last_modified_ts': None, 'bioc_indicator': None, 'matching_service_rule_id': 'fd879de7-fb74-44f0-b699-805d0b08b1fd', 'attempt_counter': None, 'bioc_category_enum_key': None, 'case_id': 413, 'is_whitelisted': False, 'starred': False, 'deduplicate_tokens': None, 'filter_rule_id': None, 'mitre_technique_id_and_name': 'T1110.001 - Brute Force: Password Guessing', 'mitre_tactic_id_and_name': 'TA0006 - Credential Access', 'agent_version': '7.9.0.18674', 'agent_ip_addresses_v6': None, 'agent_device_domain': None, 'agent_fqdn': None, 'agent_os_type': 'Windows', 'agent_os_sub_type': 'Windows 10 [10.0 (Build 19044)]', 'agent_data_collection_status': None, 'mac': None, 'agent_is_vdi': None, 'agent_install_type': 'STANDARD', 'agent_host_boot_time': 1671032983204, 'event_sub_type': 1, 'module_id': None, 'association_strength': 50, 'dst_association_strength': 0, 'story_id': 'ODczNjk1Mzc1MTMwMzI1NjA1Nw==', 'event_id': 'ODczNjk1Mzc1MTMwMzI1NjA1Nw==', 'event_type': 'Login', 'event_timestamp': 1671730625375, 'actor_process_instance_id': 'AdkP08aY7RwAAAL0AAAAAA==', 'actor_process_image_path': 'C:\\Windows\\System32\\lsass.exe', 'actor_process_image_name': 'lsass.exe', 'actor_process_command_line': 'C:\\WINDOWS\\system32\\lsass.exe', 'actor_process_signature_status': 'Signed', 'actor_process_signature_vendor': 'Microsoft Corporation', 'actor_process_image_sha256': '0777fd312394ae1afeed0ad48ae2d7b5ed6e577117a4f40305eaeb4129233650', 'actor_process_image_md5': '289d6a47b7692510e2fd3b51979a9fed', 'actor_process_causality_id': 'AdkP08aY7RwAAAL0AAAAAA==', 'actor_causality_id': 'AdkP08aY7RwAAAL0AAAAAA==', 'actor_process_os_pid': 756, 'actor_thread_thread_id': 4020, 'causality_actor_process_image_name': 'lsass.exe', 'causality_actor_process_command_line': 'C:\\WINDOWS\\system32\\lsass.exe', 'causality_actor_process_image_path': 'C:\\Windows\\System32\\lsass.exe', 'causality_actor_process_signature_vendor': 'Microsoft Corporation', 'causality_actor_process_signature_status': 'Signed', 'causality_actor_causality_id': 'AdkP08aY7RwAAAL0AAAAAA==', 'causality_actor_process_execution_time': 1671033022857, 'causality_actor_process_image_md5': '289d6a47b7692510e2fd3b51979a9fed', 'causality_actor_process_image_sha256': '0777fd312394ae1afeed0ad48ae2d7b5ed6e577117a4f40305eaeb4129233650', 'action_file_path': None, 'action_file_name': None, 'action_file_md5': None, 'action_file_sha256': None, 'action_file_macro_sha256': None, 'action_registry_data': None, 'action_registry_key_name': None, 'action_registry_value_name': None, 'action_registry_full_key': None, 'action_local_ip': 'None', 'action_local_ip_v6': None, 'action_local_port': 0, 'action_remote_ip': '137.184.208.116', 'action_remote_ip_v6': None, 'action_remote_port': 0, 'action_external_hostname': 'kali', 'action_country': 'UNKNOWN', 'action_process_instance_id': None, 'action_process_causality_id': None, 'action_process_image_name': None, 'action_process_image_sha256': None, 'action_process_image_command_line': None, 'action_process_signature_status': 'N/A', 'action_process_signature_vendor': None, 'os_actor_effective_username': None, 'os_actor_process_instance_id': 'AdkP08aY7RwAAAL0AAAAAA==', 'os_actor_process_image_path': 'C:\\Windows\\System32\\lsass.exe', 'os_actor_process_image_name': 'lsass.exe', 'os_actor_process_command_line': 'C:\\WINDOWS\\system32\\lsass.exe', 'os_actor_process_signature_status': 'Signed', 'os_actor_process_signature_vendor': 'Microsoft Corporation', 'os_actor_process_image_sha256': '0777fd312394ae1afeed0ad48ae2d7b5ed6e577117a4f40305eaeb4129233650', 'os_actor_process_causality_id': 'AdkP08aY7RwAAAL0AAAAAA==', 'os_actor_causality_id': None, 'os_actor_process_os_pid': 756, 'os_actor_thread_thread_id': 4020, 'fw_app_id': '', 'fw_interface_from': '', 'fw_interface_to': '', 'fw_rule': '', 'fw_rule_id': None, 'fw_device_name': '', 'fw_serial_number': '', 'fw_url_domain': None, 'fw_email_subject': None, 'fw_email_sender': None, 'fw_email_recipient': None, 'fw_app_subcategory': None, 'fw_app_category': None, 'fw_app_technology': None, 'fw_vsys': None, 'fw_xff': None, 'fw_misc': None, 'fw_is_phishing': 'N/A', 'dst_agent_id': '', 'dst_causality_actor_process_execution_time': None, 'dns_query_name': None, 'dst_action_external_hostname': None, 'dst_action_country': '-', 'dst_action_external_port': None, 'is_pcap': False, 'contains_featured_host': 'NO', 'contains_featured_user': 'NO', 'contains_featured_ip': 'NO', 'image_name': None, 'container_id': None, 'cluster_name': None, 'referenced_resource': None, 'operation_name': None, 'identity_sub_type': None, 'identity_type': None, 'project': None, 'cloud_provider': None, 'resource_type': None, 'resource_sub_type': None, 'user_agent': None, 'alert_type': 'Unclassified', 'resolution_status': 'STATUS_010_NEW', 'resolution_comment': None, 'dynamic_fields': None, 'tags': 'DS:PANW/XDR Agent', 'events_length': 1, 'alert_id': '150807', 'detection_timestamp': 1671730626096, 'name': 'Possible external RDP Brute-Force', 'category': 'Credential Access', 'endpoint_id': 'f6ba1a18c35d416c8e27a319cc2fea09', 'description': "DC1ENV12APC05 successfully accessed administrator by systematically guessing the user's password 22 times over an hour with 2 successful logons and 20 failed attempts. The user did not log in successfully from 137.184.208.116 during the last 30 days. Over the past 30 days, DC1ENV12APC05 has had an average of 0 failed login attempts with the user administrator from 137.184.208.116 per day", 'host_ip': '172.16.12.40', 'host_name': 'DC1ENV12APC05', 'source': 'XDR Analytics', 'action': 'DETECTED', 'action_pretty': 'Detected', 'user_name': 'administrator', 'original_tags': 'DS:PANW/XDR Agent'}]}, 'network_artifacts': {'total_count': 1, 'data': [{'type': 'DOMAIN', 'alert_count': 1, 'is_manual': False, 'network_domain': 'kali', 'network_remote_ip': None, 'network_remote_port': 0, 'network_country': 'UNKNOWN'}]}, 'file_artifacts': {'total_count': 1, 'data': [{'type': 'HASH', 'alert_count': 1, 'is_manual': False, 'is_malicious': False, 'is_process': True, 'file_name': 'lsass.exe', 'file_sha256': '0777fd312394ae1afeed0ad48ae2d7b5ed6e577117a4f40305eaeb4129233650', 'file_signature_status': 'SIGNATURE_SIGNED', 'file_signature_vendor_name': 'Microsoft Corporation', 'file_wildfire_verdict': 'BENIGN', 'low_confidence': False}]}}
    #client.get_incident_extra_data(incident_id, alerts_limit)

    incident = raw_incident.get('incident')
    incident_id = incident.get('incident_id')
    raw_alerts = raw_incident.get('alerts').get('data')
    context_alerts = clear_trailing_whitespace(raw_alerts)
    for alert in context_alerts:
        alert['host_ip_list'] = alert.get('host_ip').split(',') if alert.get('host_ip') else []
    file_artifacts = raw_incident.get('file_artifacts').get('data')
    network_artifacts = raw_incident.get('network_artifacts').get('data')

    readable_output = [tableToMarkdown('Incident {}'.format(incident_id), incident)]

    if len(context_alerts) > 0:
        readable_output.append(tableToMarkdown('Alerts', context_alerts,
                                               headers=[key for key in context_alerts[0] if key != 'host_ip']))
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
        'alerts': context_alerts,
        'file_artifacts': file_artifacts,
        'network_artifacts': network_artifacts
    })
    account_context_output = assign_params(**{
        'Username': incident.get('users', '')
    })
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

    if incident_data.get('alerts', []):
        incident_data['alerts'] = sort_by_key(incident_data.get('alerts', []), main_key='alert_id', fallback_key='name')
        reformat_sublist_fields(incident_data['alerts'])

    if incident_data.get('file_artifacts', []):
        incident_data['file_artifacts'] = sort_by_key(incident_data.get('file_artifacts', []), main_key='file_name',
                                                      fallback_key='file_sha256')
        reformat_sublist_fields(incident_data['file_artifacts'])

    if incident_data.get('network_artifacts', []):
        incident_data['network_artifacts'] = sort_by_key(incident_data.get('network_artifacts', []),
                                                         main_key='network_domain', fallback_key='network_remote_ip')
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


def handle_incoming_closing_incident(incident_data):
    closing_entry = {}  # type: Dict
    if incident_data.get('status') in XDR_RESOLVED_STATUS_TO_XSOAR:
        demisto.debug(f"Closing XDR issue {incident_data.get('incident_id')}")
        closing_entry = {
            'Type': EntryType.NOTE,
            'Contents': {
                'dbotIncidentClose': True,
                'closeReason': XDR_RESOLVED_STATUS_TO_XSOAR.get(incident_data.get("status")),
                'closeNotes': incident_data.get('resolve_comment', '')
            },
            'ContentsFormat': EntryFormat.JSON
        }
        incident_data['closeReason'] = closing_entry['Contents']['closeReason']
        incident_data['closeNotes'] = closing_entry['Contents']['closeNotes']

        if incident_data.get('status') == 'resolved_known_issue':
            close_notes = f'Known Issue.\n{incident_data.get("closeNotes", "")}'
            closing_entry['Contents']['closeNotes'] = close_notes
            incident_data['closeNotes'] = close_notes

    return closing_entry


def get_mapping_fields_command():
    xdr_incident_type_scheme = SchemeTypeMapping(type_name=XDR_INCIDENT_TYPE_NAME)
    for field in XDR_INCIDENT_FIELDS:
        xdr_incident_type_scheme.add_field(name=field, description=XDR_INCIDENT_FIELDS[field].get('description'))

    mapping_response = GetMappingFieldsResponse()
    mapping_response.add_scheme_type(xdr_incident_type_scheme)

    return mapping_response


def get_modified_remote_data_command(client, args):
    remote_args = GetModifiedRemoteDataArgs(args)
    last_update = remote_args.last_update  # In the first run, this value will be set to 1 minute earlier

    demisto.debug(f'Performing get-modified-remote-data command. Last update is: {last_update}')

    last_update_utc = dateparser.parse(last_update, settings={'TIMEZONE': 'UTC'})  # convert to utc format
    if last_update_utc:
        last_update_without_ms = last_update_utc.isoformat().split('.')[0]

    raw_incidents = client.get_incidents(gte_modification_time=last_update_without_ms, limit=100)

    modified_incident_ids = list()
    for raw_incident in raw_incidents:
        incident_id = raw_incident.get('incident_id')
        modified_incident_ids.append(incident_id)

    return GetModifiedRemoteDataResponse(modified_incident_ids)


def get_remote_data_command(client, args):
    remote_args = GetRemoteDataArgs(args)
    demisto.debug(f'Performing get-remote-data command with incident id: {remote_args.remote_incident_id}')

    incident_data = {}
    try:
        # when Demisto version is 6.1.0 and above, this command will only be automatically executed on incidents
        # returned from get_modified_remote_data_command so we want to perform extra-data request on those incidents.
        return_only_updated_incident = not is_demisto_version_ge('6.1.0')  # True if version is below 6.1 else False

        incident_data = get_incident_extra_data_command(client, {"incident_id": remote_args.remote_incident_id,
                                                                 "alerts_limit": 1000,
                                                                 "return_only_updated_incident": return_only_updated_incident,
                                                                 "last_update": remote_args.last_update})
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
            entries = [handle_incoming_closing_incident(incident_data)]

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

def createIncidentsListCTF3():
    rawJson = {
                    "aggregated_score": 14,
                    "alert_categories": [
                        "Privilege Escalation"
                    ],
                    "alert_count": 1,
                    "alerts": [
                        {
                            "action": "DETECTED",
                            "action_country": "UNKNOWN",
                            "action_external_hostname": None,
                            "action_file_macro_sha256": None,
                            "action_file_md5": None,
                            "action_file_name": None,
                            "action_file_path": None,
                            "action_file_sha256": None,
                            "action_local_ip": None,
                            "action_local_ip_v6": None,
                            "action_local_port": None,
                            "action_pretty": "Detected",
                            "action_process_causality_id": None,
                            "action_process_image_command_line": None,
                            "action_process_image_name": None,
                            "action_process_image_sha256": None,
                            "action_process_instance_id": None,
                            "action_process_signature_status": "N/A",
                            "action_process_signature_vendor": None,
                            "action_registry_data": "C:\\Windows\\regedit.exe",
                            "action_registry_full_key": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe\\Debugger",
                            "action_registry_key_name": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe",
                            "action_registry_value_name": "Debugger",
                            "action_remote_ip": None,
                            "action_remote_ip_v6": None,
                            "action_remote_port": None,
                            "actor_causality_id": "AdklBdr5uVIAABZIAAAAAA==",
                            "actor_process_causality_id": "AdklBdr5uVIAABZIAAAAAA==",
                            "actor_process_command_line": "regedit",
                            "actor_process_image_md5": "999a30979f6195bf562068639ffc4426",
                            "actor_process_image_name": "nothinghere.png",
                            "actor_process_image_path": "C:\\Temp\\nothinghere.png",
                            "actor_process_image_sha256": "92f24fs2927173aaa1f6e064aaa9815b117e8a7c4a0988ac918170",
                            "actor_process_instance_id": "AdklBdxb0K0AABcwAAAAAA==",
                            "actor_process_os_pid": 5936,
                            "actor_process_signature_status": "Signed",
                            "actor_process_signature_vendor": "Microsoft Corporation",
                            "actor_thread_thread_id": 5932,
                            "agent_data_collection_status": None,
                            "agent_device_domain": None,
                            "agent_fqdn": None,
                            "agent_host_boot_time": 1673363273815,
                            "agent_install_type": "STANDARD",
                            "agent_ip_addresses_v6": None,
                            "agent_is_vdi": None,
                            "agent_os_sub_type": "Windows 10 [10.0 (Build 19044)]",
                            "agent_os_type": "Windows",
                            "agent_version": "7.9.0.18674",
                            "alert_id": "171696",
                            "alert_type": "Unclassified",
                            "association_strength": 50,
                            "attempt_counter": None,
                            "bioc_category_enum_key": "PRIVILEGE_ESCALATION",
                            "bioc_indicator": "[{\"pretty_name\":\"Registry\",\"data_type\":None,\"render_type\":\"entity\",\"entity_map\":None,\"dml_ui\":False},{\"pretty_name\":\"registry data\",\"data_type\":\"TEXT\",\"render_type\":\"attribute\",\"entity_map\":\"attributes\",\"dml_type\":None},{\"pretty_name\":\"!=\",\"data_type\":None,\"render_type\":\"operator\",\"entity_map\":\"attributes\"},{\"pretty_name\":\"*:\\\\Users\\\\Public\\\\PSAppDeployToolkit*\",\"data_type\":None,\"render_type\":\"value\",\"entity_map\":\"attributes\"},{\"pretty_name\":\"AND\",\"data_type\":None,\"render_type\":\"connector\",\"entity_map\":None},{\"pretty_name\":\"registry key name\",\"data_type\":\"TEXT\",\"render_type\":\"attribute\",\"entity_map\":\"attributes\",\"dml_type\":None},{\"pretty_name\":\"=\",\"data_type\":None,\"render_type\":\"operator\",\"entity_map\":\"attributes\"},{\"pretty_name\":\"HKEY_LOCAL_MACHINE\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Image File Execution Options*\",\"data_type\":None,\"render_type\":\"value\",\"entity_map\":\"attributes\"},{\"pretty_name\":\"AND\",\"data_type\":None,\"render_type\":\"connector\",\"entity_map\":None},{\"pretty_name\":\"registry value name\",\"data_type\":\"TEXT\",\"render_type\":\"attribute\",\"entity_map\":\"attributes\",\"dml_type\":None},{\"pretty_name\":\"=\",\"data_type\":None,\"render_type\":\"operator\",\"entity_map\":\"attributes\"},{\"pretty_name\":\"Debugger\",\"data_type\":None,\"render_type\":\"value\",\"entity_map\":\"attributes\"},{\"pretty_name\":\"AND\",\"data_type\":None,\"render_type\":\"connector\",\"entity_map\":None},{\"pretty_name\":\"action type\",\"data_type\":\"ENUM\",\"render_type\":\"attribute\",\"entity_map\":\"action\",\"dml_type\":None},{\"pretty_name\":\"=\",\"data_type\":None,\"render_type\":\"operator\",\"entity_map\":\"action\"},{\"pretty_name\":\"set_registry_value\",\"data_type\":None,\"render_type\":\"value\",\"entity_map\":\"action\"},{\"pretty_name\":\"Process\",\"data_type\":None,\"render_type\":\"entity\",\"entity_map\":None,\"dml_ui\":False},{\"pretty_name\":\"initiated by\",\"data_type\":\"TEXT\",\"render_type\":\"attribute\",\"entity_map\":\"xdr_actor\",\"dml_type\":None},{\"pretty_name\":\"=\",\"data_type\":None,\"render_type\":\"operator\",\"entity_map\":\"xdr_actor\"},{\"pretty_name\":\"cmd.exe\",\"data_type\":None,\"render_type\":\"value\",\"entity_map\":\"xdr_actor\"},{\"pretty_name\":\",\",\"data_type\":None,\"render_type\":\"connector\",\"entity_map\":None},{\"pretty_name\":\"powershell.exe\",\"data_type\":None,\"render_type\":\"value\",\"entity_map\":\"xdr_actor\"},{\"pretty_name\":\",\",\"data_type\":None,\"render_type\":\"connector\",\"entity_map\":None},{\"pretty_name\":\"wscript.exe\",\"data_type\":None,\"render_type\":\"value\",\"entity_map\":\"xdr_actor\"},{\"pretty_name\":\",\",\"data_type\":None,\"render_type\":\"connector\",\"entity_map\":None},{\"pretty_name\":\"cscript.exe\",\"data_type\":None,\"render_type\":\"value\",\"entity_map\":\"xdr_actor\"},{\"pretty_name\":\",\",\"data_type\":None,\"render_type\":\"connector\",\"entity_map\":None},{\"pretty_name\":\"mshta.exe\",\"data_type\":None,\"render_type\":\"value\",\"entity_map\":\"xdr_actor\"},{\"pretty_name\":\",\",\"data_type\":None,\"render_type\":\"connector\",\"entity_map\":None},{\"pretty_name\":\"rundll32.exe\",\"data_type\":None,\"render_type\":\"value\",\"entity_map\":\"xdr_actor\"},{\"pretty_name\":\",\",\"data_type\":None,\"render_type\":\"connector\",\"entity_map\":None},{\"pretty_name\":\"cgo name\",\"data_type\":\"TEXT\",\"render_type\":\"attribute\",\"entity_map\":\"xdr_causality_actor\",\"dml_type\":None},{\"pretty_name\":\"=\",\"data_type\":None,\"render_type\":\"operator\",\"entity_map\":\"xdr_causality_actor\"},{\"pretty_name\":\"cmd.exe\",\"data_type\":None,\"render_type\":\"value\",\"entity_map\":\"xdr_causality_actor\"},{\"pretty_name\":\",\",\"data_type\":None,\"render_type\":\"connector\",\"entity_map\":None},{\"pretty_name\":\"powershell.exe\",\"data_type\":None,\"render_type\":\"value\",\"entity_map\":\"xdr_causality_actor\"},{\"pretty_name\":\",\",\"data_type\":None,\"render_type\":\"connector\",\"entity_map\":None},{\"pretty_name\":\"wscript.exe\",\"data_type\":None,\"render_type\":\"value\",\"entity_map\":\"xdr_causality_actor\"},{\"pretty_name\":\",\",\"data_type\":None,\"render_type\":\"connector\",\"entity_map\":None},{\"pretty_name\":\"cscript.exe\",\"data_type\":None,\"render_type\":\"value\",\"entity_map\":\"xdr_causality_actor\"},{\"pretty_name\":\",\",\"data_type\":None,\"render_type\":\"connector\",\"entity_map\":None},{\"pretty_name\":\"mshta.exe\",\"data_type\":None,\"render_type\":\"value\",\"entity_map\":\"xdr_causality_actor\"},{\"pretty_name\":\",\",\"data_type\":None,\"render_type\":\"connector\",\"entity_map\":None},{\"pretty_name\":\"rundll32.exe\",\"data_type\":None,\"render_type\":\"value\",\"entity_map\":\"xdr_causality_actor\"},{\"pretty_name\":\"Host\",\"data_type\":None,\"render_type\":\"entity\",\"entity_map\":None,\"dml_ui\":False},{\"pretty_name\":\"host os\",\"data_type\":\"ENUM\",\"render_type\":\"attribute\",\"entity_map\":\"xdr_agent\",\"dml_type\":None},{\"pretty_name\":\"=\",\"data_type\":None,\"render_type\":\"operator\",\"entity_map\":\"xdr_agent\"},{\"pretty_name\":\"windows\",\"data_type\":None,\"render_type\":\"value\",\"entity_map\":\"xdr_agent\"}]",
                            "case_id": 425,
                            "category": "Privilege Escalation",
                            "causality_actor_causality_id": "AdklBdr5uVIAABZIAAAAAA==",
                            "causality_actor_process_command_line": "\"C:\\Windows\\system32\\cmd.exe\"",
                            "causality_actor_process_execution_time": 1673363506291,
                            "causality_actor_process_image_md5": "8a2122e8162dbef04694b9c3e0b6cdee",
                            "causality_actor_process_image_name": "cmd.exe",
                            "causality_actor_process_image_path": "C:\\Windows\\System32\\cmd.exe",
                            "causality_actor_process_image_sha256": "b99d61d874728edc0918ca0eb10eab93d381e7367e377406e65963366c874450",
                            "causality_actor_process_signature_status": "Signed",
                            "causality_actor_process_signature_vendor": "Microsoft Corporation",
                            "cloud_provider": None,
                            "cluster_name": None,
                            "container_id": None,
                            "contains_featured_host": "NO",
                            "contains_featured_ip": "NO",
                            "contains_featured_user": "NO",
                            "deduplicate_tokens": None,
                            "description": "Registry registry data != *:\\Users\\Public\\PSAppDeployToolkit* AND registry key name = HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options* AND registry value name = Debugger AND action type = set_registry_value Process initiated by = cmd.exe, powershell.exe, wscript.exe, cscript.exe, mshta.exe, rundll32.exe, cgo name = cmd.exe, powershell.exe, wscript.exe, cscript.exe, mshta.exe, rundll32.exe Host host os = windows",
                            "detection_timestamp": 1673363529207,
                            "dns_query_name": None,
                            "dst_action_country": None,
                            "dst_action_external_hostname": None,
                            "dst_action_external_port": None,
                            "dst_agent_id": None,
                            "dst_association_strength": 0,
                            "dst_causality_actor_process_execution_time": None,
                            "dynamic_fields": None,
                            "end_match_attempt_ts": None,
                            "endpoint_id": "e60d43c1cb1348408f0639bc912235dd",
                            "event_id": "AAABhZw9HXAwPI68AAB/bA==",
                            "event_sub_type": 4,
                            "event_timestamp": 1673363529207,
                            "event_type": "Registry Event",
                            "events_length": 1,
                            "external_id": "9fec9a0d-e2ce-4266-ba53-c9004fad2c03",
                            "filter_rule_id": None,
                            "fw_app_category": None,
                            "fw_app_id": None,
                            "fw_app_subcategory": None,
                            "fw_app_technology": None,
                            "fw_device_name": None,
                            "fw_email_recipient": None,
                            "fw_email_sender": None,
                            "fw_email_subject": None,
                            "fw_interface_from": None,
                            "fw_interface_to": None,
                            "fw_is_phishing": "N/A",
                            "fw_misc": None,
                            "fw_rule": None,
                            "fw_rule_id": None,
                            "fw_serial_number": None,
                            "fw_url_domain": None,
                            "fw_vsys": None,
                            "fw_xff": None,
                            "host_ip": "172.16.121.11",
                            "host_ip_list": [
                                "172.16.121.11"
                            ],
                            "host_name": "DC1ENV12APC02",
                            "identity_sub_type": None,
                            "identity_type": None,
                            "image_name": None,
                            "is_pcap": False,
                            "is_whitelisted": False,
                            "last_modified_ts": 1673775538267,
                            "local_insert_ts": 1673363551091,
                            "mac": None,
                            "matching_service_rule_id": None,
                            "matching_status": "MATCHED",
                            "mitre_tactic_id_and_name": "TA0004 - Privilege Escalation",
                            "mitre_technique_id_and_name": "T1546.012 - Event Triggered Execution: Image File Execution Options Injection",
                            "module_id": None,
                            "name": "Image File Execution Options Registry key injection by scripting engine",
                            "operation_name": None,
                            "original_tags": "DS:PANW/XDR Agent",
                            "os_actor_causality_id": None,
                            "os_actor_effective_username": None,
                            "os_actor_process_causality_id": "AdklBdr5uVIAABZIAAAAAA==",
                            "os_actor_process_command_line": "regedit",
                            "os_actor_process_image_name": "regedit.exe",
                            "os_actor_process_image_path": "C:\\Windows\\regedit.exe",
                            "os_actor_process_image_sha256": "92f24fed2ba2927173aad58981f6e0643c6b89815b117e8a7c4a0988ac918170",
                            "os_actor_process_instance_id": "AdklBdxb0K0AABcwAAAAAA==",
                            "os_actor_process_os_pid": 5936,
                            "os_actor_process_signature_status": "Signed",
                            "os_actor_process_signature_vendor": "Microsoft Corporation",
                            "os_actor_thread_thread_id": 5932,
                            "project": None,
                            "referenced_resource": None,
                            "resolution_comment": None,
                            "resolution_status": "STATUS_010_NEW",
                            "resource_sub_type": None,
                            "resource_type": None,
                            "severity": "medium",
                            "source": "XDR BIOC",
                            "starred": False,
                            "story_id": None,
                            "tags": "DS:PANW/XDR Agent",
                            "user_agent": None,
                            "user_name": "DC1ENV12APC02\\Win10-Regression"
                        }
                    ],
                    "alerts_grouping_status": "Disabled",
                    "assigned_user_mail": None,
                    "assigned_user_pretty_name": None,
                    "creation_time": 1673363555141,
                    "critical_severity_alert_count": 0,
                    "description": "<Student-1>'Image File Execution Options Registry key injection by scripting engine' generated by XDR BIOC detected on host dc1env12apc02 involving user dc1env12apc02\\win10-regression",
                    "detection_time": None,
                    "file_artifacts": [
                        {
                            "alert_count": 1,
                            "file_name": "cmd.exe",
                            "file_sha256": "b99d61d874728edc0918ca0eb10eab93d381e7367e377406e65963366c874450",
                            "file_signature_status": "SIGNATURE_SIGNED",
                            "file_signature_vendor_name": "Microsoft Corporation",
                            "file_wildfire_verdict": "BENIGN",
                            "is_malicious": False,
                            "is_manual": False,
                            "is_process": True,
                            "low_confidence": False,
                            "type": "HASH"
                        },
                        {
                            "alert_count": 1,
                            "file_name": "regedit.exe",
                            "file_sha256": "92f24fed2ba2927173aad58981f6e0643c6b89815b117e8a7c4a0988ac918170",
                            "file_signature_status": "SIGNATURE_SIGNED",
                            "file_signature_vendor_name": "Microsoft Corporation",
                            "file_wildfire_verdict": "BENIGN",
                            "is_malicious": False,
                            "is_manual": False,
                            "is_process": True,
                            "low_confidence": False,
                            "type": "HASH"
                        }
                    ],
                    "high_severity_alert_count": 0,
                    "host_count": 1,
                    "hosts": [
                        "dc1env12apc02:e60d43c1cb1348408f0639bc912235dd"
                    ],
                    "incident_id": "425",
                    "incident_name": None,
                    "incident_sources": [
                        "XDR BIOC"
                    ],
                    "is_blocked": False,
                    "low_severity_alert_count": 0,
                    "manual_description": None,
                    "manual_score": None,
                    "manual_severity": None,
                    "med_severity_alert_count": 1,
                    "mitre_tactics_ids_and_names": [
                        "TA0004 - Privilege Escalation"
                    ],
                    "mitre_techniques_ids_and_names": [
                        "T1546.012 - Event Triggered Execution: Image File Execution Options Injection"
                    ],
                    "modification_time": 1673363555141,
                    "network_artifacts": [],
                    "notes": None,
                    "original_tags": [
                        "DS:PANW/XDR Agent"
                    ],
                    "predicted_score": 14,
                    "resolve_comment": None,
                    "resolved_timestamp": None,
                    "rule_based_score": None,
                    "severity": "medium",
                    "starred": False,
                    "status": "new",
                    "tags": [
                        "DS:PANW/XDR Agent"
                    ],
                    "user_count": 1,
                    "users": [
                        "dc1env12apc02\\win10-regression"
                    ],
                    "wildfire_hits": 0,
                    "xdr_url": "https://mytenanet.xdr.us.paloaltonetworks.com/incident-view?caseId=425"
                }
    incidents = [{
                    "alert_categories": [
                        "Credential Access"
                    ],
                    "alert_count": 1,
                    "alerts": [
                        {
                            "description": "DC1ENV12APC05 successfully accessed administrator by systematically guessing the user's password 22 times over an hour with 2 successful logons and 20 failed attempts. The user did not log in successfully from 137.184.208.116 during the last 30 days. Over the past 30 days, DC1ENV12APC05 has had an average of 0 failed login attempts with the user administrator from 137.184.208.116 per day",
                            "action": "DETECTED",
                            "action_country": "UNKNOWN",
                            "action_external_hostname": "kali",
                            "action_file_macro_sha256": None,
                            "action_file_md5": None,
                            "action_file_name": None,
                            "action_file_path": None,
                            "action_file_sha256": None,
                            "action_local_ip": None,
                            "action_local_ip_v6": None,
                            "action_local_port": 0,
                            "action_pretty": "Detected",
                            "action_process_causality_id": None,
                            "action_process_image_command_line": None,
                            "action_process_image_name": None,
                            "action_process_image_sha256": None,
                            "action_process_instance_id": None,
                            "action_process_signature_status": "N/A",
                            "action_process_signature_vendor": None,
                            "action_registry_data": None,
                            "action_registry_full_key": None,
                            "action_registry_key_name": None,
                            "action_registry_value_name": None,
                            "action_remote_ip": "137.184.208.116",
                            "action_remote_ip_v6": None,
                            "action_remote_port": "3889",
                            "actor_causality_id": "AdkP08aY7RwAAAL0AAAAAA==",
                            "actor_process_causality_id": "AdkP08aY7RwAAAL0AAAAAA==",
                            "actor_process_command_line": "C:\\WINDOWS\\system32\\lsass.exe",
                            "actor_process_image_md5": "289d6a47b7692510e2fd3b51979a9fed",
                            "actor_process_image_name": "lsass.exe",
                            "actor_process_image_path": "C:\\Windows\\System32\\lsass.exe",
                            "actor_process_image_sha256": "0777fd312394ae1afeed0ad48ae2d7b5ed6e577117a4f40305eaeb4129233650",
                            "actor_process_instance_id": "AdkP08aY7RwAAAL0AAAAAA==",
                            "actor_process_os_pid": 756,
                            "actor_process_signature_status": "Signed",
                            "actor_process_signature_vendor": "Microsoft Corporation",
                            "actor_thread_thread_id": 4020,
                            "agent_data_collection_status": None,
                            "agent_device_domain": None,
                            "agent_fqdn": None,
                            "agent_host_boot_time": 1671032983204,
                            "agent_install_type": "STANDARD",
                            "agent_ip_addresses_v6": None,
                            "agent_is_vdi": None,
                            "agent_os_sub_type": "Windows 10 [10.0 (Build 19044)]",
                            "agent_os_type": "Windows",
                            "agent_version": "7.9.0.18674",
                            "alert_id": "150807",
                            "alert_type": "Unclassified",
                            "association_strength": 50,
                            "attempt_counter": None,
                            "bioc_category_enum_key": None,
                            "bioc_indicator": None,
                            "case_id": 413,
                            "category": "Credential Access",
                            "causality_actor_causality_id": "AdkP08aY7RwAAAL0AAAAAA==",
                            "causality_actor_process_command_line": "C:\\WINDOWS\\system32\\lsass.exe",
                            "causality_actor_process_execution_time": 1671033022857,
                            "causality_actor_process_image_md5": "289d6a47b7692510e2fd3b51979a9fed",
                            "causality_actor_process_image_name": "lsass.exe",
                            "causality_actor_process_image_path": "C:\\Windows\\System32\\lsass.exe",
                            "causality_actor_process_image_sha256": "0777fd312394ae1afeed0ad48ae2d7b5ed6e577117a4f40305eaeb4129233650",
                            "causality_actor_process_signature_status": "Signed",
                            "causality_actor_process_signature_vendor": "Microsoft Corporation",
                            "cloud_provider": None,
                            "cluster_name": None,
                            "container_id": None,
                            "contains_featured_host": "NO",
                            "contains_featured_ip": "NO",
                            "contains_featured_user": "NO",
                            "deduplicate_tokens": None,
                            "detection_timestamp": 1671730626096,
                            "dns_query_name": None,
                            "dst_action_country": "-",
                            "dst_action_external_hostname": None,
                            "dst_action_external_port": None,
                            "dst_agent_id": "",
                            "dst_association_strength": 0,
                            "dst_causality_actor_process_execution_time": None,
                            "dynamic_fields": None,
                            "end_match_attempt_ts": None,
                            "endpoint_id": "f6ba1a18c35d416c8e27a319cc2fea09",
                            "event_id": "ODczNjk1Mzc1MTMwMzI1NjA1Nw==",
                            "event_sub_type": 1,
                            "event_timestamp": 1671730625375,
                            "event_type": "Login",
                            "events_length": 1,
                            "external_id": "2a6a3f42-9d2d-4226-922f-28e4c2a3147f",
                            "filter_rule_id": None,
                            "fw_app_category": None,
                            "fw_app_id": "",
                            "fw_app_subcategory": None,
                            "fw_app_technology": None,
                            "fw_device_name": "",
                            "fw_email_recipient": None,
                            "fw_email_sender": None,
                            "fw_email_subject": None,
                            "fw_interface_from": "",
                            "fw_interface_to": "",
                            "fw_is_phishing": "N/A",
                            "fw_misc": None,
                            "fw_rule": "",
                            "fw_rule_id": None,
                            "fw_serial_number": "",
                            "fw_url_domain": None,
                            "fw_vsys": None,
                            "fw_xff": None,
                            "host_ip": "172.16.12.40",
                            "host_ip_list": [
                                "172.16.12.40"
                            ],
                            "host_name": "DC1ENV12APC05",
                            "identity_sub_type": None,
                            "identity_type": None,
                            "image_name": None,
                            "is_pcap": False,
                            "is_whitelisted": False,
                            "last_modified_ts": None,
                            "local_insert_ts": 1671731192490,
                            "mac": None,
                            "matching_service_rule_id": "fd879de7-fb74-44f0-b699-805d0b08b1fd",
                            "matching_status": "MATCHED",
                            "mitre_tactic_id_and_name": "TA0006 - Credential Access",
                            "mitre_technique_id_and_name": "T1110.001 - Brute Force: Password Guessing",
                            "module_id": None,
                            "name": "Possible external RDP Brute-Force",
                            "operation_name": None,
                            "original_tags": "DS:PANW/XDR Agent",
                            "os_actor_causality_id": None,
                            "os_actor_effective_username": None,
                            "os_actor_process_causality_id": "AdkP08aY7RwAAAL0AAAAAA==",
                            "os_actor_process_command_line": "C:\\WINDOWS\\system32\\lsass.exe",
                            "os_actor_process_image_name": "lsass.exe",
                            "os_actor_process_image_path": "C:\\Windows\\System32\\lsass.exe",
                            "os_actor_process_image_sha256": "0777fd312394ae1afeed0ad48ae2d7b5ed6e577117a4f40305eaeb4129233650",
                            "os_actor_process_instance_id": "AdkP08aY7RwAAAL0AAAAAA==",
                            "os_actor_process_os_pid": 756,
                            "os_actor_process_signature_status": "Signed",
                            "os_actor_process_signature_vendor": "Microsoft Corporation",
                            "os_actor_thread_thread_id": 4020,
                            "project": None,
                            "referenced_resource": None,
                            "resolution_comment": None,
                            "resolution_status": "STATUS_010_NEW",
                            "resource_sub_type": None,
                            "resource_type": None,
                            "severity": "low",
                            "source": "XDR Analytics",
                            "starred": False,
                            "story_id": "ODczNjk1Mzc1MTMwMzI1NjA1Nw==",
                            "tags": "DS:PANW/XDR Agent",
                            "user_agent": None,
                            "user_name": "administrator"
                        }
                    ],
                    "alerts_grouping_status": "Disabled",
                    "assigned_user_mail": None,
                    "assigned_user_pretty_name": None,
                    "creation_time": 1671731222757,
                    "critical_severity_alert_count": 0,
                    "description": "'Possible external RDP Brute-Force' generated by XDR Analytics detected on host dc1env12apc05 involving user env12\\administrator",
                    "file_artifacts": [
                        {
                            "alert_count": 1,
                            "file_name": "lsass.exe",
                            "file_sha256": "0777fd312394ae1afeed0ad48ae2d7b5ed6e577117a4f40305eaeb4129233650",
                            "file_signature_status": "SIGNATURE_SIGNED",
                            "file_signature_vendor_name": "Microsoft Corporation",
                            "file_wildfire_verdict": "BENIGN",
                            "is_malicious": False,
                            "is_manual": False,
                            "is_process": True,
                            "low_confidence": False,
                            "type": "HASH"
                        }
                    ],
                    "detection_time": None,
                    "high_severity_alert_count": 0,
                    "host_count": 1,
                    "hosts": [
                        "dc1env12apc05:f6ba1a18c35d416c8e27a319cc2fea09"
                    ],
                    "incident_id": "413",
                    "incident_name": None,
                    "incident_sources": [
                        "XDR Analytics"
                    ],
                    "is_blocked": False,
                    "low_severity_alert_count": 1,
                    "manual_description": None,
                    "manual_score": None,
                    "manual_severity": None,
                    "med_severity_alert_count": 0,
                    "mitre_tactics_ids_and_names": [
                        "TA0006 - Credential Access"
                    ],
                    "mitre_techniques_ids_and_names": [
                        "T1110.001 - Brute Force: Password Guessing"
                    ],
                    "modification_time": 1675069594952,
                    "network_artifacts": [
                        {
                            "alert_count": 1,
                            "is_manual": False,
                            "network_country": "UNKNOWN",
                            "network_domain": "kali",
                            "network_remote_ip": None,
                            "network_remote_port": 0,
                            "type": "DOMAIN"
                        }
                    ],
                    "original_tags": [
                        "DS:PANW/XDR Agent"
                    ],
                    "notes": None,
                    "predicted_score": None,
                    "resolve_comment": None,
                    "resolved_timestamp": None,
                    "rule_based_score": None,
                    "severity": "low",
                    "starred": False,
                    "status": "new",
                    "tags": [
                        "DS:PANW/XDR Agent"
                    ],
                    "user_count": 1,
                    "users": [
                        "env12\\administrator"
                    ],
                    "wildfire_hits": 0,
                    "xdr_url": "https://mytenanet.xdr.us.paloaltonetworks.com/incident-view?caseId=413",
                    "aggregated_score": None
                }]

    for i in range(1,201):
        new_data = rawJson
        new_data["description"] = f"<Student-{i}>'Image File Execution Options Registry key injection by scripting engine' generated by XDR BIOC detected on host dc1env12apc02 involving user dc1env12apc02\\win10-regression"
        incidents.append(dict(new_data))

    return incidents



def fetch_incidents(client, first_fetch_time, integration_instance, last_run: dict = None, max_fetch: int = 10,
                    statuses: List = [], starred: Optional[bool] = None, starred_incidents_fetch_window: str = None):
    # Get the last fetch time, if exists
    last_fetch = last_run.get('time') if isinstance(last_run, dict) else None
    incidents_from_previous_run = last_run.get('incidents_from_previous_run', []) if isinstance(last_run,
                                                                                                dict) else []

    # Handle first time fetch, fetch incidents retroactively
    if last_fetch is None:
        last_fetch, _ = parse_date_range(first_fetch_time, to_timestamp=True)

    if starred:
        starred_incidents_fetch_window, _ = parse_date_range(starred_incidents_fetch_window, to_timestamp=True)

    incidents = []
    if incidents_from_previous_run:
        raw_incidents = incidents_from_previous_run
    else:
        if statuses:
            raw_incidents = []
            #for status in statuses:
                #raw_incidents += client.get_incidents(gte_creation_time_milliseconds=last_fetch, status=status,
                 #                                     limit=max_fetch, sort_by_creation_time='asc', starred=starred,
                  #                                    starred_incidents_fetch_window=starred_incidents_fetch_window)
            raw_incidents = sorted(raw_incidents, key=lambda inc: inc['creation_time'])
            raw_incidents = createIncidentsListCTF3()
        else:
            #raw_incidents = client.get_incidents(gte_creation_time_milliseconds=last_fetch, limit=max_fetch,
             #                                    sort_by_creation_time='asc', starred=starred,
             #                                    starred_incidents_fetch_window=starred_incidents_fetch_window)
            raw_incidents = createIncidentsListCTF3()

    # save the last 100 modified incidents to the integration context - for mirroring purposes
    client.save_modified_incidents_to_integration_context()

    # maintain a list of non created incidents in a case of a rate limit exception
    non_created_incidents: list = raw_incidents.copy()
    next_run = dict()
    try:
        # The count of incidents, so as not to pass the limit
        count_incidents = 0

        for raw_incident in raw_incidents:
            incident_id = raw_incident.get('incident_id')

            # incident_data = get_incident_extra_data_command(client, {"incident_id": incident_id,
            #                                                          "alerts_limit": 1000})[2].get('incident')
            incident_data = raw_incident
            sort_all_list_incident_fields(incident_data)

            incident_data['mirror_direction'] = MIRROR_DIRECTION.get(demisto.params().get('mirror_direction', 'None'),
                                                                     None)
            incident_data['mirror_instance'] = integration_instance
            incident_data['last_mirrored_in'] = int(datetime.now().timestamp() * 1000)

            description = raw_incident.get('description')
            occurred = timestamp_to_datestring(raw_incident['creation_time'], TIME_FORMAT + 'Z')
            incident = {
                'name': f'XDR Incident {incident_id} - {description}',
                'occurred': occurred,
                'rawJSON': json.dumps(incident_data),
            }

            if demisto.params().get('sync_owners') and incident_data.get('assigned_user_mail'):
                incident['owner'] = demisto.findUser(email=incident_data.get('assigned_user_mail')).get('username')

            # Update last run and add incident if the incident is newer than last fetch
            if raw_incident['creation_time'] > last_fetch:
                last_fetch = raw_incident['creation_time']

            incidents.append(incident)
            non_created_incidents.remove(raw_incident)

            count_incidents += 1
            if count_incidents == max_fetch:
                break

    except Exception as e:
        if "Rate limit exceeded" in str(e):
            demisto.info(f"Cortex XDR - rate limit exceeded, number of non created incidents is: "
                         f"'{len(non_created_incidents)}'.\n The incidents will be created in the next fetch")
        else:
            raise

    if non_created_incidents:
        next_run['incidents_from_previous_run'] = non_created_incidents
    else:
        next_run['incidents_from_previous_run'] = []

    next_run['time'] = last_fetch + 1

    return next_run, incidents


def get_endpoints_by_status_command(client: Client, args: Dict) -> CommandResults:
    status = args.get('status')

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
    print(return_entry)
    print(file_results)
    demisto.results(return_entry)
    if file_results:
        demisto.results(file_results)

def xdr_generate_ctf3_command(client: Client, args: Dict):
    raw_incident = {
        "aggregated_score": 14,
        "alert_categories": [
            "Privilege Escalation"
        ],
        "alert_count": 1,
        "alerts": [
            {
                "action": "DETECTED",
                "action_country": "UNKNOWN",
                "action_external_hostname": None,
                "action_file_macro_sha256": None,
                "action_file_md5": None,
                "action_file_name": None,
                "action_file_path": None,
                "action_file_sha256": None,
                "action_local_ip": None,
                "action_local_ip_v6": None,
                "action_local_port": None,
                "action_pretty": "Detected",
                "action_process_causality_id": None,
                "action_process_image_command_line": None,
                "action_process_image_name": None,
                "action_process_image_sha256": None,
                "action_process_instance_id": None,
                "action_process_signature_status": "N/A",
                "action_process_signature_vendor": None,
                "action_registry_data": "C:\\Windows\\regedit.exe",
                "action_registry_full_key": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe\\Debugger",
                "action_registry_key_name": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe",
                "action_registry_value_name": "Debugger",
                "action_remote_ip": None,
                "action_remote_ip_v6": None,
                "action_remote_port": None,
                "actor_causality_id": "AdklBdr5uVIAABZIAAAAAA==",
                "actor_process_causality_id": "AdklBdr5uVIAABZIAAAAAA==",
                "actor_process_command_line": "regedit",
                "actor_process_image_md5": "999a30979f6195bf562068639ffc4426",
                "actor_process_image_name": "nothinghere.png",
                "actor_process_image_path": "C:\\Temp\\nothinghere.png",
                "actor_process_image_sha256": "92f24fs2927173aaa1f6e064aaa9815b117e8a7c4a0988ac918170",
                "actor_process_instance_id": "AdklBdxb0K0AABcwAAAAAA==",
                "actor_process_os_pid": 5936,
                "actor_process_signature_status": "Signed",
                "actor_process_signature_vendor": "Microsoft Corporation",
                "actor_thread_thread_id": 5932,
                "agent_data_collection_status": None,
                "agent_device_domain": None,
                "agent_fqdn": None,
                "agent_host_boot_time": 1673363273815,
                "agent_install_type": "STANDARD",
                "agent_ip_addresses_v6": None,
                "agent_is_vdi": None,
                "agent_os_sub_type": "Windows 10 [10.0 (Build 19044)]",
                "agent_os_type": "Windows",
                "agent_version": "7.9.0.18674",
                "alert_id": "171696",
                "alert_type": "Unclassified",
                "association_strength": 50,
                "attempt_counter": None,
                "bioc_category_enum_key": "PRIVILEGE_ESCALATION",
                "bioc_indicator": "[{\"pretty_name\":\"Registry\",\"data_type\":None,\"render_type\":\"entity\",\"entity_map\":None,\"dml_ui\":False},{\"pretty_name\":\"registry data\",\"data_type\":\"TEXT\",\"render_type\":\"attribute\",\"entity_map\":\"attributes\",\"dml_type\":None},{\"pretty_name\":\"!=\",\"data_type\":None,\"render_type\":\"operator\",\"entity_map\":\"attributes\"},{\"pretty_name\":\"*:\\\\Users\\\\Public\\\\PSAppDeployToolkit*\",\"data_type\":None,\"render_type\":\"value\",\"entity_map\":\"attributes\"},{\"pretty_name\":\"AND\",\"data_type\":None,\"render_type\":\"connector\",\"entity_map\":None},{\"pretty_name\":\"registry key name\",\"data_type\":\"TEXT\",\"render_type\":\"attribute\",\"entity_map\":\"attributes\",\"dml_type\":None},{\"pretty_name\":\"=\",\"data_type\":None,\"render_type\":\"operator\",\"entity_map\":\"attributes\"},{\"pretty_name\":\"HKEY_LOCAL_MACHINE\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Image File Execution Options*\",\"data_type\":None,\"render_type\":\"value\",\"entity_map\":\"attributes\"},{\"pretty_name\":\"AND\",\"data_type\":None,\"render_type\":\"connector\",\"entity_map\":None},{\"pretty_name\":\"registry value name\",\"data_type\":\"TEXT\",\"render_type\":\"attribute\",\"entity_map\":\"attributes\",\"dml_type\":None},{\"pretty_name\":\"=\",\"data_type\":None,\"render_type\":\"operator\",\"entity_map\":\"attributes\"},{\"pretty_name\":\"Debugger\",\"data_type\":None,\"render_type\":\"value\",\"entity_map\":\"attributes\"},{\"pretty_name\":\"AND\",\"data_type\":None,\"render_type\":\"connector\",\"entity_map\":None},{\"pretty_name\":\"action type\",\"data_type\":\"ENUM\",\"render_type\":\"attribute\",\"entity_map\":\"action\",\"dml_type\":None},{\"pretty_name\":\"=\",\"data_type\":None,\"render_type\":\"operator\",\"entity_map\":\"action\"},{\"pretty_name\":\"set_registry_value\",\"data_type\":None,\"render_type\":\"value\",\"entity_map\":\"action\"},{\"pretty_name\":\"Process\",\"data_type\":None,\"render_type\":\"entity\",\"entity_map\":None,\"dml_ui\":False},{\"pretty_name\":\"initiated by\",\"data_type\":\"TEXT\",\"render_type\":\"attribute\",\"entity_map\":\"xdr_actor\",\"dml_type\":None},{\"pretty_name\":\"=\",\"data_type\":None,\"render_type\":\"operator\",\"entity_map\":\"xdr_actor\"},{\"pretty_name\":\"cmd.exe\",\"data_type\":None,\"render_type\":\"value\",\"entity_map\":\"xdr_actor\"},{\"pretty_name\":\",\",\"data_type\":None,\"render_type\":\"connector\",\"entity_map\":None},{\"pretty_name\":\"powershell.exe\",\"data_type\":None,\"render_type\":\"value\",\"entity_map\":\"xdr_actor\"},{\"pretty_name\":\",\",\"data_type\":None,\"render_type\":\"connector\",\"entity_map\":None},{\"pretty_name\":\"wscript.exe\",\"data_type\":None,\"render_type\":\"value\",\"entity_map\":\"xdr_actor\"},{\"pretty_name\":\",\",\"data_type\":None,\"render_type\":\"connector\",\"entity_map\":None},{\"pretty_name\":\"cscript.exe\",\"data_type\":None,\"render_type\":\"value\",\"entity_map\":\"xdr_actor\"},{\"pretty_name\":\",\",\"data_type\":None,\"render_type\":\"connector\",\"entity_map\":None},{\"pretty_name\":\"mshta.exe\",\"data_type\":None,\"render_type\":\"value\",\"entity_map\":\"xdr_actor\"},{\"pretty_name\":\",\",\"data_type\":None,\"render_type\":\"connector\",\"entity_map\":None},{\"pretty_name\":\"rundll32.exe\",\"data_type\":None,\"render_type\":\"value\",\"entity_map\":\"xdr_actor\"},{\"pretty_name\":\",\",\"data_type\":None,\"render_type\":\"connector\",\"entity_map\":None},{\"pretty_name\":\"cgo name\",\"data_type\":\"TEXT\",\"render_type\":\"attribute\",\"entity_map\":\"xdr_causality_actor\",\"dml_type\":None},{\"pretty_name\":\"=\",\"data_type\":None,\"render_type\":\"operator\",\"entity_map\":\"xdr_causality_actor\"},{\"pretty_name\":\"cmd.exe\",\"data_type\":None,\"render_type\":\"value\",\"entity_map\":\"xdr_causality_actor\"},{\"pretty_name\":\",\",\"data_type\":None,\"render_type\":\"connector\",\"entity_map\":None},{\"pretty_name\":\"powershell.exe\",\"data_type\":None,\"render_type\":\"value\",\"entity_map\":\"xdr_causality_actor\"},{\"pretty_name\":\",\",\"data_type\":None,\"render_type\":\"connector\",\"entity_map\":None},{\"pretty_name\":\"wscript.exe\",\"data_type\":None,\"render_type\":\"value\",\"entity_map\":\"xdr_causality_actor\"},{\"pretty_name\":\",\",\"data_type\":None,\"render_type\":\"connector\",\"entity_map\":None},{\"pretty_name\":\"cscript.exe\",\"data_type\":None,\"render_type\":\"value\",\"entity_map\":\"xdr_causality_actor\"},{\"pretty_name\":\",\",\"data_type\":None,\"render_type\":\"connector\",\"entity_map\":None},{\"pretty_name\":\"mshta.exe\",\"data_type\":None,\"render_type\":\"value\",\"entity_map\":\"xdr_causality_actor\"},{\"pretty_name\":\",\",\"data_type\":None,\"render_type\":\"connector\",\"entity_map\":None},{\"pretty_name\":\"rundll32.exe\",\"data_type\":None,\"render_type\":\"value\",\"entity_map\":\"xdr_causality_actor\"},{\"pretty_name\":\"Host\",\"data_type\":None,\"render_type\":\"entity\",\"entity_map\":None,\"dml_ui\":False},{\"pretty_name\":\"host os\",\"data_type\":\"ENUM\",\"render_type\":\"attribute\",\"entity_map\":\"xdr_agent\",\"dml_type\":None},{\"pretty_name\":\"=\",\"data_type\":None,\"render_type\":\"operator\",\"entity_map\":\"xdr_agent\"},{\"pretty_name\":\"windows\",\"data_type\":None,\"render_type\":\"value\",\"entity_map\":\"xdr_agent\"}]",
                "case_id": 425,
                "category": "Privilege Escalation",
                "causality_actor_causality_id": "AdklBdr5uVIAABZIAAAAAA==",
                "causality_actor_process_command_line": "\"C:\\Windows\\system32\\cmd.exe\"",
                "causality_actor_process_execution_time": 1673363506291,
                "causality_actor_process_image_md5": "8a2122e8162dbef04694b9c3e0b6cdee",
                "causality_actor_process_image_name": "cmd.exe",
                "causality_actor_process_image_path": "C:\\Windows\\System32\\cmd.exe",
                "causality_actor_process_image_sha256": "b99d61d874728edc0918ca0eb10eab93d381e7367e377406e65963366c874450",
                "causality_actor_process_signature_status": "Signed",
                "causality_actor_process_signature_vendor": "Microsoft Corporation",
                "cloud_provider": None,
                "cluster_name": None,
                "container_id": None,
                "contains_featured_host": "NO",
                "contains_featured_ip": "NO",
                "contains_featured_user": "NO",
                "deduplicate_tokens": None,
                "description": "Registry registry data != *:\\Users\\Public\\PSAppDeployToolkit* AND registry key name = HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options* AND registry value name = Debugger AND action type = set_registry_value Process initiated by = cmd.exe, powershell.exe, wscript.exe, cscript.exe, mshta.exe, rundll32.exe, cgo name = cmd.exe, powershell.exe, wscript.exe, cscript.exe, mshta.exe, rundll32.exe Host host os = windows",
                "detection_timestamp": 1673363529207,
                "dns_query_name": None,
                "dst_action_country": None,
                "dst_action_external_hostname": None,
                "dst_action_external_port": None,
                "dst_agent_id": None,
                "dst_association_strength": 0,
                "dst_causality_actor_process_execution_time": None,
                "dynamic_fields": None,
                "end_match_attempt_ts": None,
                "endpoint_id": "e60d43c1cb1348408f0639bc912235dd",
                "event_id": "AAABhZw9HXAwPI68AAB/bA==",
                "event_sub_type": 4,
                "event_timestamp": 1673363529207,
                "event_type": "Registry Event",
                "events_length": 1,
                "external_id": "9fec9a0d-e2ce-4266-ba53-c9004fad2c03",
                "filter_rule_id": None,
                "fw_app_category": None,
                "fw_app_id": None,
                "fw_app_subcategory": None,
                "fw_app_technology": None,
                "fw_device_name": None,
                "fw_email_recipient": None,
                "fw_email_sender": None,
                "fw_email_subject": None,
                "fw_interface_from": None,
                "fw_interface_to": None,
                "fw_is_phishing": "N/A",
                "fw_misc": None,
                "fw_rule": None,
                "fw_rule_id": None,
                "fw_serial_number": None,
                "fw_url_domain": None,
                "fw_vsys": None,
                "fw_xff": None,
                "host_ip": "172.16.121.11",
                "host_ip_list": [
                    "172.16.121.11"
                ],
                "host_name": "DC1ENV12APC02",
                "identity_sub_type": None,
                "identity_type": None,
                "image_name": None,
                "is_pcap": False,
                "is_whitelisted": False,
                "last_modified_ts": 1673775538267,
                "local_insert_ts": 1673363551091,
                "mac": None,
                "matching_service_rule_id": None,
                "matching_status": "MATCHED",
                "mitre_tactic_id_and_name": "TA0004 - Privilege Escalation",
                "mitre_technique_id_and_name": "T1546.012 - Event Triggered Execution: Image File Execution Options Injection",
                "module_id": None,
                "name": "Image File Execution Options Registry key injection by scripting engine",
                "operation_name": None,
                "original_tags": "DS:PANW/XDR Agent",
                "os_actor_causality_id": None,
                "os_actor_effective_username": None,
                "os_actor_process_causality_id": "AdklBdr5uVIAABZIAAAAAA==",
                "os_actor_process_command_line": "regedit",
                "os_actor_process_image_name": "regedit.exe",
                "os_actor_process_image_path": "C:\\Windows\\regedit.exe",
                "os_actor_process_image_sha256": "92f24fed2ba2927173aad58981f6e0643c6b89815b117e8a7c4a0988ac918170",
                "os_actor_process_instance_id": "AdklBdxb0K0AABcwAAAAAA==",
                "os_actor_process_os_pid": 5936,
                "os_actor_process_signature_status": "Signed",
                "os_actor_process_signature_vendor": "Microsoft Corporation",
                "os_actor_thread_thread_id": 5932,
                "project": None,
                "referenced_resource": None,
                "resolution_comment": None,
                "resolution_status": "STATUS_010_NEW",
                "resource_sub_type": None,
                "resource_type": None,
                "severity": "medium",
                "source": "XDR BIOC",
                "starred": False,
                "story_id": None,
                "tags": "DS:PANW/XDR Agent",
                "user_agent": None,
                "user_name": "DC1ENV12APC02\\Win10-Regression"
            }
        ],
        "alerts_grouping_status": "Disabled",
        "assigned_user_mail": None,
        "assigned_user_pretty_name": None,
        "creation_time": 1673363555141,
        "critical_severity_alert_count": 0,
        "description": "'Image File Execution Options Registry key injection by scripting engine' generated by XDR BIOC detected on host dc1env12apc02 involving user dc1env12apc02\\win10-regression",
        "detection_time": None,
        "file_artifacts": [
            {
                "alert_count": 1,
                "file_name": "cmd.exe",
                "file_sha256": "b99d61d874728edc0918ca0eb10eab93d381e7367e377406e65963366c874450",
                "file_signature_status": "SIGNATURE_SIGNED",
                "file_signature_vendor_name": "Microsoft Corporation",
                "file_wildfire_verdict": "BENIGN",
                "is_malicious": False,
                "is_manual": False,
                "is_process": True,
                "low_confidence": False,
                "type": "HASH"
            },
            {
                "alert_count": 1,
                "file_name": "regedit.exe",
                "file_sha256": "92f24fed2ba2927173aad58981f6e0643c6b89815b117e8a7c4a0988ac918170",
                "file_signature_status": "SIGNATURE_SIGNED",
                "file_signature_vendor_name": "Microsoft Corporation",
                "file_wildfire_verdict": "BENIGN",
                "is_malicious": False,
                "is_manual": False,
                "is_process": True,
                "low_confidence": False,
                "type": "HASH"
            }
        ],
        "high_severity_alert_count": 0,
        "host_count": 1,
        "hosts": [
            "dc1env12apc02:e60d43c1cb1348408f0639bc912235dd"
        ],
        "incident_id": "425",
        "incident_name": None,
        "incident_sources": [
            "XDR BIOC"
        ],
        "is_blocked": False,
        "low_severity_alert_count": 0,
        "manual_description": None,
        "manual_score": None,
        "manual_severity": None,
        "med_severity_alert_count": 1,
        "mitre_tactics_ids_and_names": [
            "TA0004 - Privilege Escalation"
        ],
        "mitre_techniques_ids_and_names": [
            "T1546.012 - Event Triggered Execution: Image File Execution Options Injection"
        ],
        "modification_time": 1673363555141,
        "network_artifacts": [],
        "notes": None,
        "original_tags": [
            "DS:PANW/XDR Agent"
        ],
        "predicted_score": 14,
        "resolve_comment": None,
        "resolved_timestamp": None,
        "rule_based_score": None,
        "severity": "medium",
        "starred": False,
        "status": "new",
        "tags": [
            "DS:PANW/XDR Agent"
        ],
        "user_count": 1,
        "users": [
            "dc1env12apc02\\win10-regression"
        ],
        "wildfire_hits": 0,
        "xdr_url": "https://mytenanet.xdr.us.paloaltonetworks.com/incident-view?caseId=425"
    }
    incident_id = raw_incident.get('incident_id')
    incident_data = raw_incident
    sort_all_list_incident_fields(incident_data)
    description = raw_incident.get('description')
    occurred = timestamp_to_datestring(raw_incident['creation_time'], TIME_FORMAT + 'Z')
    incident = [{
        'name': f'Sasha - XDR Incident {incident_id} - {description}',
        'occurred': occurred,
        'rawJSON': json.dumps(incident_data),
    }]

    demisto.results("New Incident Was Created - Go Hunt Them Down!")
    demisto.incidents(incident)
    return incident

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


def main():  # pragma: no cover
    """
    Executes an integration command
    """
    command = demisto.command()
    params = demisto.params()
    LOG(f'Command being called is {command}')

    # using two different credentials object as they both fields need to be encrypted
    api_key = params.get('apikey') or params.get('apikey_creds').get('password', '')
    api_key_id = params.get('apikey_id') or params.get('apikey_id_creds').get('password', '')
    first_fetch_time = params.get('fetch_time', '3 days')
    base_url = urljoin(params.get('url'), '/public_api/v1')
    proxy = params.get('proxy')
    verify_cert = not params.get('insecure', False)
    statuses = params.get('status')
    starred = True if params.get('starred') else None
    starred_incidents_fetch_window = params.get('starred_incidents_fetch_window', '3 days')

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

    nonce = "".join([secrets.choice(string.ascii_letters + string.digits) for _ in range(64)])
    timestamp = str(int(datetime.now(timezone.utc).timestamp()) * 1000)
    auth_key = "%s%s%s" % (api_key, nonce, timestamp)
    auth_key = auth_key.encode("utf-8")
    api_key_hash = hashlib.sha256(auth_key).hexdigest()

    if argToBoolean(params.get("prevent_only", False)):
        api_key_hash = api_key

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
        headers=headers,
        timeout=timeout
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
            next_run, incidents = fetch_incidents(client, first_fetch_time, integration_instance,
                                                  demisto.getLastRun().get('next_run'), max_fetch, statuses, starred,
                                                  starred_incidents_fetch_window)
            last_run_obj = demisto.getLastRun()
            last_run_obj['next_run'] = next_run
            demisto.setLastRun(last_run_obj)
            demisto.incidents(incidents)

        #!!!!!New Command for CTF3!!!!!
        elif command == 'xdr-generate-ctf3':
            incident = xdr_generate_ctf3_command(client, args)
            demisto.createIncidents(incident)
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
            return_outputs(*get_distribution_url_command(client, args))

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
            return_results(get_remote_data_command(client, args))

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
            try:
                if (args.get("endpoint_ids") != "e60d43c1cb1348408f0639bc912235dd" and args.get(
                        "generic_file_path") != "C:\Temp\nothinghere.gpg"):
                    return_error(f'Wrong inputs - you might want to check the layout or the context again :) ')

                client = Client(
                    base_url='https://raw.githubusercontent.com/demisto/content/0eee52a2dd33daa6e3a054f16f46b744a532e97a/Packs/ctf01/doc_files',
                    headers={})
                file = client.get_file_by_url_suffix(url_suffix='win_up_to_image.png')
                res = fileResult(filename=f'omg.png', data=file)
                return_results(res)
                return
            except Exception as exc:  # pylint: disable=W0703
                demisto.error(traceback.format_exc())  # print the traceback
                return_error(f'Failed to execute this script. Error: {str(exc)}')

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
            return_results(get_modified_remote_data_command(client, demisto.args()))

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

    except Exception as err:
        return_error(str(err))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

