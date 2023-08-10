from CoreIRApiModule import *
from itertools import zip_longest
import string
import secrets
import hashlib
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


3


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
    raw_incident = {'incident': {'incident_id': '413', 'is_blocked': False, 'incident_name': None, 'creation_time': 1671731222757, 'modification_time': 1675721186878, 'detection_time': None, 'status': 'resolved_false_positive', 'severity': 'low', 'description': "'Possible external RDP Brute-Force' generated by XDR Analytics detected on host dc1env12apc05 involving user env12\\administrator", 'assigned_user_mail': None, 'assigned_user_pretty_name': None, 'alert_count': 1, 'low_severity_alert_count': 1, 'med_severity_alert_count': 0, 'high_severity_alert_count': 0, 'critical_severity_alert_count': 0, 'user_count': 1, 'host_count': 1, 'notes': None, 'resolve_comment': None, 'resolved_timestamp': 1675721186878, 'manual_severity': None, 'manual_description': None, 'xdr_url': 'https://mytenanet.xdr.us.paloaltonetworks.com/incident-view?caseId=413', 'starred': False, 'hosts': ['dc1env12apc05:f6ba1a18c35d416c8e27a319cc2fea09'], 'users': ['env12\\administrator'], 'incident_sources': ['XDR Analytics'], 'rule_based_score': None, 'predicted_score': None, 'manual_score': None, 'aggregated_score': None, 'wildfire_hits': 0, 'alerts_grouping_status': 'Disabled', 'mitre_tactics_ids_and_names': ['TA0006 - Credential Access'], 'mitre_techniques_ids_and_names': ['T1110.001 - Brute Force: Password Guessing'], 'alert_categories': ['Credential Access'], 'original_tags': ['DS:PANW/XDR Agent'], 'tags': ['DS:PANW/XDR Agent']}, 'alerts': {'total_count': 1, 'data': [{'external_id': '2a6a3f42-9d2d-4226-922f-28e4c2a3147f', 'severity': 'low', 'matching_status': 'MATCHED', 'end_match_attempt_ts': None, 'local_insert_ts': 1671731192490, 'last_modified_ts': None, 'bioc_indicator': None, 'matching_service_rule_id': 'fd879de7-fb74-44f0-b699-805d0b08b1fd', 'attempt_counter': None, 'bioc_category_enum_key': None, 'case_id': 413, 'is_whitelisted': False, 'starred': False, 'deduplicate_tokens': None, 'filter_rule_id': None, 'mitre_technique_id_and_name': 'T1110.001 - Brute Force: Password Guessing', 'mitre_tactic_id_and_name': 'TA0006 - Credential Access', 'agent_version': '7.9.0.18674', 'agent_ip_addresses_v6': None, 'agent_device_domain': None, 'agent_fqdn': None, 'agent_os_type': 'Windows', 'agent_os_sub_type': 'Windows 10 [10.0 (Build 19044)]', 'agent_data_collection_status': None, 'mac': None, 'agent_is_vdi': None, 'agent_install_type': 'STANDARD', 'agent_host_boot_time': 1671032983204, 'event_sub_type': 1, 'module_id': None, 'association_strength': 50, 'dst_association_strength': 0, 'story_id': 'ODczNjk1Mzc1MTMwMzI1NjA1Nw==', 'event_id': 'ODczNjk1Mzc1MTMwMzI1NjA1Nw==', 'event_type': 'Login', 'event_timestamp': 1671730625375, 'actor_process_instance_id': 'AdkP08aY7RwAAAL0AAAAAA==', 'actor_process_image_path': 'C:\\Windows\\System32\\lsass.exe', 'actor_process_image_name': 'lsass.exe', 'actor_process_command_line': 'C:\\WINDOWS\\system32\\lsass.exe', 'actor_process_signature_status': 'Signed', 'actor_process_signature_vendor': 'Microsoft Corporation', 'actor_process_image_sha256': '0777fd312394ae1afeed0ad48ae2d7b5ed6e577117a4f40305eaeb4129233650', 'actor_process_image_md5': '289d6a47b7692510e2fd3b51979a9fed', 'actor_process_causality_id': 'AdkP08aY7RwAAAL0AAAAAA==', 'actor_causality_id': 'AdkP08aY7RwAAAL0AAAAAA==', 'actor_process_os_pid': 756, 'actor_thread_thread_id': 4020, 'causality_actor_process_image_name': 'lsass.exe', 'causality_actor_process_command_line': 'C:\\WINDOWS\\system32\\lsass.exe', 'causality_actor_process_image_path': 'C:\\Windows\\System32\\lsass.exe', 'causality_actor_process_signature_vendor': 'Microsoft Corporation', 'causality_actor_process_signature_status': 'Signed', 'causality_actor_causality_id': 'AdkP08aY7RwAAAL0AAAAAA==', 'causality_actor_process_execution_time': 1671033022857, 'causality_actor_process_image_md5': '289d6a47b7692510e2fd3b51979a9fed', 'causality_actor_process_image_sha256': '0777fd312394ae1afeed0ad48ae2d7b5ed6e577117a4f40305eaeb4129233650', 'action_file_path': None, 'action_file_name': None,
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        'action_file_md5': None, 'action_file_sha256': None, 'action_file_macro_sha256': None, 'action_registry_data': None, 'action_registry_key_name': None, 'action_registry_value_name': None, 'action_registry_full_key': None, 'action_local_ip': 'None', 'action_local_ip_v6': None, 'action_local_port': 0, 'action_remote_ip': '137.184.208.116', 'action_remote_ip_v6': None, 'action_remote_port': 0, 'action_external_hostname': 'kali', 'action_country': 'UNKNOWN', 'action_process_instance_id': None, 'action_process_causality_id': None, 'action_process_image_name': None, 'action_process_image_sha256': None, 'action_process_image_command_line': None, 'action_process_signature_status': 'N/A', 'action_process_signature_vendor': None, 'os_actor_effective_username': None, 'os_actor_process_instance_id': 'AdkP08aY7RwAAAL0AAAAAA==', 'os_actor_process_image_path': 'C:\\Windows\\System32\\lsass.exe', 'os_actor_process_image_name': 'lsass.exe', 'os_actor_process_command_line': 'C:\\WINDOWS\\system32\\lsass.exe', 'os_actor_process_signature_status': 'Signed', 'os_actor_process_signature_vendor': 'Microsoft Corporation', 'os_actor_process_image_sha256': '0777fd312394ae1afeed0ad48ae2d7b5ed6e577117a4f40305eaeb4129233650', 'os_actor_process_causality_id': 'AdkP08aY7RwAAAL0AAAAAA==', 'os_actor_causality_id': None, 'os_actor_process_os_pid': 756, 'os_actor_thread_thread_id': 4020, 'fw_app_id': '', 'fw_interface_from': '', 'fw_interface_to': '', 'fw_rule': '', 'fw_rule_id': None, 'fw_device_name': '', 'fw_serial_number': '', 'fw_url_domain': None, 'fw_email_subject': None, 'fw_email_sender': None, 'fw_email_recipient': None, 'fw_app_subcategory': None, 'fw_app_category': None, 'fw_app_technology': None, 'fw_vsys': None, 'fw_xff': None, 'fw_misc': None, 'fw_is_phishing': 'N/A', 'dst_agent_id': '', 'dst_causality_actor_process_execution_time': None, 'dns_query_name': None, 'dst_action_external_hostname': None, 'dst_action_country': '-', 'dst_action_external_port': None, 'is_pcap': False, 'contains_featured_host': 'NO', 'contains_featured_user': 'NO', 'contains_featured_ip': 'NO', 'image_name': None, 'container_id': None, 'cluster_name': None, 'referenced_resource': None, 'operation_name': None, 'identity_sub_type': None, 'identity_type': None, 'project': None, 'cloud_provider': None, 'resource_type': None, 'resource_sub_type': None, 'user_agent': None, 'alert_type': 'Unclassified', 'resolution_status': 'STATUS_010_NEW', 'resolution_comment': None, 'dynamic_fields': None, 'tags': 'DS:PANW/XDR Agent', 'events_length': 1, 'alert_id': '150807', 'detection_timestamp': 1671730626096, 'name': 'Possible external RDP Brute-Force', 'category': 'Credential Access', 'endpoint_id': 'f6ba1a18c35d416c8e27a319cc2fea09', 'description': "DC1ENV12APC05 successfully accessed administrator by systematically guessing the user's password 22 times over an hour with 2 successful logons and 20 failed attempts. The user did not log in successfully from 137.184.208.116 during the last 30 days. Over the past 30 days, DC1ENV12APC05 has had an average of 0 failed login attempts with the user administrator from 137.184.208.116 per day", 'host_ip': '172.16.12.40', 'host_name': 'DC1ENV12APC05', 'source': 'XDR Analytics', 'action': 'DETECTED', 'action_pretty': 'Detected', 'user_name': 'administrator', 'original_tags': 'DS:PANW/XDR Agent'}]}, 'network_artifacts': {'total_count': 1, 'data': [{'type': 'DOMAIN', 'alert_count': 1, 'is_manual': False, 'network_domain': 'kali', 'network_remote_ip': None, 'network_remote_port': 0, 'network_country': 'UNKNOWN'}]}, 'file_artifacts': {'total_count': 1, 'data': [{'type': 'HASH', 'alert_count': 1, 'is_manual': False, 'is_malicious': False, 'is_process': True, 'file_name': 'lsass.exe', 'file_sha256': '0777fd312394ae1afeed0ad48ae2d7b5ed6e577117a4f40305eaeb4129233650', 'file_signature_status': 'SIGNATURE_SIGNED', 'file_signature_vendor_name': 'Microsoft Corporation', 'file_wildfire_verdict': 'BENIGN', 'low_confidence': False}]}}
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


def createIncidentsListCTF3(max_fetch):
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
        "description": "<1>'Image File Execution Options Registry key injection by scripting engine' generated by XDR BIOC detected on host dc1env12apc02 involving user dc1env12apc02\\win10-regression",
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

    for i in range(1, max_fetch):
        new_data = rawJson
        new_data["description"] = f"<{i}>'Image File Execution Options Registry key injection by scripting engine' generated by XDR BIOC detected on host dc1env12apc02 involving user dc1env12apc02\\win10-regression"
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
            # for status in statuses:
            # raw_incidents += client.get_incidents(gte_creation_time_milliseconds=last_fetch, status=status,
            #                                     limit=max_fetch, sort_by_creation_time='asc', starred=starred,
            #                                    starred_incidents_fetch_window=starred_incidents_fetch_window)
            raw_incidents = sorted(raw_incidents, key=lambda inc: inc['creation_time'])
            raw_incidents = createIncidentsListCTF3(max_fetch)
        else:
            # raw_incidents = client.get_incidents(gte_creation_time_milliseconds=last_fetch, limit=max_fetch,
            #                                    sort_by_creation_time='asc', starred=starred,
            #                                    starred_incidents_fetch_window=starred_incidents_fetch_window)
            raw_incidents = createIncidentsListCTF3(max_fetch)

    # save the last 100 modified incidents to the integration context - for mirroring purposes
    # client.save_modified_incidents_to_integration_context()

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

def get_alerts_by_filter_command(client: CoreClient, args: Dict) -> CommandResults:

    prefix = "PaloAltoNetworksXDR"
    #filter_data['filter'] = filter_res
    #demisto.debug(f'sending the following request data: {request_data}')
    #raw_response = client.get_alerts_by_filter_data(request_data)
    raw_response = {
          "alerts": [
            {
              "alert_fields": {
                "accountid": None,
                "accountinformationbreached": None,
                "accountmemberof": None,
                "accountstatus": None,
                "acquisitionhire": None,
                "action_country": [
                  "UNKNOWN"
                ],
                "action_external_hostname": None,
                "action_file_macro_sha256": None,
                "action_file_md5": None,
                "action_file_name": [
                  "dnsapi.dll"
                ],
                "action_file_path": None,
                "action_file_sha256": [
                  "7A31418E4ABC333EC28E11A05ED794A6EE930D6B2CDE84DA4F7B959B49335FE4"
                ],
                "action_local_ip": None,
                "action_local_ip_v6": None,
                "action_local_port": None,
                "action_process_causality_id": None,
                "action_process_image_command_line": None,
                "action_process_image_md5": None,
                "action_process_image_name": None,
                "action_process_image_path": None,
                "action_process_image_sha256": None,
                "action_process_instance_id": None,
                "action_process_os_pid": None,
                "action_process_signature_status": [
                  "SIGNATURE_UNAVAILABLE"
                ],
                "action_process_signature_vendor": None,
                "action_process_user_sid": None,
                "action_registry_data": None,
                "action_registry_full_key": None,
                "action_registry_key_name": None,
                "action_registry_value_name": None,
                "action_remote_ip": None,
                "action_remote_ip_v6": None,
                "action_remote_port": None,
                "activated": "0001-01-01T00:00:00Z",
                "activatingingUserId": "",
                "activity_first_seen_at": None,
                "activity_last_seen_at": None,
                "actor_causality_id": None,
                "actor_effective_user_sid": None,
                "actor_effective_username": [
                  "env4.local\\Administrator"
                ],
                "actor_process_causality_id": None,
                "actor_process_command_line": [
                  "C:\\Users\\administrator.ENV4\\Downloads\\8866115678\\example.exe"
                ],
                "actor_process_execution_time": None,
                "actor_process_image_md5": [
                  "1392aef7cd09a1b87d26f81a0bf1c011"
                ],
                "actor_process_image_name": [
                  "example.exe"
                ],
                "actor_process_image_path": [
                  "C:\\Users\\administrator.ENV4\\Downloads\\8866115678\\example.exe"
                ],
                "actor_process_image_sha256": [
                  "7734984082dfe13fas24264ad1c2cdc79180db273fa196bd3d2e48915d9d1e4b"
                ],
                "actor_process_instance_id": [
                  "AdkwzkxP2AYAAB/YAAAAAA=="
                ],
                "actor_process_os_pid": [
                  8152
                ],
                "actor_process_signature_status": [
                  "SIGNATURE_UNAVAILABLE"
                ],
                "actor_process_signature_vendor": None,
                "actor_thread_thread_id": None,
                "additionaldata": None,
                "additionalindicators": None,
                "affecteddata": None,
                "affecteddatatype": None,
                "affectedindividualscontactinformation": None,
                "agent_data_collection_status": False,
                "agent_device_domain": "env4.local",
                "agent_file_md5": None,
                "agent_file_path": [
                  "C:\\\\Windows\\\\system32\\\\dnsapi.dll"
                ],
                "agent_fqdn": "DC1ENV4APC01.env4.local",
                "agent_host_boot_time": None,
                "agent_hostname": "DC1ENV4APC01",
                "agent_id": "ac848acbd7504115b6624c9b1d755000",
                "agent_install_type": "STANDARD",
                "agent_ip_addresses": [
                  "172.16.4.122"
                ],
                "agent_ip_addresses_v6": None,
                "agent_is_vdi": None,
                "agent_os_sub_type": "10.0.19044",
                "agent_os_type": "AGENT_OS_WINDOWS",
                "agent_version": "7.9.0.20664",
                "agentsid": None,
                "agentversion": [
                  "7.9.0.20664"
                ],
                "alert_action_status": "BLOCKED",
                "alert_action_status_readable": "prevented (blocked)",
                "alert_category": "Malware",
                "alert_description": "Suspicious executable detected",
                "alert_description_raw": "Suspicious executable detected",
                "alert_ingest_status": None,
                "alert_is_fp": False,
                "alert_json": None,
                "alert_name": "Local Analysis Malware",
                "alert_source": "TRAPS",
                "alert_sub_type": None,
                "alert_type": "Unclassified",
                "alertacknowledgement": None,
                "alertaction": None,
                "alertmalicious": None,
                "alerttypeid": None,
                "analysisreport": None,
                "appchannelname": None,
                "applicationpath": None,
                "appmessage": None,
                "approvalstatus": None,
                "approver": None,
                "approximatenumberofaffecteddatasubjects": None,
                "asmalertsummary": None,
                "asmcloud": None,
                "asmdatacollection": None,
                "asmdevcheck": False,
                "asmnotification": None,
                "asmprivateip": None,
                "asmrelated": None,
                "asmremediation": None,
                "asmremediationpathrule": None,
                "asmservicedetection": None,
                "asmserviceowner": None,
                "asmserviceownerunrankedraw": None,
                "asmsystemids": None,
                "asmtags": None,
                "asn": None,
                "asnname": None,
                "asset_service_id": None,
                "assetid": None,
                "assigneduser": None,
                "assignmentgroup": None,
                "association_strength": [
                  50
                ],
                "attachment": None,
                "attachmentcount": None,
                "attachmentextension": None,
                "attachmenthash": None,
                "attachmentid": None,
                "attachmentname": None,
                "attachmentsize": None,
                "attachmenttype": None,
                "attack_techniques": None,
                "attackmode": None,
                "attempt_counter": 0,
                "attorneygeneralnotification": None,
                "audit_ids": None,
                "awsarn": None,
                "awsguarddutyaccesskeydetails": None,
                "awsguarddutyconfidencescore": None,
                "awsguarddutycontainerdetails": None,
                "awsguarddutyebsvolumedetails": None,
                "awsguarddutyecsclusterdetails": None,
                "awsguarddutyeksclusterdetails": None,
                "awsguarddutyiaminstanceprofile": None,
                "awsguarddutyinstancedetails": None,
                "awsguarddutykubernetesuserdetails": None,
                "awsguarddutykubernetesworkloaddetails": None,
                "awsguarddutynetworkinterface": None,
                "awsguarddutypartition": None,
                "awsguarddutyresourcetype": None,
                "awsguarddutys3bucketdetails": None,
                "awsguarddutyschemaversion": None,
                "awsguarddutyservice": None,
                "awsguarddutytype": None,
                "bioc_category_enum_key": None,
                "bioc_indicator": None,
                "birthday": None,
                "blockedaction": None,
                "branchname": None,
                "breachconfirmation": None,
                "bugtraq": None,
                "caller": None,
                "caller_ip": None,
                "case_id": 74,
                "category": None,
                "categorycount": None,
                "causality_actor_causality_id": None,
                "causality_actor_process_command_line": None,
                "causality_actor_process_execution_time": None,
                "causality_actor_process_image_md5": None,
                "causality_actor_process_image_name": None,
                "causality_actor_process_image_path": None,
                "causality_actor_process_image_sha256": None,
                "causality_actor_process_instance_id": None,
                "causality_actor_process_os_pid": None,
                "causality_actor_process_signature_status": [
                  "SIGNATURE_UNAVAILABLE"
                ],
                "causality_actor_process_signature_vendor": None,
                "changed": None,
                "cicdbranch": None,
                "cicdpackname": None,
                "cicdpullrequestbranch": None,
                "cicdpullrequestcomment": None,
                "cicdpullrequestlink": None,
                "cicdpullrequestreview": None,
                "cicdpullrequesttitle": None,
                "cicdreviewer": None,
                "cicds3bucketname": None,
                "city": None,
                "classification": None,
                "clickedurls": None,
                "closeReason": "",
                "closed": "0001-01-01T00:00:00Z",
                "closereason": None,
                "closetime": None,
                "closingUserId": "",
                "closingreason": None,
                "closinguser": None,
                "closinguserid": None,
                "cloud_provider": None,
                "cloudaccountid": None,
                "cloudinstanceid": None,
                "cloudregionlist": None,
                "cloudresourcelist": None,
                "cloudservice": None,
                "cluster_name": None,
                "comment": None,
                "companyaddress": None,
                "companycity": None,
                "companyhasinsuranceforthebreach": None,
                "companyname": None,
                "companypostalcode": None,
                "compliancenotes": None,
                "configfilepath": None,
                "configurationfilesource": None,
                "consumerreportingagenciesnotification": None,
                "contactaddress": None,
                "contactemailaddress": None,
                "contactname": None,
                "contacttelephonenumber": None,
                "container_id": None,
                "contains_featured_host": [
                  "NO"
                ],
                "contains_featured_ip": [
                  "NO"
                ],
                "contains_featured_user": [
                  "NO"
                ],
                "costcenter": None,
                "costcentercode": None,
                "countrycode": None,
                "countrycodenumber": None,
                "countrywherebusinesshasitsmainestablishment": None,
                "criticalassets": None,
                "custompacksinstalled": None,
                "custompackssource": None,
                "cve": None,
                "cvelist": None,
                "cvss": None,
                "cvssavailabilityrequirement": None,
                "cvsscollateraldamagepotential": None,
                "cvssconfidentialityrequirement": None,
                "cvssintegrityrequirement": None,
                "dataencryptionstatus": None,
                "dbotCurrentDirtyFields": None,
                "dbotDirtyFields": None,
                "dbotMirrorDirection": "",
                "dbotMirrorId": "",
                "dbotMirrorInstance": "",
                "dbotMirrorLastSync": "0001-01-01T00:00:00Z",
                "dbotMirrorTags": None,
                "dbotclosed": None,
                "dbotduedate": None,
                "dbotmirrordirection": None,
                "dbotmirrorid": None,
                "dbotmirrorinstance": None,
                "dbotmirrorlastsync": None,
                "dbotmodified": None,
                "dbotprediction": None,
                "dbotpredictionprobability": None,
                "dbotstatus": None,
                "dbottextsuggestionhighlighted": None,
                "dbottotaltime": None,
                "deduplicate_tokens": None,
                "department": None,
                "destinationgeolocation": None,
                "destinationipv6": None,
                "destinationnetworks": None,
                "destos": None,
                "detectedendpoints": None,
                "detectedexternalips": None,
                "detectedinternalhosts": None,
                "detection_modules": None,
                "detectionendtime": None,
                "detectionid": None,
                "detectionurl": None,
                "deviceexternalips": None,
                "devicehash": None,
                "deviceid": None,
                "deviceinternalips": None,
                "devicemacaddress": None,
                "devicemodel": None,
                "devicename": None,
                "deviceosname": None,
                "deviceosversion": None,
                "deviceou": None,
                "devicestatus": None,
                "devicetime": None,
                "digitalguardianattachmentfilename": "dnsapi.dll",
                "digitalguardianfilename": "dnsapi.dll",
                "displayname": None,
                "dns_query_name": None,
                "domainname": None,
                "domainsquattingresult": None,
                "dpoemailaddress": None,
                "dponotification": None,
                "drilldown_max_ts": None,
                "drilldown_min_ts": None,
                "drilldown_query": None,
                "droppedCount": 0,
                "droppedcount": None,
                "dst_action_country": None,
                "dst_action_external_hostname": None,
                "dst_action_external_port": None,
                "dst_actor_process_image_name": None,
                "dst_actor_process_os_pid": None,
                "dst_agent_hostname": None,
                "dst_agent_id": None,
                "dst_agent_id_single": None,
                "dst_agent_os_type": [
                  "NO_HOST"
                ],
                "dst_association_strength": None,
                "dst_causality_actor_process_execution_time": None,
                "dst_os_actor_process_image_name": None,
                "dst_os_actor_process_os_pid": None,
                "dsts": None,
                "dueDate": "0001-01-01T00:00:00Z",
                "duration": None,
                "dynamic_fields": None,
                "email": None,
                "emailaddress": None,
                "emailauthenticitycheck": None,
                "emailbcc": None,
                "emailbody": None,
                "emailbodyformat": None,
                "emailbodyhtml": None,
                "emailcampaigncanvas": None,
                "emailcampaignmutualindicators": None,
                "emailcampaignsnippets": None,
                "emailcampaignsummary": None,
                "emailcc": None,
                "emailclassification": None,
                "emailclientname": None,
                "emaildeletefrombrand": None,
                "emaildeletereason": None,
                "emaildeleteresult": None,
                "emaildeletetype": None,
                "emailheaders": None,
                "emailhtml": None,
                "emailhtmlimage": None,
                "emailinreplyto": None,
                "emailinternalmessageid": None,
                "emailkeywords": None,
                "emaillabels": None,
                "emaillatestmessage": None,
                "emailmessageid": None,
                "emailreceived": None,
                "emailrecipientscount": None,
                "emailreplyto": None,
                "emailreturnpath": None,
                "emailsenderip": None,
                "emailsentsuccessfully": False,
                "emailsize": None,
                "emailsource": None,
                "emailtocount": None,
                "emailurlclicked": None,
                "employeedisplayname": None,
                "employeeemail": None,
                "employeemanageremail": None,
                "end_match_attempt_ts": None,
                "endpointisolationstatus": None,
                "endtime": None,
                "errorcode": None,
                "errormessage": None,
                "escalation": None,
                "event_id": None,
                "event_sub_type": None,
                "event_timestamp": [
                  1674659141991
                ],
                "event_type": [
                  1
                ],
                "eventaction": None,
                "eventdescriptions": None,
                "eventid": None,
                "eventnames": None,
                "events": [],
                "exposurelevel": None,
                "external_id": "e08916bd582b401d862ddb2dcb704def",
                "externalcategoryid": None,
                "externalcategoryname": None,
                "externalconfidence": None,
                "externalendtime": None,
                "externallink": None,
                "externalseverity": None,
                "externalstarttime": None,
                "externalstatus": None,
                "externalsubcategoryid": None,
                "externalsubcategoryname": None,
                "externalsystemid": None,
                "family_tags": [
                  "DS:PANW/XDR Agent"
                ],
                "feedBased": False,
                "feedbased": False,
                "fileaccessdate": None,
                "filecreationdate": None,
                "filehash": None,
                "filenames": "dnsapi.dll",
                "filepaths": [
                  "C:\\\\Windows\\\\system32\\\\dnsapi.dll"
                ],
                "filerelationships": None,
                "filesha1": None,
                "filesize": None,
                "filter_rule_id": None,
                "financialinformationbreached": None,
                "fireeyealertinfectionid": None,
                "fireeyealertmalicious": None,
                "fireeyealertvlan": None,
                "fireeyec2address": None,
                "fireeyec2channel": None,
                "fireeyec2host": None,
                "fireeyeemailqueueid": None,
                "fireeyeemailsourcedomain": None,
                "fireeyefireeyedownloadat": None,
                "fireeyeinfectionid": None,
                "fireeyeinfectionurl": None,
                "fireeyemalwareinfo": None,
                "fireeyemalwareinformation": None,
                "fireeyematchcount": None,
                "fireeyematchedtime": None,
                "fireeyenxalertaction": None,
                "fireeyenxalertid": None,
                "fireeyenxalertmalwarename": None,
                "fireeyenxalertscversion": None,
                "fireeyenxalerttargetip": None,
                "fireeyenxalerttype": None,
                "fireeyenxalerturl": None,
                "fireeyenxalertuuid": None,
                "fireeyenxalertvictimip": None,
                "fireeyenxeventcveid": None,
                "fireeyenxeventdestinationmacaddress": None,
                "fireeyenxeventid": None,
                "fireeyenxeventrule": None,
                "fireeyenxeventsourcemacaddress": None,
                "fireeyenxeventvictimip": None,
                "fireeyesignatureid": None,
                "fireeyesignaturerevision": None,
                "fireeyesubmittedat": None,
                "firstname": None,
                "firstseen": None,
                "followup": False,
                "forensics_artifact_type": None,
                "from_dml": None,
                "fullname": None,
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
                "fw_is_phishing": [
                  "NOT_AVAILABLE"
                ],
                "fw_misc": None,
                "fw_rule": None,
                "fw_rule_id": None,
                "fw_serial_number": None,
                "fw_url_domain": None,
                "fw_vsys": None,
                "fw_xff": None,
                "genericexportindicatorsserviceaction": None,
                "genericexportindicatorsserviceindicatorslist": None,
                "genericexportindicatorsserviceindicatortype": None,
                "genericexportindicatorsservicetag": None,
                "gibleakedfilename": "dnsapi.dll",
                "givenname": None,
                "groupid": None,
                "gsuitesacalertid": None,
                "gsuitesacalertseverity": None,
                "gsuitesacalertsource": None,
                "gsuitesacalertstatus": None,
                "gsuitesacalerttype": None,
                "gsuitesaccreatetime": None,
                "gsuitesaccustomerid": None,
                "gsuitesacdeleted": None,
                "gsuitesacendtime": None,
                "gsuitesacetag": None,
                "gsuitesacfeedbackcreatetime": None,
                "gsuitesacfeedbackemail": None,
                "gsuitesacfeedbackid": None,
                "gsuitesacfeedbacktype": None,
                "gsuitesacsecurityinvestigationtoollink": None,
                "gsuitesacstarttime": None,
                "gsuitesacupdatetime": None,
                "has_alert_layout_data": None,
                "healthinsurancebreached": None,
                "helloworldid": None,
                "helloworldstatus": None,
                "helloworldtype": None,
                "huntresultscount": None,
                "identity_invoked_by_type": None,
                "identity_name": None,
                "identity_sub_type": None,
                "identity_type": None,
                "image_name": None,
                "impacteddevices": None,
                "impactedentities": None,
                "incidentlink": None,
                "incomingmirrorerror": None,
                "individualsnotification": None,
                "internal_id": "14864",
                "internaladdresses": None,
                "investigationId": "14864",
                "investigationstage": None,
                "iot_pivot_url": None,
                "ipblockedstatus": None,
                "ipreputation": None,
                "isDebug": False,
                "is_deleted": False,
                "is_disintegrated": None,
                "is_identity": False,
                "is_pcap": False,
                "is_rule_triggering": False,
                "is_whitelisted": False,
                "is_xdm": None,
                "is_xsoar_alert": False,
                "isactive": None,
                "isolated": None,
                "isthedatasubjecttodpia": None,
                "itemowner": None,
                "itemowneremail": None,
                "jobcode": None,
                "jobfamily": None,
                "jobfunction": None,
                "jobscreated": None,
                "join_next_attempt_time": None,
                "labels": None,
                "lastJobRunTime": "0001-01-01T00:00:00Z",
                "lastOpen": "0001-01-01T00:00:00Z",
                "last_modified_ts": 1678193813541,
                "lastmodifiedby": None,
                "lastmodifiedon": None,
                "lastname": None,
                "lastseen": None,
                "lastupdatetime": None,
                "leadership": None,
                "likelyimpact": None,
                "linkedCount": 0,
                "linkedIncidents": None,
                "linkedcount": None,
                "listofrulesevent": None,
                "listscreated": None,
                "local_insert_ts": 1674659148751,
                "location": None,
                "locationregion": None,
                "logsource": None,
                "logsourcename": None,
                "logsourcetype": None,
                "lowlevelcategoriesevents": None,
                "mac": "00:50:56:9f:f5:5f",
                "macrosourcecode": None,
                "maliciousbehavior": None,
                "maliciouscauseifthecauseisamaliciousattack": None,
                "maliciousurlclicked": None,
                "maliciousurlviewed": None,
                "malwarefamily": None,
                "malwarename": None,
                "managementnotification": None,
                "manageremailaddress": None,
                "managername": None,
                "marketplacepacksinstalled": None,
                "matching_service_rule_id": None,
                "matching_status": "UNMATCHABLE",
                "measurestomitigate": None,
                "medianotification": None,
                "medicalinformationbreached": None,
                "microsoft365defendera": None,
                "microsoft365defenderactive": None,
                "microsoft365defendercategoriescount": None,
                "microsoft365defenderclassification": None,
                "microsoft365defenderdevices": None,
                "microsoft365defenderdisplayname": None,
                "microsoft365defenderfirstactivity": None,
                "microsoft365defenderid": None,
                "microsoft365defenderlastactivity": None,
                "microsoft365defenderstatus": None,
                "microsoftdefenderforendpointevidencecreationtime": None,
                "microsoftdefenderforendpointevidencetype": None,
                "microsoftgraphidentityandaccessactivity": None,
                "microsoftgraphidentityandaccessalerttype": None,
                "microsoftgraphidentityandaccessdetectiontimingtype": None,
                "microsoftgraphidentityandaccesstokenissuertype": None,
                "mitre_tactic_id_and_name": None,
                "mitre_technique_id_and_name": None,
                "mitretacticid": None,
                "mitretacticname": None,
                "mitretechniqueid": None,
                "mitretechniquename": None,
                "mobiledevicemodel": None,
                "mobilephone": None,
                "module_id": [
                  "Local Analysis"
                ],
                "module_name": [
                  "COMPONENT_LOCAL_ANALYSIS"
                ],
                "notifyTime": "2023-03-07T12:56:50.991890521Z",
                "numberoflogsources": None,
                "numberofrelatedincidents": None,
                "numberofsimilarfiles": None,
                "objective": None,
                "occurred": "0001-01-01T00:00:00Z",
                "openDuration": 0,
                "operation_name": None,
                "orglevel1": None,
                "orglevel2": None,
                "orglevel3": None,
                "orgunit": None,
                "original_severity": "SEV_030_MEDIUM",
                "originalalertid": None,
                "originalalertname": None,
                "originalalertsource": None,
                "originaldescription": None,
                "originalevents": None,
                "os": None,
                "os_actor_causality_id": None,
                "os_actor_effective_username": None,
                "os_actor_process_causality_id": None,
                "os_actor_process_command_line": None,
                "os_actor_process_execution_time": None,
                "os_actor_process_image_md5": None,
                "os_actor_process_image_name": None,
                "os_actor_process_image_path": None,
                "os_actor_process_image_sha256": None,
                "os_actor_process_instance_id": None,
                "os_actor_process_os_pid": None,
                "os_actor_process_signature_status": [
                  "SIGNATURE_UNAVAILABLE"
                ],
                "os_actor_process_signature_vendor": None,
                "os_actor_thread_thread_id": None,
                "ostype": None,
                "otherpiidatabreached": None,
                "outgoingmirrorerror": None,
                "owner": None,
                "parentprocesscmd": None,
                "parentprocessfilepath": None,
                "parentprocessid": None,
                "parentprocessids": None,
                "parentprocessmd5": None,
                "parentprocessname": None,
                "parentprocesspath": None,
                "parentprocesssha256": None,
                "partofcampaign": None,
                "passwordchangeddate": None,
                "passwordresetsuccessfully": False,
                "pcapfilename": "dnsapi.dll",
                "personalemail": None,
                "phase": None,
                "phishingbclscore": None,
                "phishingpclscore": None,
                "phishingreporteremailheaders": None,
                "phishingsclscore": None,
                "phishingsubtype": None,
                "phone_number": None,
                "piidatatype": None,
                "pivot_url": None,
                "playbookId": "5a05f427-1416-426a-89d8-df7c89992486",
                "playbook_suggestion_rule_id": None,
                "playbookid": None,
                "policy_id": None,
                "policyactions": None,
                "policydeleted": None,
                "policydescription": None,
                "policydetails": None,
                "policyid": None,
                "policyrecommendation": None,
                "policyremediable": None,
                "policyseverity": None,
                "policytype": None,
                "policyuri": None,
                "possiblecauseofthebreach": None,
                "postalcode": None,
                "postnatdestinationip": None,
                "postnatdestinationport": None,
                "postnatsourceip": None,
                "postnatsourceport": None,
                "prenatdestinationport": None,
                "prenatsourceip": None,
                "prenatsourceport": None,
                "processcmd": None,
                "processcreationtime": None,
                "processid": None,
                "processmd5": None,
                "processnames": None,
                "processpaths": None,
                "processsha256": None,
                "project": None,
                "protocolnames": None,
                "quarantined": None,
                "query_tables": None,
                "rating": None,
                "rawevent": None,
                "reason": "",
                "referenced_resource": None,
                "region": None,
                "regionid": None,
                "registryhive": None,
                "registrykey": None,
                "registryvalue": None,
                "registryvaluetype": None,
                "relatedcampaign": None,
                "relatedendpoints": None,
                "relatedreport": None,
                "reminder": "0001-01-01T00:00:00Z",
                "remote_cid": None,
                "renderedhtml": None,
                "reportedemailcc": None,
                "reportedemailfrom": None,
                "reportedemailmessageid": None,
                "reportedemailorigin": None,
                "reportedemailsubject": None,
                "reportedemailto": None,
                "reporteremailaddress": None,
                "residentnotificationoption": None,
                "residentsemailaddress": None,
                "resolution_comment": None,
                "resolution_status": "STATUS_020_UNDER_INVESTIGATION",
                "resolution_status_modified_ts": 1674659179219,
                "resource_sub_type": None,
                "resource_type": None,
                "resourcename": None,
                "resourcetype": None,
                "riskrating": None,
                "riskscore": None,
                "rulename": None,
                "runStatus": "error",
                "samaccountname": None,
                "scenario": None,
                "secretarynotification": None,
                "sectorofaffectedparty": None,
                "selectedindicators": None,
                "sensorip": None,
                "severity": "SEV_030_MEDIUM",
                "sha1": None,
                "sha256": "7A31418E4ABC333EC28E11A05ED794A6EE930D6B2CDE84DA4F7B959B49335FE4",
                "sha512": None,
                "signature": None,
                "similarincidents": None,
                "similarincidentsdbot": None,
                "sizenumberofemployees": None,
                "sizeturnover": None,
                "skuname": None,
                "skutier": None,
                "sla": 0,
                "sourceInstance": "",
                "source_insert_ts": 1674659141991,
                "sourcecategory": None,
                "sourcecreatedby": None,
                "sourcecreatetime": None,
                "sourceexternalips": None,
                "sourcegeolocation": None,
                "sourceid": None,
                "sourceinstance": None,
                "sourcenetworks": None,
                "sourcepriority": None,
                "sourcestatus": None,
                "sourceupdatedby": None,
                "sourceurgency": None,
                "srcos": None,
                "ssdeep": None,
                "starred": False,
                "starttime": None,
                "state": None,
                "statecisonotification": None,
                "statewherethebreachtookplace": None,
                "story_id": None,
                "streetaddress": None,
                "subcategory": None,
                "subtype": None,
                "suggested_playbook_id": None,
                "surname": None,
                "tactic": None,
                "tacticid": None,
                "tags": [
                  "DS:PANW/XDR Agent"
                ],
                "target": None,
                "targetfirewallversion": None,
                "teamname": None,
                "technicalowner": None,
                "technicalownercontact": None,
                "technicaluser": None,
                "technique": None,
                "techniqueid": None,
                "telephoneno": None,
                "tenantname": None,
                "terminatedaction": None,
                "threatactor": None,
                "threatfamilyname": None,
                "threatname": None,
                "ticketacknowledgeddate": None,
                "ticketcloseddate": None,
                "ticketnumber": None,
                "tim_main_indicator": None,
                "timezone": None,
                "title": None,
                "totalmaliciousurlsclicks": None,
                "trafficdirection": None,
                "triggeredsecurityprofile": None,
                "uniquebiometricdatabreached": None,
                "uniqueidentificationnumberbreached": None,
                "uniqueports": None,
                "urls": None,
                "urlsslverification": None,
                "usecasedescription": None,
                "user_agent": None,
                "useraccountcontrol": None,
                "usercreationtime": None,
                "userengagementresponse": None,
                "userid": None,
                "usersid": None,
                "uuid": None,
                "values_changed": True,
                "vendorid": None,
                "vendorproduct": None,
                "verdict": None,
                "verificationmethod": None,
                "verificationstatus": None,
                "vulnerabilitycategory": None,
                "whereisdatahosted": None,
                "workphone": None,
                "xdr_additional_info": None,
                "xpanse_asset_id": None,
                "xpanse_asset_name": None,
                "xpanse_first_observed": None,
                "xpanse_policy_id": None,
                "xpanse_primary_asset_id": None,
                "xpanse_service_id": None,
                "xpanse_website_id": None,
                "zipcode": None
              },
              "incident_fields": None
            },
            {
              "alert_fields": {
                "accountid": None,
                "accountinformationbreached": None,
                "accountmemberof": None,
                "accountstatus": None,
                "acquisitionhire": None,
                "action_country": [
                  "UNKNOWN"
                ],
                "action_external_hostname": None,
                "action_file_macro_sha256": None,
                "action_file_md5": None,
                "action_file_name": None,
                "action_file_path": None,
                "action_file_sha256": None,
                "action_local_ip": None,
                "action_local_ip_v6": None,
                "action_local_port": None,
                "action_process_causality_id": None,
                "action_process_image_command_line": None,
                "action_process_image_md5": None,
                "action_process_image_name": None,
                "action_process_image_path": None,
                "action_process_image_sha256": None,
                "action_process_instance_id": None,
                "action_process_os_pid": None,
                "action_process_signature_status": [
                  "SIGNATURE_UNAVAILABLE"
                ],
                "action_process_signature_vendor": None,
                "action_process_user_sid": None,
                "action_registry_data": None,
                "action_registry_full_key": None,
                "action_registry_key_name": None,
                "action_registry_value_name": None,
                "action_remote_ip": None,
                "action_remote_ip_v6": None,
                "action_remote_port": None,
                "activated": "0001-01-01T00:00:00Z",
                "activity_first_seen_at": None,
                "activity_last_seen_at": None,
                "actor_causality_id": None,
                "actor_effective_user_sid": None,
                "actor_effective_username": [
                  "env4.local\\Administrator"
                ],
                "actor_process_causality_id": None,
                "actor_process_command_line": [
                  "\"C:\\Users\\administrator.ENV4\\Downloads\\8872230438\\wanmgr.exe\" "
                ],
                "actor_process_execution_time": None,
                "actor_process_image_md5": [
                  "7265719c94c5ffbcdbb5f71228d8ca68"
                ],
                "actor_process_image_name": [
                  "wanmgr.exe"
                ],
                "actor_process_image_path": [
                  "C:\\Users\\administrator.ENV4\\Downloads\\8872230438\\wanmgr.exe"
                ],
                "actor_process_image_sha256": [
                  "000001e7a228b2a7abdf7f7e3313324332b725e86907dde32176bddbbbb27"
                ],
                "actor_process_instance_id": [
                  "Adkwy9zWJhIAAA1sAAAAAA=="
                ],
                "actor_process_os_pid": [
                  3436
                ],
                "actor_process_signature_status": [
                  "SIGNATURE_UNAVAILABLE"
                ],
                "actor_process_signature_vendor": None,
                "actor_thread_thread_id": None,
                "additionaldata": None,
                "additionalindicators": None,
                "affecteddata": None,
                "affecteddatatype": None,
                "affectedindividualscontactinformation": None,
                "agent_data_collection_status": False,
                "agent_device_domain": "env4.local",
                "agent_file_md5": None,
                "agent_file_path": None,
                "agent_fqdn": "DC1ENV4APC01.env4.local",
                "agent_host_boot_time": None,
                "agent_hostname": "DC1ENV4APC01",
                "agent_id": "ac848acbd7504115b6624c9b1d755000",
                "agent_install_type": "STANDARD",
                "agent_ip_addresses": [
                  "172.16.4.122"
                ],
                "agent_ip_addresses_v6": None,
                "agent_is_vdi": None,
                "agent_os_sub_type": "10.0.19044",
                "agent_os_type": "AGENT_OS_WINDOWS",
                "agent_version": "7.9.0.20664",
                "agentsid": None,
                "agentversion": None,
                "alert_action_status": "BLOCKED",
                "alert_action_status_readable": "prevented (blocked)",
                "alert_category": "Malware",
                "alert_description": "Suspicious executable detected",
                "alert_description_raw": "Suspicious executable detected",
                "alert_ingest_status": None,
                "alert_is_fp": False,
                "alert_json": None,
                "alert_name": "WildFire Malware",
                "alert_source": "TRAPS",
                "alert_sub_type": None,
                "alert_type": "Unclassified",
                "alertacknowledgement": None,
                "alertaction": None,
                "alertmalicious": None,
                "alerttypeid": None,
                "analysisreport": None,
                "appchannelname": None,
                "applicationpath": None,
                "appmessage": None,
                "approvalstatus": None,
                "approver": None,
                "approximatenumberofaffecteddatasubjects": None,
                "asmalertsummary": None,
                "asmcloud": None,
                "asmdatacollection": None,
                "asmdevcheck": False,
                "asmnotification": None,
                "asmprivateip": None,
                "asmrelated": None,
                "asmremediation": None,
                "asmremediationpathrule": None,
                "asmservicedetection": None,
                "asmserviceowner": None,
                "asmserviceownerunrankedraw": None,
                "asmsystemids": None,
                "asmtags": None,
                "asn": None,
                "asnname": None,
                "asset_service_id": None,
                "assetid": None,
                "assigneduser": None,
                "assignmentgroup": None,
                "association_strength": [
                  50
                ],
                "attachment": None,
                "attachmentcount": None,
                "attachmentextension": None,
                "attachmenthash": None,
                "attachmentid": None,
                "attachmentname": None,
                "attachmentsize": None,
                "attachmenttype": None,
                "attack_techniques": None,
                "attackmode": None,
                "attempt_counter": 0,
                "attorneygeneralnotification": None,
                "audit_ids": None,
                "awsarn": None,
                "awsguarddutyaccesskeydetails": None,
                "awsguarddutyconfidencescore": None,
                "awsguarddutycontainerdetails": None,
                "awsguarddutyebsvolumedetails": None,
                "awsguarddutyecsclusterdetails": None,
                "awsguarddutyeksclusterdetails": None,
                "awsguarddutyiaminstanceprofile": None,
                "awsguarddutyinstancedetails": None,
                "awsguarddutykubernetesuserdetails": None,
                "awsguarddutykubernetesworkloaddetails": None,
                "awsguarddutynetworkinterface": None,
                "awsguarddutypartition": None,
                "awsguarddutyresourcetype": None,
                "awsguarddutys3bucketdetails": None,
                "awsguarddutyschemaversion": None,
                "awsguarddutyservice": None,
                "awsguarddutytype": None,
                "bioc_category_enum_key": None,
                "bioc_indicator": None,
                "birthday": None,
                "blockedaction": None,
                "branchname": None,
                "breachconfirmation": None,
                "bugtraq": None,
                "caller": None,
                "caller_ip": None,
                "case_id": 73,
                "category": None,
                "categorycount": None,
                "causality_actor_causality_id": None,
                "causality_actor_process_command_line": None,
                "causality_actor_process_execution_time": None,
                "causality_actor_process_image_md5": None,
                "causality_actor_process_image_name": None,
                "causality_actor_process_image_path": None,
                "causality_actor_process_image_sha256": None,
                "causality_actor_process_instance_id": None,
                "causality_actor_process_os_pid": None,
                "causality_actor_process_signature_status": [
                  "SIGNATURE_UNAVAILABLE"
                ],
                "causality_actor_process_signature_vendor": None,
                "changed": None,
                "cicdbranch": None,
                "cicdpackname": None,
                "cicdpullrequestbranch": None,
                "cicdpullrequestcomment": None,
                "cicdpullrequestlink": None,
                "cicdpullrequestreview": None,
                "cicdpullrequesttitle": None,
                "cicdreviewer": None,
                "cicds3bucketname": None,
                "city": None,
                "classification": None,
                "clickedurls": None,
                "closed": "0001-01-01T00:00:00Z",
                "closereason": None,
                "closetime": None,
                "closingreason": None,
                "closinguser": None,
                "closinguserid": None,
                "cloud_provider": None,
                "cloudaccountid": None,
                "cloudinstanceid": None,
                "cloudregionlist": None,
                "cloudresourcelist": None,
                "cloudservice": None,
                "cluster_name": None,
                "comment": None,
                "companyaddress": None,
                "companycity": None,
                "companyhasinsuranceforthebreach": None,
                "companyname": None,
                "companypostalcode": None,
                "compliancenotes": None,
                "configfilepath": None,
                "configurationfilesource": None,
                "consumerreportingagenciesnotification": None,
                "contactaddress": None,
                "contactemailaddress": None,
                "contactname": None,
                "contacttelephonenumber": None,
                "container_id": None,
                "contains_featured_host": [
                  "NO"
                ],
                "contains_featured_ip": [
                  "NO"
                ],
                "contains_featured_user": [
                  "NO"
                ],
                "costcenter": None,
                "costcentercode": None,
                "countrycode": None,
                "countrycodenumber": None,
                "countrywherebusinesshasitsmainestablishment": None,
                "criticalassets": None,
                "custompacksinstalled": None,
                "custompackssource": None,
                "cve": None,
                "cvelist": None,
                "cvss": None,
                "cvssavailabilityrequirement": None,
                "cvsscollateraldamagepotential": None,
                "cvssconfidentialityrequirement": None,
                "cvssintegrityrequirement": None,
                "dataencryptionstatus": None,
                "dbotMirrorLastSync": "0001-01-01T00:00:00Z",
                "dbotclosed": None,
                "dbotduedate": None,
                "dbotmirrordirection": None,
                "dbotmirrorid": None,
                "dbotmirrorinstance": None,
                "dbotmirrorlastsync": None,
                "dbotmodified": None,
                "dbotprediction": None,
                "dbotpredictionprobability": None,
                "dbotstatus": None,
                "dbottextsuggestionhighlighted": None,
                "dbottotaltime": None,
                "deduplicate_tokens": None,
                "department": None,
                "destinationgeolocation": None,
                "destinationipv6": None,
                "destinationnetworks": None,
                "destos": None,
                "detectedendpoints": None,
                "detectedexternalips": None,
                "detectedinternalhosts": None,
                "detection_modules": None,
                "detectionendtime": None,
                "detectionid": None,
                "detectionurl": None,
                "deviceexternalips": None,
                "devicehash": None,
                "deviceid": None,
                "deviceinternalips": None,
                "devicemacaddress": None,
                "devicemodel": None,
                "devicename": None,
                "deviceosname": None,
                "deviceosversion": None,
                "deviceou": None,
                "devicestatus": None,
                "devicetime": None,
                "displayname": None,
                "dns_query_name": None,
                "domainname": None,
                "domainsquattingresult": None,
                "dpoemailaddress": None,
                "dponotification": None,
                "drilldown_max_ts": None,
                "drilldown_min_ts": None,
                "drilldown_query": None,
                "droppedCount": 0,
                "droppedcount": None,
                "dst_action_country": None,
                "dst_action_external_hostname": None,
                "dst_action_external_port": None,
                "dst_actor_process_image_name": None,
                "dst_actor_process_os_pid": None,
                "dst_agent_hostname": None,
                "dst_agent_id": None,
                "dst_agent_id_single": None,
                "dst_agent_os_type": [
                  "NO_HOST"
                ],
                "dst_association_strength": None,
                "dst_causality_actor_process_execution_time": None,
                "dst_os_actor_process_image_name": None,
                "dst_os_actor_process_os_pid": None,
                "dsts": None,
                "dueDate": "0001-01-01T00:00:00Z",
                "duration": None,
                "dynamic_fields": {
                  "action_country": [
                    "UNKNOWN"
                  ],
                  "action_process_signature_status": [
                    "SIGNATURE_UNAVAILABLE"
                  ],
                  "activated": "0001-01-01T00:00:00Z",
                  "activatingingUserId": "",
                  "actor_effective_username": [
                    "env4.local\\Administrator"
                  ],
                  "actor_process_command_line": [
                    "\"C:\\Users\\administrator.ENV4\\Downloads\\8872230438\\wanmgr.exe\" "
                  ],
                  "actor_process_image_md5": [
                    "7265719c94c5ffbcdbb5f71228d8ca68"
                  ],
                  "actor_process_image_name": [
                    "wanmgr.exe"
                  ],
                  "actor_process_image_path": [
                    "C:\\Users\\administrator.ENV4\\Downloads\\8872230438\\wanmgr.exe"
                  ],
                  "actor_process_image_sha256": [
                    "000001e7a228b2a7abdf7f7e3313324332b725e86907dde32176bddbbbb27"
                  ],
                  "actor_process_os_pid": [
                    3436
                  ],
                  "actor_process_signature_status": [
                    "SIGNATURE_UNAVAILABLE"
                  ],
                  "agent_device_domain": "env4.local",
                  "agent_fqdn": "DC1ENV4APC01.env4.local",
                  "agent_hostname": "DC1ENV4APC01",
                  "agent_id": "ac848acbd7504115b6624c9b1d755000",
                  "agent_ip_addresses": [
                    "172.16.4.122"
                  ],
                  "agent_os_sub_type": "10.0.19044",
                  "agent_os_type": "AGENT_OS_WINDOWS",
                  "alert_action_status": "BLOCKED",
                  "alert_category": "Malware",
                  "alert_description": "Suspicious executable detected",
                  "alert_name": "WildFire Malware",
                  "alert_source": "TRAPS",
                  "alert_type": "Unclassified",
                  "attachment": None,
                  "category": "",
                  "causality_actor_process_signature_status": [
                    "SIGNATURE_UNAVAILABLE"
                  ],
                  "closeReason": "",
                  "closed": "0001-01-01T00:00:00Z",
                  "closingUserId": "",
                  "contains_featured_host": [
                    "NO"
                  ],
                  "contains_featured_ip": [
                    "NO"
                  ],
                  "contains_featured_user": [
                    "NO"
                  ],
                  "dbotCurrentDirtyFields": None,
                  "dbotDirtyFields": None,
                  "dbotMirrorDirection": "",
                  "dbotMirrorId": "",
                  "dbotMirrorInstance": "",
                  "dbotMirrorLastSync": "0001-01-01T00:00:00Z",
                  "dbotMirrorTags": None,
                  "droppedCount": 0,
                  "dueDate": "0001-01-01T00:00:00Z",
                  "event_type": [
                    1
                  ],
                  "feedBased": False,
                  "fw_is_phishing": [
                    "NOT_AVAILABLE"
                  ],
                  "internal_id": 14863,
                  "investigationId": "14863",
                  "isDebug": False,
                  "is_whitelisted": False,
                  "labels": None,
                  "lastJobRunTime": "0001-01-01T00:00:00Z",
                  "lastOpen": "0001-01-01T00:00:00Z",
                  "linkedCount": 0,
                  "linkedIncidents": None,
                  "mac": "00:50:56:9f:f5:5f",
                  "module_id": [
                    "WildFire"
                  ],
                  "notifyTime": "0001-01-01T00:00:00Z",
                  "occurred": "0001-01-01T00:00:00Z",
                  "openDuration": 0,
                  "os_actor_process_signature_status": [
                    "SIGNATURE_UNAVAILABLE"
                  ],
                  "phase": "",
                  "playbookId": "f1fa9cef-75be-429e-8d16-e29350af29a9",
                  "reason": "",
                  "reminder": "0001-01-01T00:00:00Z",
                  "resolution_comment": "",
                  "resolution_status": "STATUS_020_UNDER_INVESTIGATION",
                  "runStatus": "pending",
                  "severity": "SEV_030_MEDIUM",
                  "sla": 0,
                  "sourceInstance": "",
                  "source_insert_ts": 1674658129127,
                  "starred": False
                },
                "email": None,
                "emailaddress": None,
                "emailauthenticitycheck": None,
                "emailbcc": None,
                "emailbody": None,
                "emailbodyformat": None,
                "emailbodyhtml": None,
                "emailcampaigncanvas": None,
                "emailcampaignmutualindicators": None,
                "emailcampaignsnippets": None,
                "emailcampaignsummary": None,
                "emailcc": None,
                "emailclassification": None,
                "emailclientname": None,
                "emaildeletefrombrand": None,
                "emaildeletereason": None,
                "emaildeleteresult": None,
                "emaildeletetype": None,
                "emailheaders": None,
                "emailhtml": None,
                "emailhtmlimage": None,
                "emailinreplyto": None,
                "emailinternalmessageid": None,
                "emailkeywords": None,
                "emaillabels": None,
                "emaillatestmessage": None,
                "emailmessageid": None,
                "emailreceived": None,
                "emailrecipientscount": None,
                "emailreplyto": None,
                "emailreturnpath": None,
                "emailsenderip": None,
                "emailsentsuccessfully": False,
                "emailsize": None,
                "emailsource": None,
                "emailtocount": None,
                "emailurlclicked": None,
                "employeedisplayname": None,
                "employeeemail": None,
                "employeemanageremail": None,
                "end_match_attempt_ts": None,
                "endpointisolationstatus": None,
                "endtime": None,
                "errorcode": None,
                "errormessage": None,
                "escalation": None,
                "event_id": None,
                "event_sub_type": None,
                "event_timestamp": [
                  1674658095784
                ],
                "event_type": [
                  1
                ],
                "eventaction": None,
                "eventdescriptions": None,
                "eventid": None,
                "eventnames": None,
                "events": [],
                "exposurelevel": None,
                "external_id": "57e81344f4a340538b540c770f36d7aa",
                "externalcategoryid": None,
                "externalcategoryname": None,
                "externalconfidence": None,
                "externalendtime": None,
                "externallink": None,
                "externalseverity": None,
                "externalstarttime": None,
                "externalstatus": None,
                "externalsubcategoryid": None,
                "externalsubcategoryname": None,
                "externalsystemid": None,
                "family_tags": [
                  "DS:PANW/XDR Agent"
                ],
                "feedBased": False,
                "feedbased": False,
                "fileaccessdate": None,
                "filecreationdate": None,
                "filehash": None,
                "filerelationships": None,
                "filesha1": None,
                "filesize": None,
                "filter_rule_id": None,
                "financialinformationbreached": None,
                "fireeyealertinfectionid": None,
                "fireeyealertmalicious": None,
                "fireeyealertvlan": None,
                "fireeyec2address": None,
                "fireeyec2channel": None,
                "fireeyec2host": None,
                "fireeyeemailqueueid": None,
                "fireeyeemailsourcedomain": None,
                "fireeyefireeyedownloadat": None,
                "fireeyeinfectionid": None,
                "fireeyeinfectionurl": None,
                "fireeyemalwareinfo": None,
                "fireeyemalwareinformation": None,
                "fireeyematchcount": None,
                "fireeyematchedtime": None,
                "fireeyenxalertaction": None,
                "fireeyenxalertid": None,
                "fireeyenxalertmalwarename": None,
                "fireeyenxalertscversion": None,
                "fireeyenxalerttargetip": None,
                "fireeyenxalerttype": None,
                "fireeyenxalerturl": None,
                "fireeyenxalertuuid": None,
                "fireeyenxalertvictimip": None,
                "fireeyenxeventcveid": None,
                "fireeyenxeventdestinationmacaddress": None,
                "fireeyenxeventid": None,
                "fireeyenxeventrule": None,
                "fireeyenxeventsourcemacaddress": None,
                "fireeyenxeventvictimip": None,
                "fireeyesignatureid": None,
                "fireeyesignaturerevision": None,
                "fireeyesubmittedat": None,
                "firstname": None,
                "firstseen": None,
                "followup": False,
                "forensics_artifact_type": None,
                "from_dml": None,
                "fullname": None,
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
                "fw_is_phishing": [
                  "NOT_AVAILABLE"
                ],
                "fw_misc": None,
                "fw_rule": None,
                "fw_rule_id": None,
                "fw_serial_number": None,
                "fw_url_domain": None,
                "fw_vsys": None,
                "fw_xff": None,
                "genericexportindicatorsserviceaction": None,
                "genericexportindicatorsserviceindicatorslist": None,
                "genericexportindicatorsserviceindicatortype": None,
                "genericexportindicatorsservicetag": None,
                "givenname": None,
                "groupid": None,
                "gsuitesacalertid": None,
                "gsuitesacalertseverity": None,
                "gsuitesacalertsource": None,
                "gsuitesacalertstatus": None,
                "gsuitesacalerttype": None,
                "gsuitesaccreatetime": None,
                "gsuitesaccustomerid": None,
                "gsuitesacdeleted": None,
                "gsuitesacendtime": None,
                "gsuitesacetag": None,
                "gsuitesacfeedbackcreatetime": None,
                "gsuitesacfeedbackemail": None,
                "gsuitesacfeedbackid": None,
                "gsuitesacfeedbacktype": None,
                "gsuitesacsecurityinvestigationtoollink": None,
                "gsuitesacstarttime": None,
                "gsuitesacupdatetime": None,
                "has_alert_layout_data": None,
                "healthinsurancebreached": None,
                "helloworldid": None,
                "helloworldstatus": None,
                "helloworldtype": None,
                "huntresultscount": None,
                "identity_invoked_by_type": None,
                "identity_name": None,
                "identity_sub_type": None,
                "identity_type": None,
                "image_name": None,
                "impacteddevices": None,
                "impactedentities": None,
                "incidentlink": None,
                "incomingmirrorerror": None,
                "individualsnotification": None,
                "internal_id": "14863",
                "internaladdresses": None,
                "investigationId": "14863",
                "investigationstage": None,
                "iot_pivot_url": None,
                "ipblockedstatus": None,
                "ipreputation": None,
                "isDebug": False,
                "is_deleted": None,
                "is_disintegrated": None,
                "is_identity": None,
                "is_pcap": False,
                "is_rule_triggering": False,
                "is_whitelisted": False,
                "is_xdm": None,
                "is_xsoar_alert": False,
                "isactive": None,
                "isolated": None,
                "isthedatasubjecttodpia": None,
                "itemowner": None,
                "itemowneremail": None,
                "jobcode": None,
                "jobfamily": None,
                "jobfunction": None,
                "jobscreated": None,
                "join_next_attempt_time": None,
                "labels": None,
                "lastJobRunTime": "0001-01-01T00:00:00Z",
                "lastOpen": "0001-01-01T00:00:00Z",
                "last_modified_ts": None,
                "lastmodifiedby": None,
                "lastmodifiedon": None,
                "lastname": None,
                "lastseen": None,
                "lastupdatetime": None,
                "leadership": None,
                "likelyimpact": None,
                "linkedCount": 0,
                "linkedcount": None,
                "listofrulesevent": None,
                "listscreated": None,
                "local_insert_ts": 1674658099828,
                "location": None,
                "locationregion": None,
                "logsource": None,
                "logsourcename": None,
                "logsourcetype": None,
                "lowlevelcategoriesevents": None,
                "mac": "00:50:56:9f:f5:5f",
                "macrosourcecode": None,
                "maliciousbehavior": None,
                "maliciouscauseifthecauseisamaliciousattack": None,
                "maliciousurlclicked": None,
                "maliciousurlviewed": None,
                "malwarefamily": None,
                "malwarename": None,
                "managementnotification": None,
                "manageremailaddress": None,
                "managername": None,
                "marketplacepacksinstalled": None,
                "matching_service_rule_id": None,
                "matching_status": "UNMATCHABLE",
                "measurestomitigate": None,
                "medianotification": None,
                "medicalinformationbreached": None,
                "microsoft365defendera": None,
                "microsoft365defenderactive": None,
                "microsoft365defendercategoriescount": None,
                "microsoft365defenderclassification": None,
                "microsoft365defenderdevices": None,
                "microsoft365defenderdisplayname": None,
                "microsoft365defenderfirstactivity": None,
                "microsoft365defenderid": None,
                "microsoft365defenderlastactivity": None,
                "microsoft365defenderstatus": None,
                "microsoftdefenderforendpointevidencecreationtime": None,
                "microsoftdefenderforendpointevidencetype": None,
                "microsoftgraphidentityandaccessactivity": None,
                "microsoftgraphidentityandaccessalerttype": None,
                "microsoftgraphidentityandaccessdetectiontimingtype": None,
                "microsoftgraphidentityandaccesstokenissuertype": None,
                "mitre_tactic_id_and_name": None,
                "mitre_technique_id_and_name": None,
                "mitretacticid": None,
                "mitretacticname": None,
                "mitretechniqueid": None,
                "mitretechniquename": None,
                "mobiledevicemodel": None,
                "mobilephone": None,
                "module_id": [
                  "WildFire"
                ],
                "module_name": [
                  "COMPONENT_WILDFIRE"
                ],
                "notifyTime": "0001-01-01T00:00:00Z",
                "numberoflogsources": None,
                "numberofrelatedincidents": None,
                "numberofsimilarfiles": None,
                "objective": None,
                "occurred": "0001-01-01T00:00:00Z",
                "openDuration": 0,
                "operation_name": None,
                "orglevel1": None,
                "orglevel2": None,
                "orglevel3": None,
                "orgunit": None,
                "original_severity": "SEV_030_MEDIUM",
                "originalalertid": None,
                "originalalertname": None,
                "originalalertsource": None,
                "originaldescription": None,
                "originalevents": None,
                "os": None,
                "os_actor_causality_id": None,
                "os_actor_effective_username": None,
                "os_actor_process_causality_id": None,
                "os_actor_process_command_line": None,
                "os_actor_process_execution_time": None,
                "os_actor_process_image_md5": None,
                "os_actor_process_image_name": None,
                "os_actor_process_image_path": None,
                "os_actor_process_image_sha256": None,
                "os_actor_process_instance_id": None,
                "os_actor_process_os_pid": None,
                "os_actor_process_signature_status": [
                  "SIGNATURE_UNAVAILABLE"
                ],
                "os_actor_process_signature_vendor": None,
                "os_actor_thread_thread_id": None,
                "ostype": None,
                "otherpiidatabreached": None,
                "outgoingmirrorerror": None,
                "owner": None,
                "parentprocesscmd": None,
                "parentprocessfilepath": None,
                "parentprocessid": None,
                "parentprocessids": None,
                "parentprocessmd5": None,
                "parentprocessname": None,
                "parentprocesspath": None,
                "parentprocesssha256": None,
                "partofcampaign": None,
                "passwordchangeddate": None,
                "passwordresetsuccessfully": False,
                "personalemail": None,
                "phase": None,
                "phishingbclscore": None,
                "phishingpclscore": None,
                "phishingreporteremailheaders": None,
                "phishingsclscore": None,
                "phishingsubtype": None,
                "phone_number": None,
                "piidatatype": None,
                "pivot_url": None,
                "playbookId": "f1fa9cef-75be-429e-8d16-e29350af29a9",
                "playbook_suggestion_rule_id": None,
                "playbookid": None,
                "policy_id": None,
                "policyactions": None,
                "policydeleted": None,
                "policydescription": None,
                "policydetails": None,
                "policyid": None,
                "policyrecommendation": None,
                "policyremediable": None,
                "policyseverity": None,
                "policytype": None,
                "policyuri": None,
                "possiblecauseofthebreach": None,
                "postalcode": None,
                "postnatdestinationip": None,
                "postnatdestinationport": None,
                "postnatsourceip": None,
                "postnatsourceport": None,
                "prenatdestinationport": None,
                "prenatsourceip": None,
                "prenatsourceport": None,
                "processcmd": None,
                "processcreationtime": None,
                "processid": None,
                "processmd5": None,
                "processnames": None,
                "processpaths": None,
                "processsha256": None,
                "project": None,
                "protocolnames": None,
                "quarantined": None,
                "query_tables": None,
                "rating": None,
                "rawevent": None,
                "referenced_resource": None,
                "region": None,
                "regionid": None,
                "registryhive": None,
                "registrykey": None,
                "registryvalue": None,
                "registryvaluetype": None,
                "relatedcampaign": None,
                "relatedendpoints": None,
                "relatedreport": None,
                "reminder": "0001-01-01T00:00:00Z",
                "remote_cid": None,
                "renderedhtml": None,
                "reportedemailcc": None,
                "reportedemailfrom": None,
                "reportedemailmessageid": None,
                "reportedemailorigin": None,
                "reportedemailsubject": None,
                "reportedemailto": None,
                "reporteremailaddress": None,
                "residentnotificationoption": None,
                "residentsemailaddress": None,
                "resolution_comment": "",
                "resolution_status": "STATUS_020_UNDER_INVESTIGATION",
                "resolution_status_modified_ts": 1674658129232,
                "resource_sub_type": None,
                "resource_type": None,
                "resourcename": None,
                "resourcetype": None,
                "riskrating": None,
                "riskscore": None,
                "rulename": None,
                "runStatus": "pending",
                "samaccountname": None,
                "scenario": None,
                "secretarynotification": None,
                "sectorofaffectedparty": None,
                "selectedindicators": None,
                "sensorip": None,
                "severity": "SEV_030_MEDIUM",
                "sha1": None,
                "sha512": None,
                "signature": None,
                "similarincidents": None,
                "similarincidentsdbot": None,
                "sizenumberofemployees": None,
                "sizeturnover": None,
                "skuname": None,
                "skutier": None,
                "sla": 0,
                "source_insert_ts": 1674658095784,
                "sourcecategory": None,
                "sourcecreatedby": None,
                "sourcecreatetime": None,
                "sourceexternalips": None,
                "sourcegeolocation": None,
                "sourceid": None,
                "sourceinstance": None,
                "sourcenetworks": None,
                "sourcepriority": None,
                "sourcestatus": None,
                "sourceupdatedby": None,
                "sourceurgency": None,
                "srcos": None,
                "ssdeep": None,
                "starred": False,
                "starttime": None,
                "state": None,
                "statecisonotification": None,
                "statewherethebreachtookplace": None,
                "story_id": None,
                "streetaddress": None,
                "subcategory": None,
                "subtype": None,
                "suggested_playbook_id": None,
                "surname": None,
                "tactic": None,
                "tacticid": None,
                "tags": [
                  "DS:PANW/XDR Agent"
                ],
                "target": None,
                "targetfirewallversion": None,
                "teamname": None,
                "technicalowner": None,
                "technicalownercontact": None,
                "technicaluser": None,
                "technique": None,
                "techniqueid": None,
                "telephoneno": None,
                "tenantname": None,
                "terminatedaction": None,
                "threatactor": None,
                "threatfamilyname": None,
                "threatname": None,
                "ticketacknowledgeddate": None,
                "ticketcloseddate": None,
                "ticketnumber": None,
                "tim_main_indicator": None,
                "timezone": None,
                "title": None,
                "totalmaliciousurlsclicks": None,
                "trafficdirection": None,
                "triggeredsecurityprofile": None,
                "uniquebiometricdatabreached": None,
                "uniqueidentificationnumberbreached": None,
                "uniqueports": None,
                "urls": None,
                "urlsslverification": None,
                "usecasedescription": None,
                "user_agent": None,
                "useraccountcontrol": None,
                "usercreationtime": None,
                "userengagementresponse": None,
                "userid": None,
                "usersid": None,
                "uuid": None,
                "values_changed": None,
                "vendorid": None,
                "vendorproduct": None,
                "verdict": None,
                "verificationmethod": None,
                "verificationstatus": None,
                "vulnerabilitycategory": None,
                "whereisdatahosted": None,
                "workphone": None,
                "xdr_additional_info": None,
                "xpanse_asset_id": None,
                "xpanse_asset_name": None,
                "xpanse_first_observed": None,
                "xpanse_policy_id": None,
                "xpanse_primary_asset_id": None,
                "xpanse_service_id": None,
                "xpanse_website_id": None,
                "zipcode": None
              },
              "incident_fields": None
            },
            {
              "alert_fields": {
                "accountid": None,
                "accountinformationbreached": None,
                "accountmemberof": None,
                "accountstatus": None,
                "acquisitionhire": None,
                "action_country": [
                  "UNKNOWN"
                ],
                "action_external_hostname": None,
                "action_file_macro_sha256": None,
                "action_file_md5": None,
                "action_file_name": None,
                "action_file_path": None,
                "action_file_sha256": None,
                "action_local_ip": None,
                "action_local_ip_v6": None,
                "action_local_port": None,
                "action_process_causality_id": None,
                "action_process_image_command_line": None,
                "action_process_image_md5": None,
                "action_process_image_name": None,
                "action_process_image_path": None,
                "action_process_image_sha256": None,
                "action_process_instance_id": None,
                "action_process_os_pid": None,
                "action_process_signature_status": [
                  "SIGNATURE_UNAVAILABLE"
                ],
                "action_process_signature_vendor": None,
                "action_process_user_sid": None,
                "action_registry_data": None,
                "action_registry_full_key": None,
                "action_registry_key_name": None,
                "action_registry_value_name": None,
                "action_remote_ip": None,
                "action_remote_ip_v6": None,
                "action_remote_port": None,
                "activated": "0001-01-01T00:00:00Z",
                "activity_first_seen_at": None,
                "activity_last_seen_at": None,
                "actor_causality_id": None,
                "actor_effective_user_sid": None,
                "actor_effective_username": [
                  "env4.local\\Administrator"
                ],
                "actor_process_causality_id": None,
                "actor_process_command_line": [
                  "\"C:\\Users\\administrator.ENV4\\Downloads\\8872362056\\000001e7a228b2a7abdfa4b3c8522df32b725e86907dde32176bccbbbb27.exe\" "
                ],
                "actor_process_execution_time": None,
                "actor_process_image_md5": [
                  "e9aaa45159dacbc596ebefb6311eae54"
                ],
                "actor_process_image_name": [
                  "000001e7a228b2a7abdf7f7e40313324332b725e86907dde32176bccbbbb27.exe"
                ],
                "actor_process_image_path": [
                  "C:\\Users\\administrator.ENV4\\Downloads\\8872362056\\000001e7a228b2a7abdf7f7e40313324332b725e86907dde32176bccbbbb27.exe"
                ],
                "actor_process_image_sha256": [
                  "000001e7a228b2a7abdf7f7e40313324332b725e86907dde32176bccbbbb27"
                ],
                "actor_process_instance_id": [
                  "AdkwxLhiKM4AABJsAAAAAA=="
                ],
                "actor_process_os_pid": [
                  4716
                ],
                "actor_process_signature_status": [
                  "SIGNATURE_UNAVAILABLE"
                ],
                "actor_process_signature_vendor": None,
                "actor_thread_thread_id": None,
                "additionaldata": None,
                "additionalindicators": None,
                "affecteddata": None,
                "affecteddatatype": None,
                "affectedindividualscontactinformation": None,
                "agent_data_collection_status": False,
                "agent_device_domain": "env4.local",
                "agent_file_md5": None,
                "agent_file_path": None,
                "agent_fqdn": "DC1ENV4APC01.env4.local",
                "agent_host_boot_time": None,
                "agent_hostname": "DC1ENV4APC01",
                "agent_id": "ac848acbd7504115b6624c9b1d755000",
                "agent_install_type": "STANDARD",
                "agent_ip_addresses": [
                  "172.16.4.122"
                ],
                "agent_ip_addresses_v6": None,
                "agent_is_vdi": None,
                "agent_os_sub_type": "10.0.19044",
                "agent_os_type": "AGENT_OS_WINDOWS",
                "agent_version": "7.9.0.20664",
                "agentsid": None,
                "agentversion": None,
                "alert_action_status": "BLOCKED",
                "alert_action_status_readable": "prevented (blocked)",
                "alert_category": "Malware",
                "alert_description": "Suspicious executable detected",
                "alert_description_raw": "Suspicious executable detected",
                "alert_ingest_status": None,
                "alert_is_fp": False,
                "alert_json": None,
                "alert_name": "WildFire Malware",
                "alert_source": "TRAPS",
                "alert_sub_type": None,
                "alert_type": "Unclassified",
                "alertacknowledgement": None,
                "alertaction": None,
                "alertmalicious": None,
                "alerttypeid": None,
                "analysisreport": None,
                "appchannelname": None,
                "applicationpath": None,
                "appmessage": None,
                "approvalstatus": None,
                "approver": None,
                "approximatenumberofaffecteddatasubjects": None,
                "asmalertsummary": None,
                "asmcloud": None,
                "asmdatacollection": None,
                "asmdevcheck": False,
                "asmnotification": None,
                "asmprivateip": None,
                "asmrelated": None,
                "asmremediation": None,
                "asmremediationpathrule": None,
                "asmservicedetection": None,
                "asmserviceowner": None,
                "asmserviceownerunrankedraw": None,
                "asmsystemids": None,
                "asmtags": None,
                "asn": None,
                "asnname": None,
                "asset_service_id": None,
                "assetid": None,
                "assigneduser": None,
                "assignmentgroup": None,
                "association_strength": [
                  50
                ],
                "attachment": None,
                "attachmentcount": None,
                "attachmentextension": None,
                "attachmenthash": None,
                "attachmentid": None,
                "attachmentname": None,
                "attachmentsize": None,
                "attachmenttype": None,
                "attack_techniques": None,
                "attackmode": None,
                "attempt_counter": 0,
                "attorneygeneralnotification": None,
                "audit_ids": None,
                "awsarn": None,
                "awsguarddutyaccesskeydetails": None,
                "awsguarddutyconfidencescore": None,
                "awsguarddutycontainerdetails": None,
                "awsguarddutyebsvolumedetails": None,
                "awsguarddutyecsclusterdetails": None,
                "awsguarddutyeksclusterdetails": None,
                "awsguarddutyiaminstanceprofile": None,
                "awsguarddutyinstancedetails": None,
                "awsguarddutykubernetesuserdetails": None,
                "awsguarddutykubernetesworkloaddetails": None,
                "awsguarddutynetworkinterface": None,
                "awsguarddutypartition": None,
                "awsguarddutyresourcetype": None,
                "awsguarddutys3bucketdetails": None,
                "awsguarddutyschemaversion": None,
                "awsguarddutyservice": None,
                "awsguarddutytype": None,
                "bioc_category_enum_key": None,
                "bioc_indicator": None,
                "birthday": None,
                "blockedaction": None,
                "branchname": None,
                "breachconfirmation": None,
                "bugtraq": None,
                "caller": None,
                "caller_ip": None,
                "case_id": 72,
                "category": None,
                "categorycount": None,
                "causality_actor_causality_id": None,
                "causality_actor_process_command_line": None,
                "causality_actor_process_execution_time": None,
                "causality_actor_process_image_md5": None,
                "causality_actor_process_image_name": None,
                "causality_actor_process_image_path": None,
                "causality_actor_process_image_sha256": None,
                "causality_actor_process_instance_id": None,
                "causality_actor_process_os_pid": None,
                "causality_actor_process_signature_status": [
                  "SIGNATURE_UNAVAILABLE"
                ],
                "causality_actor_process_signature_vendor": None,
                "changed": None,
                "cicdbranch": None,
                "cicdpackname": None,
                "cicdpullrequestbranch": None,
                "cicdpullrequestcomment": None,
                "cicdpullrequestlink": None,
                "cicdpullrequestreview": None,
                "cicdpullrequesttitle": None,
                "cicdreviewer": None,
                "cicds3bucketname": None,
                "city": None,
                "classification": None,
                "clickedurls": None,
                "closed": "0001-01-01T00:00:00Z",
                "closereason": None,
                "closetime": None,
                "closingreason": None,
                "closinguser": None,
                "closinguserid": None,
                "cloud_provider": None,
                "cloudaccountid": None,
                "cloudinstanceid": None,
                "cloudregionlist": None,
                "cloudresourcelist": None,
                "cloudservice": None,
                "cluster_name": None,
                "comment": None,
                "companyaddress": None,
                "companycity": None,
                "companyhasinsuranceforthebreach": None,
                "companyname": None,
                "companypostalcode": None,
                "compliancenotes": None,
                "configfilepath": None,
                "configurationfilesource": None,
                "consumerreportingagenciesnotification": None,
                "contactaddress": None,
                "contactemailaddress": None,
                "contactname": None,
                "contacttelephonenumber": None,
                "container_id": None,
                "contains_featured_host": [
                  "NO"
                ],
                "contains_featured_ip": [
                  "NO"
                ],
                "contains_featured_user": [
                  "NO"
                ],
                "costcenter": None,
                "costcentercode": None,
                "countrycode": None,
                "countrycodenumber": None,
                "countrywherebusinesshasitsmainestablishment": None,
                "criticalassets": None,
                "custompacksinstalled": None,
                "custompackssource": None,
                "cve": None,
                "cvelist": None,
                "cvss": None,
                "cvssavailabilityrequirement": None,
                "cvsscollateraldamagepotential": None,
                "cvssconfidentialityrequirement": None,
                "cvssintegrityrequirement": None,
                "dataencryptionstatus": None,
                "dbotMirrorLastSync": "0001-01-01T00:00:00Z",
                "dbotclosed": None,
                "dbotduedate": None,
                "dbotmirrordirection": None,
                "dbotmirrorid": None,
                "dbotmirrorinstance": None,
                "dbotmirrorlastsync": None,
                "dbotmodified": None,
                "dbotprediction": None,
                "dbotpredictionprobability": None,
                "dbotstatus": None,
                "dbottextsuggestionhighlighted": None,
                "dbottotaltime": None,
                "deduplicate_tokens": None,
                "department": None,
                "destinationgeolocation": None,
                "destinationipv6": None,
                "destinationnetworks": None,
                "destos": None,
                "detectedendpoints": None,
                "detectedexternalips": None,
                "detectedinternalhosts": None,
                "detection_modules": None,
                "detectionendtime": None,
                "detectionid": None,
                "detectionurl": None,
                "deviceexternalips": None,
                "devicehash": None,
                "deviceid": None,
                "deviceinternalips": None,
                "devicemacaddress": None,
                "devicemodel": None,
                "devicename": None,
                "deviceosname": None,
                "deviceosversion": None,
                "deviceou": None,
                "devicestatus": None,
                "devicetime": None,
                "displayname": None,
                "dns_query_name": None,
                "domainname": None,
                "domainsquattingresult": None,
                "dpoemailaddress": None,
                "dponotification": None,
                "drilldown_max_ts": None,
                "drilldown_min_ts": None,
                "drilldown_query": None,
                "droppedCount": 0,
                "droppedcount": None,
                "dst_action_country": None,
                "dst_action_external_hostname": None,
                "dst_action_external_port": None,
                "dst_actor_process_image_name": None,
                "dst_actor_process_os_pid": None,
                "dst_agent_hostname": None,
                "dst_agent_id": None,
                "dst_agent_id_single": None,
                "dst_agent_os_type": [
                  "NO_HOST"
                ],
                "dst_association_strength": None,
                "dst_causality_actor_process_execution_time": None,
                "dst_os_actor_process_image_name": None,
                "dst_os_actor_process_os_pid": None,
                "dsts": None,
                "dueDate": "0001-01-01T00:00:00Z",
                "duration": None,
                "dynamic_fields": {
                  "action_country": [
                    "UNKNOWN"
                  ],
                  "action_process_signature_status": [
                    "SIGNATURE_UNAVAILABLE"
                  ],
                  "activated": "0001-01-01T00:00:00Z",
                  "activatingingUserId": "",
                  "actor_effective_username": [
                    "env4.local\\Administrator"
                  ],
                  "actor_process_command_line": [
                    "\"C:\\Users\\administrator.ENV4\\Downloads\\8872362056\\000001e7a228b2a7abdf7f7e40313324332b725e86907dde32176bccbbbb27.exe\" "
                  ],
                  "actor_process_image_md5": [
                    "e9aaa45159dacbc596ebefb6311eae54"
                  ],
                  "actor_process_image_name": [
                    "000001e7a228b2a7abdf7f7e40313324332b725e86907dde32176bccbbbb27.exe"
                  ],
                  "actor_process_image_path": [
                    "C:\\Users\\administrator.ENV4\\Downloads\\8872362056\\000001e7a228b2a7abdf7f7e40313324332b725e86907dde32176bccbbbb27.exe"
                  ],
                  "actor_process_image_sha256": [
                    "000001e7a228b2a7abdf7f7e40313324332b725e86907dde32176bccbbbb27"
                  ],
                  "actor_process_os_pid": [
                    4716
                  ],
                  "actor_process_signature_status": [
                    "SIGNATURE_UNAVAILABLE"
                  ],
                  "agent_device_domain": "env4.local",
                  "agent_fqdn": "DC1ENV4APC01.env4.local",
                  "agent_hostname": "DC1ENV4APC01",
                  "agent_id": "ac848acbd7504115b6624c9b1d755000",
                  "agent_ip_addresses": [
                    "172.16.4.122"
                  ],
                  "agent_os_sub_type": "10.0.19044",
                  "agent_os_type": "AGENT_OS_WINDOWS",
                  "alert_action_status": "BLOCKED",
                  "alert_category": "Malware",
                  "alert_description": "Suspicious executable detected",
                  "alert_name": "WildFire Malware",
                  "alert_source": "TRAPS",
                  "alert_type": "Unclassified",
                  "attachment": None,
                  "category": "",
                  "causality_actor_process_signature_status": [
                    "SIGNATURE_UNAVAILABLE"
                  ],
                  "closeReason": "",
                  "closed": "0001-01-01T00:00:00Z",
                  "closingUserId": "",
                  "contains_featured_host": [
                    "NO"
                  ],
                  "contains_featured_ip": [
                    "NO"
                  ],
                  "contains_featured_user": [
                    "NO"
                  ],
                  "dbotCurrentDirtyFields": None,
                  "dbotDirtyFields": None,
                  "dbotMirrorDirection": "",
                  "dbotMirrorId": "",
                  "dbotMirrorInstance": "",
                  "dbotMirrorLastSync": "0001-01-01T00:00:00Z",
                  "dbotMirrorTags": None,
                  "droppedCount": 0,
                  "dueDate": "0001-01-01T00:00:00Z",
                  "event_type": [
                    1
                  ],
                  "feedBased": False,
                  "fw_is_phishing": [
                    "NOT_AVAILABLE"
                  ],
                  "internal_id": 14862,
                  "investigationId": "14862",
                  "isDebug": False,
                  "is_whitelisted": False,
                  "labels": None,
                  "lastJobRunTime": "0001-01-01T00:00:00Z",
                  "lastOpen": "0001-01-01T00:00:00Z",
                  "linkedCount": 0,
                  "linkedIncidents": None,
                  "mac": "00:50:56:9f:f5:5f",
                  "module_id": [
                    "WildFire"
                  ],
                  "notifyTime": "0001-01-01T00:00:00Z",
                  "occurred": "0001-01-01T00:00:00Z",
                  "openDuration": 0,
                  "os_actor_process_signature_status": [
                    "SIGNATURE_UNAVAILABLE"
                  ],
                  "phase": "",
                  "playbookId": "f1fa9cef-75be-429e-8d16-e29350af29a9",
                  "reason": "",
                  "reminder": "0001-01-01T00:00:00Z",
                  "resolution_comment": "",
                  "resolution_status": "STATUS_020_UNDER_INVESTIGATION",
                  "runStatus": "pending",
                  "severity": "SEV_030_MEDIUM",
                  "sla": 0,
                  "sourceInstance": "",
                  "source_insert_ts": 1674655039367,
                  "starred": False
                },
                "email": None,
                "emailaddress": None,
                "emailauthenticitycheck": None,
                "emailbcc": None,
                "emailbody": None,
                "emailbodyformat": None,
                "emailbodyhtml": None,
                "emailcampaigncanvas": None,
                "emailcampaignmutualindicators": None,
                "emailcampaignsnippets": None,
                "emailcampaignsummary": None,
                "emailcc": None,
                "emailclassification": None,
                "emailclientname": None,
                "emaildeletefrombrand": None,
                "emaildeletereason": None,
                "emaildeleteresult": None,
                "emaildeletetype": None,
                "emailheaders": None,
                "emailhtml": None,
                "emailhtmlimage": None,
                "emailinreplyto": None,
                "emailinternalmessageid": None,
                "emailkeywords": None,
                "emaillabels": None,
                "emaillatestmessage": None,
                "emailmessageid": None,
                "emailreceived": None,
                "emailrecipientscount": None,
                "emailreplyto": None,
                "emailreturnpath": None,
                "emailsenderip": None,
                "emailsentsuccessfully": False,
                "emailsize": None,
                "emailsource": None,
                "emailtocount": None,
                "emailurlclicked": None,
                "employeedisplayname": None,
                "employeeemail": None,
                "employeemanageremail": None,
                "end_match_attempt_ts": None,
                "endpointisolationstatus": None,
                "endtime": None,
                "errorcode": None,
                "errormessage": None,
                "escalation": None,
                "event_id": None,
                "event_sub_type": None,
                "event_timestamp": [
                  1674655027190
                ],
                "event_type": [
                  1
                ],
                "eventaction": None,
                "eventdescriptions": None,
                "eventid": None,
                "eventnames": None,
                "events": [],
                "exposurelevel": None,
                "external_id": "4ee579e1cbe4495280e536bd6d6ca866",
                "externalcategoryid": None,
                "externalcategoryname": None,
                "externalconfidence": None,
                "externalendtime": None,
                "externallink": None,
                "externalseverity": None,
                "externalstarttime": None,
                "externalstatus": None,
                "externalsubcategoryid": None,
                "externalsubcategoryname": None,
                "externalsystemid": None,
                "family_tags": [
                  "DS:PANW/XDR Agent"
                ],
                "feedBased": False,
                "feedbased": False,
                "fileaccessdate": None,
                "filecreationdate": None,
                "filehash": None,
                "filerelationships": None,
                "filesha1": None,
                "filesize": None,
                "filter_rule_id": None,
                "financialinformationbreached": None,
                "fireeyealertinfectionid": None,
                "fireeyealertmalicious": None,
                "fireeyealertvlan": None,
                "fireeyec2address": None,
                "fireeyec2channel": None,
                "fireeyec2host": None,
                "fireeyeemailqueueid": None,
                "fireeyeemailsourcedomain": None,
                "fireeyefireeyedownloadat": None,
                "fireeyeinfectionid": None,
                "fireeyeinfectionurl": None,
                "fireeyemalwareinfo": None,
                "fireeyemalwareinformation": None,
                "fireeyematchcount": None,
                "fireeyematchedtime": None,
                "fireeyenxalertaction": None,
                "fireeyenxalertid": None,
                "fireeyenxalertmalwarename": None,
                "fireeyenxalertscversion": None,
                "fireeyenxalerttargetip": None,
                "fireeyenxalerttype": None,
                "fireeyenxalerturl": None,
                "fireeyenxalertuuid": None,
                "fireeyenxalertvictimip": None,
                "fireeyenxeventcveid": None,
                "fireeyenxeventdestinationmacaddress": None,
                "fireeyenxeventid": None,
                "fireeyenxeventrule": None,
                "fireeyenxeventsourcemacaddress": None,
                "fireeyenxeventvictimip": None,
                "fireeyesignatureid": None,
                "fireeyesignaturerevision": None,
                "fireeyesubmittedat": None,
                "firstname": None,
                "firstseen": None,
                "followup": False,
                "forensics_artifact_type": None,
                "from_dml": None,
                "fullname": None,
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
                "fw_is_phishing": [
                  "NOT_AVAILABLE"
                ],
                "fw_misc": None,
                "fw_rule": None,
                "fw_rule_id": None,
                "fw_serial_number": None,
                "fw_url_domain": None,
                "fw_vsys": None,
                "fw_xff": None,
                "genericexportindicatorsserviceaction": None,
                "genericexportindicatorsserviceindicatorslist": None,
                "genericexportindicatorsserviceindicatortype": None,
                "genericexportindicatorsservicetag": None,
                "givenname": None,
                "groupid": None,
                "gsuitesacalertid": None,
                "gsuitesacalertseverity": None,
                "gsuitesacalertsource": None,
                "gsuitesacalertstatus": None,
                "gsuitesacalerttype": None,
                "gsuitesaccreatetime": None,
                "gsuitesaccustomerid": None,
                "gsuitesacdeleted": None,
                "gsuitesacendtime": None,
                "gsuitesacetag": None,
                "gsuitesacfeedbackcreatetime": None,
                "gsuitesacfeedbackemail": None,
                "gsuitesacfeedbackid": None,
                "gsuitesacfeedbacktype": None,
                "gsuitesacsecurityinvestigationtoollink": None,
                "gsuitesacstarttime": None,
                "gsuitesacupdatetime": None,
                "has_alert_layout_data": None,
                "healthinsurancebreached": None,
                "helloworldid": None,
                "helloworldstatus": None,
                "helloworldtype": None,
                "huntresultscount": None,
                "identity_invoked_by_type": None,
                "identity_name": None,
                "identity_sub_type": None,
                "identity_type": None,
                "image_name": None,
                "impacteddevices": None,
                "impactedentities": None,
                "incidentlink": None,
                "incomingmirrorerror": None,
                "individualsnotification": None,
                "internal_id": "14862",
                "internaladdresses": None,
                "investigationId": "14862",
                "investigationstage": None,
                "iot_pivot_url": None,
                "ipblockedstatus": None,
                "ipreputation": None,
                "isDebug": False,
                "is_deleted": None,
                "is_disintegrated": None,
                "is_identity": None,
                "is_pcap": False,
                "is_rule_triggering": False,
                "is_whitelisted": False,
                "is_xdm": None,
                "is_xsoar_alert": False,
                "isactive": None,
                "isolated": None,
                "isthedatasubjecttodpia": None,
                "itemowner": None,
                "itemowneremail": None,
                "jobcode": None,
                "jobfamily": None,
                "jobfunction": None,
                "jobscreated": None,
                "join_next_attempt_time": None,
                "labels": None,
                "lastJobRunTime": "0001-01-01T00:00:00Z",
                "lastOpen": "0001-01-01T00:00:00Z",
                "last_modified_ts": None,
                "lastmodifiedby": None,
                "lastmodifiedon": None,
                "lastname": None,
                "lastseen": None,
                "lastupdatetime": None,
                "leadership": None,
                "likelyimpact": None,
                "linkedCount": 0,
                "linkedcount": None,
                "listofrulesevent": None,
                "listscreated": None,
                "local_insert_ts": 1674655034860,
                "location": None,
                "locationregion": None,
                "logsource": None,
                "logsourcename": None,
                "logsourcetype": None,
                "lowlevelcategoriesevents": None,
                "mac": "00:50:56:9f:f5:5f",
                "macrosourcecode": None,
                "maliciousbehavior": None,
                "maliciouscauseifthecauseisamaliciousattack": None,
                "maliciousurlclicked": None,
                "maliciousurlviewed": None,
                "malwarefamily": None,
                "malwarename": None,
                "managementnotification": None,
                "manageremailaddress": None,
                "managername": None,
                "marketplacepacksinstalled": None,
                "matching_service_rule_id": None,
                "matching_status": "UNMATCHABLE",
                "measurestomitigate": None,
                "medianotification": None,
                "medicalinformationbreached": None,
                "microsoft365defendera": None,
                "microsoft365defenderactive": None,
                "microsoft365defendercategoriescount": None,
                "microsoft365defenderclassification": None,
                "microsoft365defenderdevices": None,
                "microsoft365defenderdisplayname": None,
                "microsoft365defenderfirstactivity": None,
                "microsoft365defenderid": None,
                "microsoft365defenderlastactivity": None,
                "microsoft365defenderstatus": None,
                "microsoftdefenderforendpointevidencecreationtime": None,
                "microsoftdefenderforendpointevidencetype": None,
                "microsoftgraphidentityandaccessactivity": None,
                "microsoftgraphidentityandaccessalerttype": None,
                "microsoftgraphidentityandaccessdetectiontimingtype": None,
                "microsoftgraphidentityandaccesstokenissuertype": None,
                "mitre_tactic_id_and_name": None,
                "mitre_technique_id_and_name": None,
                "mitretacticid": None,
                "mitretacticname": None,
                "mitretechniqueid": None,
                "mitretechniquename": None,
                "mobiledevicemodel": None,
                "mobilephone": None,
                "module_id": [
                  "WildFire"
                ],
                "module_name": [
                  "COMPONENT_WILDFIRE"
                ],
                "notifyTime": "0001-01-01T00:00:00Z",
                "numberoflogsources": None,
                "numberofrelatedincidents": None,
                "numberofsimilarfiles": None,
                "objective": None,
                "occurred": "0001-01-01T00:00:00Z",
                "openDuration": 0,
                "operation_name": None,
                "orglevel1": None,
                "orglevel2": None,
                "orglevel3": None,
                "orgunit": None,
                "original_severity": "SEV_030_MEDIUM",
                "originalalertid": None,
                "originalalertname": None,
                "originalalertsource": None,
                "originaldescription": None,
                "originalevents": None,
                "os": None,
                "os_actor_causality_id": None,
                "os_actor_effective_username": None,
                "os_actor_process_causality_id": None,
                "os_actor_process_command_line": None,
                "os_actor_process_execution_time": None,
                "os_actor_process_image_md5": None,
                "os_actor_process_image_name": None,
                "os_actor_process_image_path": None,
                "os_actor_process_image_sha256": None,
                "os_actor_process_instance_id": None,
                "os_actor_process_os_pid": None,
                "os_actor_process_signature_status": [
                  "SIGNATURE_UNAVAILABLE"
                ],
                "os_actor_process_signature_vendor": None,
                "os_actor_thread_thread_id": None,
                "ostype": None,
                "otherpiidatabreached": None,
                "outgoingmirrorerror": None,
                "owner": None,
                "parentprocesscmd": None,
                "parentprocessfilepath": None,
                "parentprocessid": None,
                "parentprocessids": None,
                "parentprocessmd5": None,
                "parentprocessname": None,
                "parentprocesspath": None,
                "parentprocesssha256": None,
                "partofcampaign": None,
                "passwordchangeddate": None,
                "passwordresetsuccessfully": False,
                "personalemail": None,
                "phase": None,
                "phishingbclscore": None,
                "phishingpclscore": None,
                "phishingreporteremailheaders": None,
                "phishingsclscore": None,
                "phishingsubtype": None,
                "phone_number": None,
                "piidatatype": None,
                "pivot_url": None,
                "playbookId": "f1fa9cef-75be-429e-8d16-e29350af29a9",
                "playbook_suggestion_rule_id": None,
                "playbookid": None,
                "policy_id": None,
                "policyactions": None,
                "policydeleted": None,
                "policydescription": None,
                "policydetails": None,
                "policyid": None,
                "policyrecommendation": None,
                "policyremediable": None,
                "policyseverity": None,
                "policytype": None,
                "policyuri": None,
                "possiblecauseofthebreach": None,
                "postalcode": None,
                "postnatdestinationip": None,
                "postnatdestinationport": None,
                "postnatsourceip": None,
                "postnatsourceport": None,
                "prenatdestinationport": None,
                "prenatsourceip": None,
                "prenatsourceport": None,
                "processcmd": None,
                "processcreationtime": None,
                "processid": None,
                "processmd5": None,
                "processnames": None,
                "processpaths": None,
                "processsha256": None,
                "project": None,
                "protocolnames": None,
                "quarantined": None,
                "query_tables": None,
                "rating": None,
                "rawevent": None,
                "referenced_resource": None,
                "region": None,
                "regionid": None,
                "registryhive": None,
                "registrykey": None,
                "registryvalue": None,
                "registryvaluetype": None,
                "relatedcampaign": None,
                "relatedendpoints": None,
                "relatedreport": None,
                "reminder": "0001-01-01T00:00:00Z",
                "remote_cid": None,
                "renderedhtml": None,
                "reportedemailcc": None,
                "reportedemailfrom": None,
                "reportedemailmessageid": None,
                "reportedemailorigin": None,
                "reportedemailsubject": None,
                "reportedemailto": None,
                "reporteremailaddress": None,
                "residentnotificationoption": None,
                "residentsemailaddress": None,
                "resolution_comment": "",
                "resolution_status": "STATUS_020_UNDER_INVESTIGATION",
                "resolution_status_modified_ts": 1674655039472,
                "resource_sub_type": None,
                "resource_type": None,
                "resourcename": None,
                "resourcetype": None,
                "riskrating": None,
                "riskscore": None,
                "rulename": None,
                "runStatus": "pending",
                "samaccountname": None,
                "scenario": None,
                "secretarynotification": None,
                "sectorofaffectedparty": None,
                "selectedindicators": None,
                "sensorip": None,
                "severity": "SEV_030_MEDIUM",
                "sha1": None,
                "sha512": None,
                "signature": None,
                "similarincidents": None,
                "similarincidentsdbot": None,
                "sizenumberofemployees": None,
                "sizeturnover": None,
                "skuname": None,
                "skutier": None,
                "sla": 0,
                "source_insert_ts": 1674655027190,
                "sourcecategory": None,
                "sourcecreatedby": None,
                "sourcecreatetime": None,
                "sourceexternalips": None,
                "sourcegeolocation": None,
                "sourceid": None,
                "sourceinstance": None,
                "sourcenetworks": None,
                "sourcepriority": None,
                "sourcestatus": None,
                "sourceupdatedby": None,
                "sourceurgency": None,
                "srcos": None,
                "ssdeep": None,
                "starred": False,
                "starttime": None,
                "state": None,
                "statecisonotification": None,
                "statewherethebreachtookplace": None,
                "story_id": None,
                "streetaddress": None,
                "subcategory": None,
                "subtype": None,
                "suggested_playbook_id": None,
                "surname": None,
                "tactic": None,
                "tacticid": None,
                "tags": [
                  "DS:PANW/XDR Agent"
                ],
                "target": None,
                "targetfirewallversion": None,
                "teamname": None,
                "technicalowner": None,
                "technicalownercontact": None,
                "technicaluser": None,
                "technique": None,
                "techniqueid": None,
                "telephoneno": None,
                "tenantname": None,
                "terminatedaction": None,
                "threatactor": None,
                "threatfamilyname": None,
                "threatname": None,
                "ticketacknowledgeddate": None,
                "ticketcloseddate": None,
                "ticketnumber": None,
                "tim_main_indicator": None,
                "timezone": None,
                "title": None,
                "totalmaliciousurlsclicks": None,
                "trafficdirection": None,
                "triggeredsecurityprofile": None,
                "uniquebiometricdatabreached": None,
                "uniqueidentificationnumberbreached": None,
                "uniqueports": None,
                "urls": None,
                "urlsslverification": None,
                "usecasedescription": None,
                "user_agent": None,
                "useraccountcontrol": None,
                "usercreationtime": None,
                "userengagementresponse": None,
                "userid": None,
                "usersid": None,
                "uuid": None,
                "values_changed": None,
                "vendorid": None,
                "vendorproduct": None,
                "verdict": None,
                "verificationmethod": None,
                "verificationstatus": None,
                "vulnerabilitycategory": None,
                "whereisdatahosted": None,
                "workphone": None,
                "xdr_additional_info": None,
                "xpanse_asset_id": None,
                "xpanse_asset_name": None,
                "xpanse_first_observed": None,
                "xpanse_policy_id": None,
                "xpanse_primary_asset_id": None,
                "xpanse_service_id": None,
                "xpanse_website_id": None,
                "zipcode": None
              },
              "incident_fields": None
            },
            {
              "alert_fields": {
                "accountid": None,
                "accountinformationbreached": None,
                "accountmemberof": None,
                "accountstatus": None,
                "acquisitionhire": None,
                "action_country": [
                  "UNKNOWN"
                ],
                "action_external_hostname": None,
                "action_file_macro_sha256": None,
                "action_file_md5": None,
                "action_file_name": None,
                "action_file_path": None,
                "action_file_sha256": None,
                "action_local_ip": None,
                "action_local_ip_v6": None,
                "action_local_port": None,
                "action_process_causality_id": None,
                "action_process_image_command_line": None,
                "action_process_image_md5": None,
                "action_process_image_name": None,
                "action_process_image_path": None,
                "action_process_image_sha256": None,
                "action_process_instance_id": None,
                "action_process_os_pid": None,
                "action_process_signature_status": [
                  "SIGNATURE_UNAVAILABLE"
                ],
                "action_process_signature_vendor": None,
                "action_process_user_sid": None,
                "action_registry_data": None,
                "action_registry_full_key": None,
                "action_registry_key_name": None,
                "action_registry_value_name": None,
                "action_remote_ip": None,
                "action_remote_ip_v6": None,
                "action_remote_port": None,
                "activated": "0001-01-01T00:00:00Z",
                "activity_first_seen_at": None,
                "activity_last_seen_at": None,
                "actor_causality_id": None,
                "actor_effective_user_sid": None,
                "actor_effective_username": [
                  "env4.local\\Administrator"
                ],
                "actor_process_causality_id": None,
                "actor_process_command_line": [
                  "\"C:\\Users\\administrator.ENV4\\Downloads\\8872230438\\wanmgr.exe\" "
                ],
                "actor_process_execution_time": None,
                "actor_process_image_md5": [
                  "7265719c94c5ffbcdbb5f71228d8ca68"
                ],
                "actor_process_image_name": [
                  "wanmgr.exe"
                ],
                "actor_process_image_path": [
                  "C:\\Users\\administrator.ENV4\\Downloads\\8872230438\\wanmgr.exe"
                ],
                "actor_process_image_sha256": [
                  "000001e7a228b2a7abdf7f7e3313324332b725e86907dde32176bddbbbb27"
                ],
                "actor_process_instance_id": [
                  "AdkwsQxs4pMAAB9YAAAAAA=="
                ],
                "actor_process_os_pid": [
                  8024
                ],
                "actor_process_signature_status": [
                  "SIGNATURE_UNAVAILABLE"
                ],
                "actor_process_signature_vendor": None,
                "actor_thread_thread_id": None,
                "additionaldata": None,
                "additionalindicators": None,
                "affecteddata": None,
                "affecteddatatype": None,
                "affectedindividualscontactinformation": None,
                "agent_data_collection_status": False,
                "agent_device_domain": "env4.local",
                "agent_file_md5": None,
                "agent_file_path": None,
                "agent_fqdn": "DC1ENV4APC01.env4.local",
                "agent_host_boot_time": None,
                "agent_hostname": "DC1ENV4APC01",
                "agent_id": "ac848acbd7504115b6624c9b1d755000",
                "agent_install_type": "STANDARD",
                "agent_ip_addresses": [
                  "172.16.4.122"
                ],
                "agent_ip_addresses_v6": None,
                "agent_is_vdi": None,
                "agent_os_sub_type": "10.0.19044",
                "agent_os_type": "AGENT_OS_WINDOWS",
                "agent_version": "7.9.0.20664",
                "agentsid": None,
                "agentversion": None,
                "alert_action_status": "BLOCKED",
                "alert_action_status_readable": "prevented (blocked)",
                "alert_category": "Malware",
                "alert_description": "Suspicious executable detected",
                "alert_description_raw": "Suspicious executable detected",
                "alert_ingest_status": None,
                "alert_is_fp": False,
                "alert_json": None,
                "alert_name": "WildFire Malware",
                "alert_source": "TRAPS",
                "alert_sub_type": None,
                "alert_type": "Unclassified",
                "alertacknowledgement": None,
                "alertaction": None,
                "alertmalicious": None,
                "alerttypeid": None,
                "analysisreport": None,
                "appchannelname": None,
                "applicationpath": None,
                "appmessage": None,
                "approvalstatus": None,
                "approver": None,
                "approximatenumberofaffecteddatasubjects": None,
                "asmalertsummary": None,
                "asmcloud": None,
                "asmdatacollection": None,
                "asmdevcheck": False,
                "asmnotification": None,
                "asmprivateip": None,
                "asmrelated": None,
                "asmremediation": None,
                "asmremediationpathrule": None,
                "asmservicedetection": None,
                "asmserviceowner": None,
                "asmserviceownerunrankedraw": None,
                "asmsystemids": None,
                "asmtags": None,
                "asn": None,
                "asnname": None,
                "asset_service_id": None,
                "assetid": None,
                "assigneduser": None,
                "assignmentgroup": None,
                "association_strength": [
                  50
                ],
                "attachment": None,
                "attachmentcount": None,
                "attachmentextension": None,
                "attachmenthash": None,
                "attachmentid": None,
                "attachmentname": None,
                "attachmentsize": None,
                "attachmenttype": None,
                "attack_techniques": None,
                "attackmode": None,
                "attempt_counter": 0,
                "attorneygeneralnotification": None,
                "audit_ids": None,
                "awsarn": None,
                "awsguarddutyaccesskeydetails": None,
                "awsguarddutyconfidencescore": None,
                "awsguarddutycontainerdetails": None,
                "awsguarddutyebsvolumedetails": None,
                "awsguarddutyecsclusterdetails": None,
                "awsguarddutyeksclusterdetails": None,
                "awsguarddutyiaminstanceprofile": None,
                "awsguarddutyinstancedetails": None,
                "awsguarddutykubernetesuserdetails": None,
                "awsguarddutykubernetesworkloaddetails": None,
                "awsguarddutynetworkinterface": None,
                "awsguarddutypartition": None,
                "awsguarddutyresourcetype": None,
                "awsguarddutys3bucketdetails": None,
                "awsguarddutyschemaversion": None,
                "awsguarddutyservice": None,
                "awsguarddutytype": None,
                "bioc_category_enum_key": None,
                "bioc_indicator": None,
                "birthday": None,
                "blockedaction": None,
                "branchname": None,
                "breachconfirmation": None,
                "bugtraq": None,
                "caller": None,
                "caller_ip": None,
                "case_id": 72,
                "category": None,
                "categorycount": None,
                "causality_actor_causality_id": None,
                "causality_actor_process_command_line": None,
                "causality_actor_process_execution_time": None,
                "causality_actor_process_image_md5": None,
                "causality_actor_process_image_name": None,
                "causality_actor_process_image_path": None,
                "causality_actor_process_image_sha256": None,
                "causality_actor_process_instance_id": None,
                "causality_actor_process_os_pid": None,
                "causality_actor_process_signature_status": [
                  "SIGNATURE_UNAVAILABLE"
                ],
                "causality_actor_process_signature_vendor": None,
                "changed": None,
                "cicdbranch": None,
                "cicdpackname": None,
                "cicdpullrequestbranch": None,
                "cicdpullrequestcomment": None,
                "cicdpullrequestlink": None,
                "cicdpullrequestreview": None,
                "cicdpullrequesttitle": None,
                "cicdreviewer": None,
                "cicds3bucketname": None,
                "city": None,
                "classification": None,
                "clickedurls": None,
                "closed": "0001-01-01T00:00:00Z",
                "closereason": None,
                "closetime": None,
                "closingreason": None,
                "closinguser": None,
                "closinguserid": None,
                "cloud_provider": None,
                "cloudaccountid": None,
                "cloudinstanceid": None,
                "cloudregionlist": None,
                "cloudresourcelist": None,
                "cloudservice": None,
                "cluster_name": None,
                "comment": None,
                "companyaddress": None,
                "companycity": None,
                "companyhasinsuranceforthebreach": None,
                "companyname": None,
                "companypostalcode": None,
                "compliancenotes": None,
                "configfilepath": None,
                "configurationfilesource": None,
                "consumerreportingagenciesnotification": None,
                "contactaddress": None,
                "contactemailaddress": None,
                "contactname": None,
                "contacttelephonenumber": None,
                "container_id": None,
                "contains_featured_host": [
                  "NO"
                ],
                "contains_featured_ip": [
                  "NO"
                ],
                "contains_featured_user": [
                  "NO"
                ],
                "costcenter": None,
                "costcentercode": None,
                "countrycode": None,
                "countrycodenumber": None,
                "countrywherebusinesshasitsmainestablishment": None,
                "criticalassets": None,
                "custompacksinstalled": None,
                "custompackssource": None,
                "cve": None,
                "cvelist": None,
                "cvss": None,
                "cvssavailabilityrequirement": None,
                "cvsscollateraldamagepotential": None,
                "cvssconfidentialityrequirement": None,
                "cvssintegrityrequirement": None,
                "dataencryptionstatus": None,
                "dbotMirrorLastSync": "0001-01-01T00:00:00Z",
                "dbotclosed": None,
                "dbotduedate": None,
                "dbotmirrordirection": None,
                "dbotmirrorid": None,
                "dbotmirrorinstance": None,
                "dbotmirrorlastsync": None,
                "dbotmodified": None,
                "dbotprediction": None,
                "dbotpredictionprobability": None,
                "dbotstatus": None,
                "dbottextsuggestionhighlighted": None,
                "dbottotaltime": None,
                "deduplicate_tokens": None,
                "department": None,
                "destinationgeolocation": None,
                "destinationipv6": None,
                "destinationnetworks": None,
                "destos": None,
                "detectedendpoints": None,
                "detectedexternalips": None,
                "detectedinternalhosts": None,
                "detection_modules": None,
                "detectionendtime": None,
                "detectionid": None,
                "detectionurl": None,
                "deviceexternalips": None,
                "devicehash": None,
                "deviceid": None,
                "deviceinternalips": None,
                "devicemacaddress": None,
                "devicemodel": None,
                "devicename": None,
                "deviceosname": None,
                "deviceosversion": None,
                "deviceou": None,
                "devicestatus": None,
                "devicetime": None,
                "displayname": None,
                "dns_query_name": None,
                "domainname": None,
                "domainsquattingresult": None,
                "dpoemailaddress": None,
                "dponotification": None,
                "drilldown_max_ts": None,
                "drilldown_min_ts": None,
                "drilldown_query": None,
                "droppedCount": 0,
                "droppedcount": None,
                "dst_action_country": None,
                "dst_action_external_hostname": None,
                "dst_action_external_port": None,
                "dst_actor_process_image_name": None,
                "dst_actor_process_os_pid": None,
                "dst_agent_hostname": None,
                "dst_agent_id": None,
                "dst_agent_id_single": None,
                "dst_agent_os_type": [
                  "NO_HOST"
                ],
                "dst_association_strength": None,
                "dst_causality_actor_process_execution_time": None,
                "dst_os_actor_process_image_name": None,
                "dst_os_actor_process_os_pid": None,
                "dsts": None,
                "dueDate": "0001-01-01T00:00:00Z",
                "duration": None,
                "dynamic_fields": {
                  "action_country": [
                    "UNKNOWN"
                  ],
                  "action_process_signature_status": [
                    "SIGNATURE_UNAVAILABLE"
                  ],
                  "activated": "0001-01-01T00:00:00Z",
                  "activatingingUserId": "",
                  "actor_effective_username": [
                    "env4.local\\Administrator"
                  ],
                  "actor_process_command_line": [
                    "\"C:\\Users\\administrator.ENV4\\Downloads\\8872230438\\wanmgr.exe\" "
                  ],
                  "actor_process_image_md5": [
                    "7265719c94c5ffbcdbb5f71228d8ca68"
                  ],
                  "actor_process_image_name": [
                    "wanmgr.exe"
                  ],
                  "actor_process_image_path": [
                    "C:\\Users\\administrator.ENV4\\Downloads\\8872230438\\wanmgr.exe"
                  ],
                  "actor_process_image_sha256": [
                    "000001e7a228b2a7abdf7f7e3313324332b725e86907dde32176bddbbbb27"
                  ],
                  "actor_process_os_pid": [
                    8024
                  ],
                  "actor_process_signature_status": [
                    "SIGNATURE_UNAVAILABLE"
                  ],
                  "agent_device_domain": "env4.local",
                  "agent_fqdn": "DC1ENV4APC01.env4.local",
                  "agent_hostname": "DC1ENV4APC01",
                  "agent_id": "ac848acbd7504115b6624c9b1d755000",
                  "agent_ip_addresses": [
                    "172.16.4.122"
                  ],
                  "agent_os_sub_type": "10.0.19044",
                  "agent_os_type": "AGENT_OS_WINDOWS",
                  "alert_action_status": "BLOCKED",
                  "alert_category": "Malware",
                  "alert_description": "Suspicious executable detected",
                  "alert_name": "WildFire Malware",
                  "alert_source": "TRAPS",
                  "alert_type": "Unclassified",
                  "attachment": None,
                  "category": "",
                  "causality_actor_process_signature_status": [
                    "SIGNATURE_UNAVAILABLE"
                  ],
                  "closeReason": "",
                  "closed": "0001-01-01T00:00:00Z",
                  "closingUserId": "",
                  "contains_featured_host": [
                    "NO"
                  ],
                  "contains_featured_ip": [
                    "NO"
                  ],
                  "contains_featured_user": [
                    "NO"
                  ],
                  "dbotCurrentDirtyFields": None,
                  "dbotDirtyFields": None,
                  "dbotMirrorDirection": "",
                  "dbotMirrorId": "",
                  "dbotMirrorInstance": "",
                  "dbotMirrorLastSync": "0001-01-01T00:00:00Z",
                  "dbotMirrorTags": None,
                  "droppedCount": 0,
                  "dueDate": "0001-01-01T00:00:00Z",
                  "event_type": [
                    1
                  ],
                  "feedBased": False,
                  "fw_is_phishing": [
                    "NOT_AVAILABLE"
                  ],
                  "internal_id": 14861,
                  "investigationId": "14861",
                  "isDebug": False,
                  "is_whitelisted": False,
                  "labels": None,
                  "lastJobRunTime": "0001-01-01T00:00:00Z",
                  "lastOpen": "0001-01-01T00:00:00Z",
                  "linkedCount": 0,
                  "linkedIncidents": None,
                  "mac": "00:50:56:9f:f5:5f",
                  "module_id": [
                    "WildFire"
                  ],
                  "notifyTime": "0001-01-01T00:00:00Z",
                  "occurred": "0001-01-01T00:00:00Z",
                  "openDuration": 0,
                  "os_actor_process_signature_status": [
                    "SIGNATURE_UNAVAILABLE"
                  ],
                  "phase": "",
                  "playbookId": "f1fa9cef-75be-429e-8d16-e29350af29a9",
                  "reason": "",
                  "reminder": "0001-01-01T00:00:00Z",
                  "resolution_comment": "",
                  "resolution_status": "STATUS_020_UNDER_INVESTIGATION",
                  "runStatus": "pending",
                  "severity": "SEV_030_MEDIUM",
                  "sla": 0,
                  "sourceInstance": "",
                  "source_insert_ts": 1674646610961,
                  "starred": False
                },
                "email": None,
                "emailaddress": None,
                "emailauthenticitycheck": None,
                "emailbcc": None,
                "emailbody": None,
                "emailbodyformat": None,
                "emailbodyhtml": None,
                "emailcampaigncanvas": None,
                "emailcampaignmutualindicators": None,
                "emailcampaignsnippets": None,
                "emailcampaignsummary": None,
                "emailcc": None,
                "emailclassification": None,
                "emailclientname": None,
                "emaildeletefrombrand": None,
                "emaildeletereason": None,
                "emaildeleteresult": None,
                "emaildeletetype": None,
                "emailheaders": None,
                "emailhtml": None,
                "emailhtmlimage": None,
                "emailinreplyto": None,
                "emailinternalmessageid": None,
                "emailkeywords": None,
                "emaillabels": None,
                "emaillatestmessage": None,
                "emailmessageid": None,
                "emailreceived": None,
                "emailrecipientscount": None,
                "emailreplyto": None,
                "emailreturnpath": None,
                "emailsenderip": None,
                "emailsentsuccessfully": False,
                "emailsize": None,
                "emailsource": None,
                "emailtocount": None,
                "emailurlclicked": None,
                "employeedisplayname": None,
                "employeeemail": None,
                "employeemanageremail": None,
                "end_match_attempt_ts": None,
                "endpointisolationstatus": None,
                "endtime": None,
                "errorcode": None,
                "errormessage": None,
                "escalation": None,
                "event_id": None,
                "event_sub_type": None,
                "event_timestamp": [
                  1674646578590
                ],
                "event_type": [
                  1
                ],
                "eventaction": None,
                "eventdescriptions": None,
                "eventid": None,
                "eventnames": None,
                "events": [],
                "exposurelevel": None,
                "external_id": "303a293a9227422da0475cca1f6a8710",
                "externalcategoryid": None,
                "externalcategoryname": None,
                "externalconfidence": None,
                "externalendtime": None,
                "externallink": None,
                "externalseverity": None,
                "externalstarttime": None,
                "externalstatus": None,
                "externalsubcategoryid": None,
                "externalsubcategoryname": None,
                "externalsystemid": None,
                "family_tags": [
                  "DS:PANW/XDR Agent"
                ],
                "feedBased": False,
                "feedbased": False,
                "fileaccessdate": None,
                "filecreationdate": None,
                "filehash": None,
                "filerelationships": None,
                "filesha1": None,
                "filesize": None,
                "filter_rule_id": None,
                "financialinformationbreached": None,
                "fireeyealertinfectionid": None,
                "fireeyealertmalicious": None,
                "fireeyealertvlan": None,
                "fireeyec2address": None,
                "fireeyec2channel": None,
                "fireeyec2host": None,
                "fireeyeemailqueueid": None,
                "fireeyeemailsourcedomain": None,
                "fireeyefireeyedownloadat": None,
                "fireeyeinfectionid": None,
                "fireeyeinfectionurl": None,
                "fireeyemalwareinfo": None,
                "fireeyemalwareinformation": None,
                "fireeyematchcount": None,
                "fireeyematchedtime": None,
                "fireeyenxalertaction": None,
                "fireeyenxalertid": None,
                "fireeyenxalertmalwarename": None,
                "fireeyenxalertscversion": None,
                "fireeyenxalerttargetip": None,
                "fireeyenxalerttype": None,
                "fireeyenxalerturl": None,
                "fireeyenxalertuuid": None,
                "fireeyenxalertvictimip": None,
                "fireeyenxeventcveid": None,
                "fireeyenxeventdestinationmacaddress": None,
                "fireeyenxeventid": None,
                "fireeyenxeventrule": None,
                "fireeyenxeventsourcemacaddress": None,
                "fireeyenxeventvictimip": None,
                "fireeyesignatureid": None,
                "fireeyesignaturerevision": None,
                "fireeyesubmittedat": None,
                "firstname": None,
                "firstseen": None,
                "followup": False,
                "forensics_artifact_type": None,
                "from_dml": None,
                "fullname": None,
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
                "fw_is_phishing": [
                  "NOT_AVAILABLE"
                ],
                "fw_misc": None,
                "fw_rule": None,
                "fw_rule_id": None,
                "fw_serial_number": None,
                "fw_url_domain": None,
                "fw_vsys": None,
                "fw_xff": None,
                "genericexportindicatorsserviceaction": None,
                "genericexportindicatorsserviceindicatorslist": None,
                "genericexportindicatorsserviceindicatortype": None,
                "genericexportindicatorsservicetag": None,
                "givenname": None,
                "groupid": None,
                "gsuitesacalertid": None,
                "gsuitesacalertseverity": None,
                "gsuitesacalertsource": None,
                "gsuitesacalertstatus": None,
                "gsuitesacalerttype": None,
                "gsuitesaccreatetime": None,
                "gsuitesaccustomerid": None,
                "gsuitesacdeleted": None,
                "gsuitesacendtime": None,
                "gsuitesacetag": None,
                "gsuitesacfeedbackcreatetime": None,
                "gsuitesacfeedbackemail": None,
                "gsuitesacfeedbackid": None,
                "gsuitesacfeedbacktype": None,
                "gsuitesacsecurityinvestigationtoollink": None,
                "gsuitesacstarttime": None,
                "gsuitesacupdatetime": None,
                "has_alert_layout_data": None,
                "healthinsurancebreached": None,
                "helloworldid": None,
                "helloworldstatus": None,
                "helloworldtype": None,
                "huntresultscount": None,
                "identity_invoked_by_type": None,
                "identity_name": None,
                "identity_sub_type": None,
                "identity_type": None,
                "image_name": None,
                "impacteddevices": None,
                "impactedentities": None,
                "incidentlink": None,
                "incomingmirrorerror": None,
                "individualsnotification": None,
                "internal_id": "14861",
                "internaladdresses": None,
                "investigationId": "14861",
                "investigationstage": None,
                "iot_pivot_url": None,
                "ipblockedstatus": None,
                "ipreputation": None,
                "isDebug": False,
                "is_deleted": None,
                "is_disintegrated": None,
                "is_identity": None,
                "is_pcap": False,
                "is_rule_triggering": False,
                "is_whitelisted": False,
                "is_xdm": None,
                "is_xsoar_alert": False,
                "isactive": None,
                "isolated": None,
                "isthedatasubjecttodpia": None,
                "itemowner": None,
                "itemowneremail": None,
                "jobcode": None,
                "jobfamily": None,
                "jobfunction": None,
                "jobscreated": None,
                "join_next_attempt_time": None,
                "labels": None,
                "lastJobRunTime": "0001-01-01T00:00:00Z",
                "lastOpen": "0001-01-01T00:00:00Z",
                "last_modified_ts": None,
                "lastmodifiedby": None,
                "lastmodifiedon": None,
                "lastname": None,
                "lastseen": None,
                "lastupdatetime": None,
                "leadership": None,
                "likelyimpact": None,
                "linkedCount": 0,
                "linkedcount": None,
                "listofrulesevent": None,
                "listscreated": None,
                "local_insert_ts": 1674646586780,
                "location": None,
                "locationregion": None,
                "logsource": None,
                "logsourcename": None,
                "logsourcetype": None,
                "lowlevelcategoriesevents": None,
                "mac": "00:50:56:9f:f5:5f",
                "macrosourcecode": None,
                "maliciousbehavior": None,
                "maliciouscauseifthecauseisamaliciousattack": None,
                "maliciousurlclicked": None,
                "maliciousurlviewed": None,
                "malwarefamily": None,
                "malwarename": None,
                "managementnotification": None,
                "manageremailaddress": None,
                "managername": None,
                "marketplacepacksinstalled": None,
                "matching_service_rule_id": None,
                "matching_status": "UNMATCHABLE",
                "measurestomitigate": None,
                "medianotification": None,
                "medicalinformationbreached": None,
                "microsoft365defendera": None,
                "microsoft365defenderactive": None,
                "microsoft365defendercategoriescount": None,
                "microsoft365defenderclassification": None,
                "microsoft365defenderdevices": None,
                "microsoft365defenderdisplayname": None,
                "microsoft365defenderfirstactivity": None,
                "microsoft365defenderid": None,
                "microsoft365defenderlastactivity": None,
                "microsoft365defenderstatus": None,
                "microsoftdefenderforendpointevidencecreationtime": None,
                "microsoftdefenderforendpointevidencetype": None,
                "microsoftgraphidentityandaccessactivity": None,
                "microsoftgraphidentityandaccessalerttype": None,
                "microsoftgraphidentityandaccessdetectiontimingtype": None,
                "microsoftgraphidentityandaccesstokenissuertype": None,
                "mitre_tactic_id_and_name": None,
                "mitre_technique_id_and_name": None,
                "mitretacticid": None,
                "mitretacticname": None,
                "mitretechniqueid": None,
                "mitretechniquename": None,
                "mobiledevicemodel": None,
                "mobilephone": None,
                "module_id": [
                  "WildFire"
                ],
                "module_name": [
                  "COMPONENT_WILDFIRE"
                ],
                "notifyTime": "0001-01-01T00:00:00Z",
                "numberoflogsources": None,
                "numberofrelatedincidents": None,
                "numberofsimilarfiles": None,
                "objective": None,
                "occurred": "0001-01-01T00:00:00Z",
                "openDuration": 0,
                "operation_name": None,
                "orglevel1": None,
                "orglevel2": None,
                "orglevel3": None,
                "orgunit": None,
                "original_severity": "SEV_030_MEDIUM",
                "originalalertid": None,
                "originalalertname": None,
                "originalalertsource": None,
                "originaldescription": None,
                "originalevents": None,
                "os": None,
                "os_actor_causality_id": None,
                "os_actor_effective_username": None,
                "os_actor_process_causality_id": None,
                "os_actor_process_command_line": None,
                "os_actor_process_execution_time": None,
                "os_actor_process_image_md5": None,
                "os_actor_process_image_name": None,
                "os_actor_process_image_path": None,
                "os_actor_process_image_sha256": None,
                "os_actor_process_instance_id": None,
                "os_actor_process_os_pid": None,
                "os_actor_process_signature_status": [
                  "SIGNATURE_UNAVAILABLE"
                ],
                "os_actor_process_signature_vendor": None,
                "os_actor_thread_thread_id": None,
                "ostype": None,
                "otherpiidatabreached": None,
                "outgoingmirrorerror": None,
                "owner": None,
                "parentprocesscmd": None,
                "parentprocessfilepath": None,
                "parentprocessid": None,
                "parentprocessids": None,
                "parentprocessmd5": None,
                "parentprocessname": None,
                "parentprocesspath": None,
                "parentprocesssha256": None,
                "partofcampaign": None,
                "passwordchangeddate": None,
                "passwordresetsuccessfully": False,
                "personalemail": None,
                "phase": None,
                "phishingbclscore": None,
                "phishingpclscore": None,
                "phishingreporteremailheaders": None,
                "phishingsclscore": None,
                "phishingsubtype": None,
                "phone_number": None,
                "piidatatype": None,
                "pivot_url": None,
                "playbookId": "f1fa9cef-75be-429e-8d16-e29350af29a9",
                "playbook_suggestion_rule_id": None,
                "playbookid": None,
                "policy_id": None,
                "policyactions": None,
                "policydeleted": None,
                "policydescription": None,
                "policydetails": None,
                "policyid": None,
                "policyrecommendation": None,
                "policyremediable": None,
                "policyseverity": None,
                "policytype": None,
                "policyuri": None,
                "possiblecauseofthebreach": None,
                "postalcode": None,
                "postnatdestinationip": None,
                "postnatdestinationport": None,
                "postnatsourceip": None,
                "postnatsourceport": None,
                "prenatdestinationport": None,
                "prenatsourceip": None,
                "prenatsourceport": None,
                "processcmd": None,
                "processcreationtime": None,
                "processid": None,
                "processmd5": None,
                "processnames": None,
                "processpaths": None,
                "processsha256": None,
                "project": None,
                "protocolnames": None,
                "quarantined": None,
                "query_tables": None,
                "rating": None,
                "rawevent": None,
                "referenced_resource": None,
                "region": None,
                "regionid": None,
                "registryhive": None,
                "registrykey": None,
                "registryvalue": None,
                "registryvaluetype": None,
                "relatedcampaign": None,
                "relatedendpoints": None,
                "relatedreport": None,
                "reminder": "0001-01-01T00:00:00Z",
                "remote_cid": None,
                "renderedhtml": None,
                "reportedemailcc": None,
                "reportedemailfrom": None,
                "reportedemailmessageid": None,
                "reportedemailorigin": None,
                "reportedemailsubject": None,
                "reportedemailto": None,
                "reporteremailaddress": None,
                "residentnotificationoption": None,
                "residentsemailaddress": None,
                "resolution_comment": "",
                "resolution_status": "STATUS_020_UNDER_INVESTIGATION",
                "resolution_status_modified_ts": 1674646611059,
                "resource_sub_type": None,
                "resource_type": None,
                "resourcename": None,
                "resourcetype": None,
                "riskrating": None,
                "riskscore": None,
                "rulename": None,
                "runStatus": "pending",
                "samaccountname": None,
                "scenario": None,
                "secretarynotification": None,
                "sectorofaffectedparty": None,
                "selectedindicators": None,
                "sensorip": None,
                "severity": "SEV_030_MEDIUM",
                "sha1": None,
                "sha512": None,
                "signature": None,
                "similarincidents": None,
                "similarincidentsdbot": None,
                "sizenumberofemployees": None,
                "sizeturnover": None,
                "skuname": None,
                "skutier": None,
                "sla": 0,
                "source_insert_ts": 1674646578590,
                "sourcecategory": None,
                "sourcecreatedby": None,
                "sourcecreatetime": None,
                "sourceexternalips": None,
                "sourcegeolocation": None,
                "sourceid": None,
                "sourceinstance": None,
                "sourcenetworks": None,
                "sourcepriority": None,
                "sourcestatus": None,
                "sourceupdatedby": None,
                "sourceurgency": None,
                "srcos": None,
                "ssdeep": None,
                "starred": False,
                "starttime": None,
                "state": None,
                "statecisonotification": None,
                "statewherethebreachtookplace": None,
                "story_id": None,
                "streetaddress": None,
                "subcategory": None,
                "subtype": None,
                "suggested_playbook_id": None,
                "surname": None,
                "tactic": None,
                "tacticid": None,
                "tags": [
                  "DS:PANW/XDR Agent"
                ],
                "target": None,
                "targetfirewallversion": None,
                "teamname": None,
                "technicalowner": None,
                "technicalownercontact": None,
                "technicaluser": None,
                "technique": None,
                "techniqueid": None,
                "telephoneno": None,
                "tenantname": None,
                "terminatedaction": None,
                "threatactor": None,
                "threatfamilyname": None,
                "threatname": None,
                "ticketacknowledgeddate": None,
                "ticketcloseddate": None,
                "ticketnumber": None,
                "tim_main_indicator": None,
                "timezone": None,
                "title": None,
                "totalmaliciousurlsclicks": None,
                "trafficdirection": None,
                "triggeredsecurityprofile": None,
                "uniquebiometricdatabreached": None,
                "uniqueidentificationnumberbreached": None,
                "uniqueports": None,
                "urls": None,
                "urlsslverification": None,
                "usecasedescription": None,
                "user_agent": None,
                "useraccountcontrol": None,
                "usercreationtime": None,
                "userengagementresponse": None,
                "userid": None,
                "usersid": None,
                "uuid": None,
                "values_changed": None,
                "vendorid": None,
                "vendorproduct": None,
                "verdict": None,
                "verificationmethod": None,
                "verificationstatus": None,
                "vulnerabilitycategory": None,
                "whereisdatahosted": None,
                "workphone": None,
                "xdr_additional_info": None,
                "xpanse_asset_id": None,
                "xpanse_asset_name": None,
                "xpanse_first_observed": None,
                "xpanse_policy_id": None,
                "xpanse_primary_asset_id": None,
                "xpanse_service_id": None,
                "xpanse_website_id": None,
                "zipcode": None
              },
              "incident_fields": None
            }
          ],
          "result_count": 4
        }

    context = []
    for alert in raw_response.get('alerts', []):
        alert = alert.get('alert_fields')
        if 'alert_action_status' in alert:
            # convert the status, if failed take the original status
            action_status = alert.get('alert_action_status')
            alert['alert_action_status_readable'] = ALERT_STATUS_TYPES.get(action_status, action_status)

        context.append(alert)

    human_readable = [{
        'Alert ID': alert.get('internal_id'),
        'Detection Timestamp': timestamp_to_datestring(alert.get('source_insert_ts')),
        'Name': alert.get('alert_name'),
        'Severity': alert.get('severity'),
        'Category': alert.get('alert_category'),
        'Action': alert.get('alert_action_status_readable'),
        'Description': alert.get('alert_description'),
        'Host IP': alert.get('agent_ip_addresses'),
        'Host Name': alert.get('agent_hostname'),
    } for alert in context]

    return CommandResults(
        outputs_prefix=f'{prefix}.Alert',
        outputs_key_field='internal_id',
        outputs=context,
        readable_output=tableToMarkdown('Alerts', human_readable),
        raw_response=raw_response,
    )

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
    #api_key = params.get('apikey') or params.get('apikey_creds').get('password', '')
    #api_key_id = params.get('apikey_id') or params.get('apikey_id_creds').get('password', '')
    first_fetch_time = params.get('fetch_time', '3 days')
    #base_url = urljoin(params.get('url'), '/public_api/v1')
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
    #auth_key = "%s%s%s" % (api_key, nonce, timestamp)
    #auth_key = auth_key.encode("utf-8")
    #api_key_hash = hashlib.sha256(auth_key).hexdigest()

    # if argToBoolean(params.get("prevent_only", False)):
    #api_key_hash = api_key

    # headers = {
    #    "x-xdr-timestamp": timestamp,
    #    "x-xdr-nonce": nonce,
    #    "x-xdr-auth-id": str(api_key_id),
    #    "Authorization": api_key_hash
    # }

    # client = Client(
    #    base_url=base_url,
    #   proxy=proxy,
    #    verify=verify_cert,
    #    headers=headers,
    #    timeout=timeout
    # )
    client = None

    args = demisto.args()
    args["integration_context_brand"] = INTEGRATION_CONTEXT_BRAND
    args["integration_name"] = INTEGRATION_NAME

    try:
        if command == 'test-module':
            # client.test_module(first_fetch_time)
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

        elif command == 'xdr-get-incident-extra-data-ctf':
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

        elif command == 'xdr-endpoint-isolate-ctf':
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

        elif command == 'xdr-file-retrieve-ctf':
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

        elif command == 'xdr-get-alerts-ctf':
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
