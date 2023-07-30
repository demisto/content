import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


from CoreIRApiModule import *
from itertools import zip_longest
import string
import secrets
import hashlib




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
    if (incident_id == "1284"):
        raw_incident = {
  'alerts': {
    'data': [
      {
        'action': 'DETECTED',
        'action_country': 'UNKNOWN',
        'action_external_hostname': None,
        'action_file_macro_sha256': None,
        'action_file_md5': None,
        'action_file_name': None,
        'action_file_path': None,
        'action_file_sha256': None,
        'action_local_ip': None,
        'action_local_ip_v6': None,
        'action_local_port': None,
        'action_pretty': 'Detected',
        'action_process_causality_id': None,
        'action_process_image_command_line': None,
        'action_process_image_name': None,
        'action_process_image_sha256': None,
        'action_process_instance_id': None,
        'action_process_signature_status': 'N/A',
        'action_process_signature_vendor': None,
        'action_registry_data': None,
        'action_registry_full_key': None,
        'action_registry_key_name': None,
        'action_registry_value_name': None,
        'action_remote_ip': None,
        'action_remote_ip_v6': None,
        'action_remote_port': None,
        'actor_causality_id': None,
        'actor_process_causality_id': None,
        'actor_process_command_line': None,
        'actor_process_image_md5': None,
        'actor_process_image_name': None,
        'actor_process_image_path': None,
        'actor_process_image_sha256': None,
        'actor_process_instance_id': None,
        'actor_process_os_pid': None,
        'actor_process_signature_status': 'N/A',
        'actor_process_signature_vendor': None,
        'actor_thread_thread_id': None,
        'agent_data_collection_status': None,
        'agent_device_domain': None,
        'agent_fqdn': None,
        'agent_host_boot_time': None,
        'agent_install_type': 'NA',
        'agent_ip_addresses_v6': None,
        'agent_is_vdi': None,
        'agent_os_sub_type': None,
        'agent_os_type': 'NO_HOST',
        'agent_version': None,
        'alert_id': '14827',
        'alert_type': 'Unclassified',
        'association_strength': 50,
        'attempt_counter': 0,
        'bioc_category_enum_key': None,
        'bioc_indicator': None,
        'case_id': 1284,
        'category': 'Defense Evasion',
        'causality_actor_causality_id': None,
        'causality_actor_process_command_line': None,
        'causality_actor_process_execution_time': None,
        'causality_actor_process_image_md5': None,
        'causality_actor_process_image_name': None,
        'causality_actor_process_image_path': None,
        'causality_actor_process_image_sha256': None,
        'causality_actor_process_signature_status': 'N/A',
        'causality_actor_process_signature_vendor': None,
        'cloud_provider': 'AWS',
        'cluster_name': None,
        'container_id': None,
        'contains_featured_host': 'NO',
        'contains_featured_ip': 'NO',
        'contains_featured_user': 'NO',
        'deduplicate_tokens': None,
        'description': 'An unusual activity was performed in AWS, region eu-west-1. The CREATE operation was performed against a COMPUTE service in the project 666688938958. This behavior was not observed in the last 30 days',
        'detection_timestamp': 1676282755000,
        'dns_query_name': None,
        'dst_action_country': None,
        'dst_action_external_hostname': None,
        'dst_action_external_port': None,
        'dst_agent_id': None,
        'dst_association_strength': None,
        'dst_causality_actor_process_execution_time': None,
        'dynamic_fields': None,
        'end_match_attempt_ts': None,
        'endpoint_id': None,
        'event_id': '2db6ffaa-694d-560c-bdd1-8f22e97331db_4',
        'event_sub_type': 3,
        'event_timestamp': 1672665266000,
        'event_type': 'Cloud Audit Log',
        'events_length': 1,
        'external_id': '8fa790af-ee28-4f27-9e5e-343e4053c44c',
        'filter_rule_id': None,
        'fw_app_category': None,
        'fw_app_id': None,
        'fw_app_subcategory': None,
        'fw_app_technology': None,
        'fw_device_name': None,
        'fw_email_recipient': None,
        'fw_email_sender': None,
        'fw_email_subject': None,
        'fw_interface_from': None,
        'fw_interface_to': None,
        'fw_is_phishing': 'N/A',
        'fw_misc': None,
        'fw_rule': None,
        'fw_rule_id': None,
        'fw_serial_number': None,
        'fw_url_domain': None,
        'fw_vsys': None,
        'fw_xff': None,
        'host_ip': '31.154.166.148',
        'host_ip_list': [
          '31.154.166.148'
        ],
        'host_name': None,
        'identity_sub_type': 'IAM',
        'identity_type': 'USER',
        'image_name': None,
        'is_pcap': False,
        'is_whitelisted': False,
        'last_modified_ts': 1686732679256,
        'local_insert_ts': 1672665528800,
        'mac': None,
        'malicious_urls': None,
        'matching_service_rule_id': '22e661ae-3081-4a2d-9550-c65b6b660af1',
        'matching_status': 'MATCHED',
        'mitre_tactic_id_and_name': 'TA0005 - Defense Evasion',
        'mitre_technique_id_and_name': 'T1535 - Unused/Unsupported Cloud Regions',
        'module_id': None,
        'name': 'A cloud compute instance was created in a dormant region',
        'operation_name': 'CREATE',
        'original_tags': 'DS:Amazon/AWS',
        'os_actor_causality_id': None,
        'os_actor_effective_username': None,
        'os_actor_process_causality_id': None,
        'os_actor_process_command_line': None,
        'os_actor_process_image_name': None,
        'os_actor_process_image_path': None,
        'os_actor_process_image_sha256': None,
        'os_actor_process_instance_id': None,
        'os_actor_process_os_pid': None,
        'os_actor_process_signature_status': 'N/A',
        'os_actor_process_signature_vendor': None,
        'os_actor_thread_thread_id': None,
        'project': '666688938958',
        'referenced_resource': 'arn:aws:ec2:us-west-2:666688938958:vpc/vpc-04cfed27f1f06f385',
        'resolution_comment': None,
        'resolution_status': 'STATUS_020_UNDER_INVESTIGATION',
        'resource_sub_type': 'VPC',
        'resource_type': 'COMPUTE',
        'severity': 'medium',
        'source': 'XDR Analytics BIOC',
        'starred': False,
        'story_id': None,
        'tags': 'DS:Amazon/AWS',
        'user_agent': 'Boto3/1.24.93 Python/3.10.0 Darwin/20.6.0 Botocore/1.27.93',
        'user_name': 'svc_dev'
      },
      {
        'action': 'DETECTED',
        'action_country': 'UNKNOWN',
        'action_external_hostname': None,
        'action_file_macro_sha256': None,
        'action_file_md5': None,
        'action_file_name': None,
        'action_file_path': None,
        'action_file_sha256': None,
        'action_local_ip': None,
        'action_local_ip_v6': None,
        'action_local_port': None,
        'action_pretty': 'Detected',
        'action_process_causality_id': None,
        'action_process_image_command_line': None,
        'action_process_image_name': None,
        'action_process_image_sha256': None,
        'action_process_instance_id': None,
        'action_process_signature_status': 'N/A',
        'action_process_signature_vendor': None,
        'action_registry_data': None,
        'action_registry_full_key': None,
        'action_registry_key_name': None,
        'action_registry_value_name': None,
        'action_remote_ip': None,
        'action_remote_ip_v6': None,
        'action_remote_port': None,
        'actor_causality_id': None,
        'actor_process_causality_id': None,
        'actor_process_command_line': None,
        'actor_process_image_md5': None,
        'actor_process_image_name': None,
        'actor_process_image_path': None,
        'actor_process_image_sha256': None,
        'actor_process_instance_id': None,
        'actor_process_os_pid': None,
        'actor_process_signature_status': 'N/A',
        'actor_process_signature_vendor': None,
        'actor_thread_thread_id': None,
        'agent_data_collection_status': None,
        'agent_device_domain': None,
        'agent_fqdn': None,
        'agent_host_boot_time': None,
        'agent_install_type': 'NA',
        'agent_ip_addresses_v6': None,
        'agent_is_vdi': None,
        'agent_os_sub_type': None,
        'agent_os_type': 'NO_HOST',
        'agent_version': None,
        'alert_id': '16223',
        'alert_type': 'Unclassified',
        'association_strength': None,
        'attempt_counter': 0,
        'bioc_category_enum_key': None,
        'bioc_indicator': None,
        'case_id': 1284,
        'category': 'Impact',
        'causality_actor_causality_id': None,
        'causality_actor_process_command_line': None,
        'causality_actor_process_execution_time': None,
        'causality_actor_process_image_md5': None,
        'causality_actor_process_image_name': None,
        'causality_actor_process_image_path': None,
        'causality_actor_process_image_sha256': None,
        'causality_actor_process_signature_status': 'N/A',
        'causality_actor_process_signature_vendor': None,
        'cloud_provider': 'AWS',
        'cluster_name': None,
        'container_id': None,
        'contains_featured_host': 'NO',
        'contains_featured_ip': 'NO',
        'contains_featured_user': 'NO',
        'deduplicate_tokens': None,
        'description': 'The identity svc_dev created an unusual amount of compute resources. The activity seen on AWS provider within 666688938958 project on eu-west-1 region',
        'detection_timestamp': 1676282745000,
        'dns_query_name': None,
        'dst_action_country': None,
        'dst_action_external_hostname': None,
        'dst_action_external_port': None,
        'dst_agent_id': None,
        'dst_association_strength': None,
        'dst_causality_actor_process_execution_time': None,
        'dynamic_fields': None,
        'end_match_attempt_ts': None,
        'endpoint_id': '-1',
        'event_id': '36451364-79e7-582b-a5df-e331bd45bb1b_4',
        'event_sub_type': 3,
        'event_timestamp': 1676282725000,
        'event_type': 'Cloud Audit Log',
        'events_length': 1,
        'external_id': '5c5beda1-a9ac-4799-959f-0f6b16f23f3a',
        'filter_rule_id': None,
        'fw_app_category': None,
        'fw_app_id': None,
        'fw_app_subcategory': None,
        'fw_app_technology': None,
        'fw_device_name': None,
        'fw_email_recipient': None,
        'fw_email_sender': None,
        'fw_email_subject': None,
        'fw_interface_from': None,
        'fw_interface_to': None,
        'fw_is_phishing': 'N/A',
        'fw_misc': None,
        'fw_rule': None,
        'fw_rule_id': None,
        'fw_serial_number': None,
        'fw_url_domain': None,
        'fw_vsys': None,
        'fw_xff': None,
        'host_ip': None,
        'host_ip_list': [],
        'host_name': None,
        'identity_sub_type': 'IAM',
        'identity_type': 'USER',
        'image_name': None,
        'is_pcap': False,
        'is_whitelisted': False,
        'last_modified_ts': 1686731961937,
        'local_insert_ts': 1676282795282,
        'mac': None,
        'malicious_urls': None,
        'matching_service_rule_id': '653d6d6c-2f5b-11ed-8017-acde48001122',
        'matching_status': 'MATCHED',
        'mitre_tactic_id_and_name': 'TA0040 - Impact',
        'mitre_technique_id_and_name': 'T1496 - Resource Hijacking',
        'module_id': None,
        'name': 'Allocation of multiple cloud compute resources with accelerator gear',
        'operation_name': 'CREATE',
        'original_tags': 'DS:Amazon/AWS',
        'os_actor_causality_id': None,
        'os_actor_effective_username': None,
        'os_actor_process_causality_id': None,
        'os_actor_process_command_line': None,
        'os_actor_process_image_name': None,
        'os_actor_process_image_path': None,
        'os_actor_process_image_sha256': None,
        'os_actor_process_instance_id': None,
        'os_actor_process_os_pid': None,
        'os_actor_process_signature_status': 'N/A',
        'os_actor_process_signature_vendor': None,
        'os_actor_thread_thread_id': None,
        'project': '666688938958',
        'referenced_resource': 'arn:aws:ec2:eu-west-1:666688938958:instance/i-0dc36ef8209f667fb',
        'resolution_comment': None,
        'resolution_status': 'STATUS_020_UNDER_INVESTIGATION',
        'resource_sub_type': 'COMPUTE_INSTANCE',
        'resource_type': 'COMPUTE',
        'severity': 'high',
        'source': 'XDR Analytics',
        'starred': False,
        'story_id': None,
        'tags': 'DS:Amazon/AWS',
        'user_agent': 'Boto3/1.24.93 Python/3.10.0 Darwin/20.6.0 Botocore/1.27.93',
        'user_name': 'svc_dev'
      },
      {
        'action': 'DETECTED',
        'action_country': 'UNKNOWN',
        'action_external_hostname': None,
        'action_file_macro_sha256': None,
        'action_file_md5': None,
        'action_file_name': None,
        'action_file_path': None,
        'action_file_sha256': None,
        'action_local_ip': None,
        'action_local_ip_v6': None,
        'action_local_port': None,
        'action_pretty': 'Detected',
        'action_process_causality_id': None,
        'action_process_image_command_line': None,
        'action_process_image_name': None,
        'action_process_image_sha256': None,
        'action_process_instance_id': None,
        'action_process_signature_status': 'N/A',
        'action_process_signature_vendor': None,
        'action_registry_data': None,
        'action_registry_full_key': None,
        'action_registry_key_name': None,
        'action_registry_value_name': None,
        'action_remote_ip': None,
        'action_remote_ip_v6': None,
        'action_remote_port': None,
        'actor_causality_id': None,
        'actor_process_causality_id': None,
        'actor_process_command_line': None,
        'actor_process_image_md5': None,
        'actor_process_image_name': None,
        'actor_process_image_path': None,
        'actor_process_image_sha256': None,
        'actor_process_instance_id': None,
        'actor_process_os_pid': None,
        'actor_process_signature_status': 'N/A',
        'actor_process_signature_vendor': None,
        'actor_thread_thread_id': None,
        'agent_data_collection_status': None,
        'agent_device_domain': None,
        'agent_fqdn': None,
        'agent_host_boot_time': None,
        'agent_install_type': 'NA',
        'agent_ip_addresses_v6': None,
        'agent_is_vdi': None,
        'agent_os_sub_type': None,
        'agent_os_type': 'NO_HOST',
        'agent_version': None,
        'alert_id': '14873',
        'alert_type': 'Unclassified',
        'association_strength': 50,
        'attempt_counter': 0,
        'bioc_category_enum_key': None,
        'bioc_indicator': None,
        'case_id': 1284,
        'category': 'Execution',
        'causality_actor_causality_id': None,
        'causality_actor_process_command_line': None,
        'causality_actor_process_execution_time': None,
        'causality_actor_process_image_md5': None,
        'causality_actor_process_image_name': None,
        'causality_actor_process_image_path': None,
        'causality_actor_process_image_sha256': None,
        'causality_actor_process_signature_status': 'N/A',
        'causality_actor_process_signature_vendor': None,
        'cloud_provider': 'AWS',
        'cluster_name': None,
        'container_id': None,
        'contains_featured_host': 'NO',
        'contains_featured_ip': 'NO',
        'contains_featured_user': 'NO',
        'deduplicate_tokens': None,
        'description': 'The cloud Identity svc_dev has executed an API call. The identity\'s user-agent call is aws-cli/1.22.34 Python/3.10.4 Linux/5.16.0-kali7-cloud-amd64 botocore/1.27.28. The operation was performed on AWS/666688938958',
        'detection_timestamp': 1676282568000,
        'dns_query_name': None,
        'dst_action_country': None,
        'dst_action_external_hostname': None,
        'dst_action_external_port': None,
        'dst_agent_id': None,
        'dst_association_strength': None,
        'dst_causality_actor_process_execution_time': None,
        'dynamic_fields': None,
        'end_match_attempt_ts': None,
        'endpoint_id': None,
        'event_id': '210db407-f1fa-52c7-9ff5-bc3fd27426a9',
        'event_sub_type': 3,
        'event_timestamp': 1675768999000,
        'event_type': 'Cloud Audit Log',
        'events_length': 1,
        'external_id': '8940f509-5f71-4309-b0ea-4b48eb2d0fd7',
        'filter_rule_id': None,
        'fw_app_category': None,
        'fw_app_id': None,
        'fw_app_subcategory': None,
        'fw_app_technology': None,
        'fw_device_name': None,
        'fw_email_recipient': None,
        'fw_email_sender': None,
        'fw_email_subject': None,
        'fw_interface_from': None,
        'fw_interface_to': None,
        'fw_is_phishing': 'N/A',
        'fw_misc': None,
        'fw_rule': None,
        'fw_rule_id': None,
        'fw_serial_number': None,
        'fw_url_domain': None,
        'fw_vsys': None,
        'fw_xff': None,
        'host_ip': '18.221.214.175',
        'host_ip_list': [
          '18.221.214.175'
        ],
        'host_name': None,
        'identity_sub_type': 'IAM',
        'identity_type': 'USER',
        'image_name': None,
        'is_pcap': False,
        'is_whitelisted': False,
        'last_modified_ts': 1686652368965,
        'local_insert_ts': 1675769251633,
        'mac': None,
        'malicious_urls': None,
        'matching_service_rule_id': 'f6e71c10-dfd2-11eb-8670-acde48001122',
        'matching_status': 'MATCHED',
        'mitre_tactic_id_and_name': 'TA0002 - Execution',
        'mitre_technique_id_and_name': 'T1204 - User Execution',
        'module_id': None,
        'name': 'Penetration testing tool activity',
        'operation_name': 'GET',
        'original_tags': 'DS:Amazon/AWS',
        'os_actor_causality_id': None,
        'os_actor_effective_username': None,
        'os_actor_process_causality_id': None,
        'os_actor_process_command_line': None,
        'os_actor_process_image_name': None,
        'os_actor_process_image_path': None,
        'os_actor_process_image_sha256': None,
        'os_actor_process_instance_id': None,
        'os_actor_process_os_pid': None,
        'os_actor_process_signature_status': 'N/A',
        'os_actor_process_signature_vendor': None,
        'os_actor_thread_thread_id': None,
        'project': '666688938958',
        'referenced_resource': None,
        'resolution_comment': None,
        'resolution_status': 'STATUS_020_UNDER_INVESTIGATION',
        'resource_sub_type': None,
        'resource_type': 'IDENTITY_ACCESS_MANAGEMENT',
        'severity': 'medium',
        'source': 'XDR Analytics BIOC',
        'starred': False,
        'story_id': None,
        'tags': 'DS:Amazon/AWS',
        'user_agent': 'aws-cli/1.22.34 Python/3.10.4 Linux/5.16.0-kali7-cloud-amd64 botocore/1.27.28',
        'user_name': 'svc_dev'
      },
      {
        'action': 'DETECTED',
        'action_country': 'UNKNOWN',
        'action_external_hostname': None,
        'action_file_macro_sha256': None,
        'action_file_md5': None,
        'action_file_name': None,
        'action_file_path': None,
        'action_file_sha256': None,
        'action_local_ip': None,
        'action_local_ip_v6': None,
        'action_local_port': None,
        'action_pretty': 'Detected',
        'action_process_causality_id': None,
        'action_process_image_command_line': None,
        'action_process_image_name': None,
        'action_process_image_sha256': None,
        'action_process_instance_id': None,
        'action_process_signature_status': 'N/A',
        'action_process_signature_vendor': None,
        'action_registry_data': None,
        'action_registry_full_key': None,
        'action_registry_key_name': None,
        'action_registry_value_name': None,
        'action_remote_ip': None,
        'action_remote_ip_v6': None,
        'action_remote_port': None,
        'actor_causality_id': None,
        'actor_process_causality_id': None,
        'actor_process_command_line': None,
        'actor_process_image_md5': None,
        'actor_process_image_name': None,
        'actor_process_image_path': None,
        'actor_process_image_sha256': None,
        'actor_process_instance_id': None,
        'actor_process_os_pid': None,
        'actor_process_signature_status': 'N/A',
        'actor_process_signature_vendor': None,
        'actor_thread_thread_id': None,
        'agent_data_collection_status': None,
        'agent_device_domain': None,
        'agent_fqdn': None,
        'agent_host_boot_time': None,
        'agent_install_type': 'NA',
        'agent_ip_addresses_v6': None,
        'agent_is_vdi': None,
        'agent_os_sub_type': None,
        'agent_os_type': 'NO_HOST',
        'agent_version': None,
        'alert_id': '16217',
        'alert_type': 'Unclassified',
        'association_strength': 50,
        'attempt_counter': 0,
        'bioc_category_enum_key': None,
        'bioc_indicator': None,
        'case_id': 1284,
        'category': 'Initial Access',
        'causality_actor_causality_id': None,
        'causality_actor_process_command_line': None,
        'causality_actor_process_execution_time': None,
        'causality_actor_process_image_md5': None,
        'causality_actor_process_image_name': None,
        'causality_actor_process_image_path': None,
        'causality_actor_process_image_sha256': None,
        'causality_actor_process_signature_status': 'N/A',
        'causality_actor_process_signature_vendor': None,
        'cloud_provider': 'AWS',
        'cluster_name': None,
        'container_id': None,
        'contains_featured_host': 'NO',
        'contains_featured_ip': 'NO',
        'contains_featured_user': 'NO',
        'deduplicate_tokens': None,
        'description': 'The cloud identity svc_dev connected from Czechia. This behavior was not observed in the last 30 days. The country Czechia was not seen in the organization in the last 30 days',
        'detection_timestamp': 1676281911000,
        'dns_query_name': None,
        'dst_action_country': None,
        'dst_action_external_hostname': None,
        'dst_action_external_port': None,
        'dst_agent_id': None,
        'dst_association_strength': None,
        'dst_causality_actor_process_execution_time': None,
        'dynamic_fields': None,
        'end_match_attempt_ts': None,
        'endpoint_id': None,
        'event_id': '44436ab8-bcdf-5753-829c-7de557d7361b',
        'event_sub_type': 3,
        'event_timestamp': 1676281911000,
        'event_type': 'Cloud Audit Log',
        'events_length': 1,
        'external_id': 'e2d60f8e-fc57-497e-8080-82e75802b190',
        'filter_rule_id': None,
        'fw_app_category': None,
        'fw_app_id': None,
        'fw_app_subcategory': None,
        'fw_app_technology': None,
        'fw_device_name': None,
        'fw_email_recipient': None,
        'fw_email_sender': None,
        'fw_email_subject': None,
        'fw_interface_from': None,
        'fw_interface_to': None,
        'fw_is_phishing': 'N/A',
        'fw_misc': None,
        'fw_rule': None,
        'fw_rule_id': None,
        'fw_serial_number': None,
        'fw_url_domain': None,
        'fw_vsys': None,
        'fw_xff': None,
        'host_ip': '130.193.10.21',
        'host_ip_list': [
          '130.193.10.21'
        ],
        'host_name': None,
        'identity_sub_type': 'IAM',
        'identity_type': 'USER',
        'image_name': None,
        'is_pcap': False,
        'is_whitelisted': False,
        'last_modified_ts': 1686735220954,
        'local_insert_ts': 1676282105888,
        'mac': None,
        'malicious_urls': None,
        'matching_service_rule_id': '32cff288-9e1e-11ec-ac34-acde48001122',
        'matching_status': 'MATCHED',
        'mitre_tactic_id_and_name': 'TA0001 - Initial Access',
        'mitre_technique_id_and_name': 'T1078 - Valid Accounts',
        'module_id': None,
        'name': 'A cloud identity executed an API call from an unusual country',
        'operation_name': 'ENUMERATE',
        'original_tags': 'DS:Amazon/AWS',
        'os_actor_causality_id': None,
        'os_actor_effective_username': None,
        'os_actor_process_causality_id': None,
        'os_actor_process_command_line': None,
        'os_actor_process_image_name': None,
        'os_actor_process_image_path': None,
        'os_actor_process_image_sha256': None,
        'os_actor_process_instance_id': None,
        'os_actor_process_os_pid': None,
        'os_actor_process_signature_status': 'N/A',
        'os_actor_process_signature_vendor': None,
        'os_actor_thread_thread_id': None,
        'project': '666688938958',
        'referenced_resource': None,
        'resolution_comment': None,
        'resolution_status': 'STATUS_020_UNDER_INVESTIGATION',
        'resource_sub_type': None,
        'resource_type': 'COMPUTE',
        'severity': 'high',
        'source': 'XDR Analytics BIOC',
        'starred': False,
        'story_id': None,
        'tags': 'DS:Amazon/AWS',
        'user_agent': 'Boto3/1.24.93 Python/3.10.0 Darwin/20.6.0 Botocore/1.27.93',
        'user_name': 'svc_dev'
      },
      {
        'action': 'DETECTED',
        'action_country': 'UNKNOWN',
        'action_external_hostname': None,
        'action_file_macro_sha256': None,
        'action_file_md5': None,
        'action_file_name': None,
        'action_file_path': None,
        'action_file_sha256': None,
        'action_local_ip': None,
        'action_local_ip_v6': None,
        'action_local_port': None,
        'action_pretty': 'Detected',
        'action_process_causality_id': None,
        'action_process_image_command_line': None,
        'action_process_image_name': None,
        'action_process_image_sha256': None,
        'action_process_instance_id': None,
        'action_process_signature_status': 'N/A',
        'action_process_signature_vendor': None,
        'action_registry_data': None,
        'action_registry_full_key': None,
        'action_registry_key_name': None,
        'action_registry_value_name': None,
        'action_remote_ip': None,
        'action_remote_ip_v6': None,
        'action_remote_port': None,
        'actor_causality_id': None,
        'actor_process_causality_id': None,
        'actor_process_command_line': None,
        'actor_process_image_md5': None,
        'actor_process_image_name': None,
        'actor_process_image_path': None,
        'actor_process_image_sha256': None,
        'actor_process_instance_id': None,
        'actor_process_os_pid': None,
        'actor_process_signature_status': 'N/A',
        'actor_process_signature_vendor': None,
        'actor_thread_thread_id': None,
        'agent_data_collection_status': None,
        'agent_device_domain': None,
        'agent_fqdn': None,
        'agent_host_boot_time': None,
        'agent_install_type': 'NA',
        'agent_ip_addresses_v6': None,
        'agent_is_vdi': None,
        'agent_os_sub_type': None,
        'agent_os_type': 'NO_HOST',
        'agent_version': None,
        'alert_id': '16211',
        'alert_type': 'Unclassified',
        'association_strength': 50,
        'attempt_counter': 0,
        'bioc_category_enum_key': None,
        'bioc_indicator': None,
        'case_id': 1284,
        'category': 'Command and Control',
        'causality_actor_causality_id': None,
        'causality_actor_process_command_line': None,
        'causality_actor_process_execution_time': None,
        'causality_actor_process_image_md5': None,
        'causality_actor_process_image_name': None,
        'causality_actor_process_image_path': None,
        'causality_actor_process_image_sha256': None,
        'causality_actor_process_signature_status': 'N/A',
        'causality_actor_process_signature_vendor': None,
        'cloud_provider': 'AWS',
        'cluster_name': None,
        'container_id': None,
        'contains_featured_host': 'NO',
        'contains_featured_ip': 'NO',
        'contains_featured_user': 'NO',
        'deduplicate_tokens': None,
        'description': 'The cloud user svc_dev has called an API from 192.42.116.193. This IP address is known as a Tor exit node\'s IP address in the last 36 hours',
        'detection_timestamp': 1676281453000,
        'dns_query_name': None,
        'dst_action_country': None,
        'dst_action_external_hostname': None,
        'dst_action_external_port': None,
        'dst_agent_id': None,
        'dst_association_strength': None,
        'dst_causality_actor_process_execution_time': None,
        'dynamic_fields': None,
        'end_match_attempt_ts': None,
        'endpoint_id': None,
        'event_id': 'aa5f2e70-3a1e-5244-8b65-47ea323bbce2',
        'event_sub_type': 3,
        'event_timestamp': 1676281453000,
        'event_type': 'Cloud Audit Log',
        'events_length': 1,
        'external_id': 'eb419ce4-a9cc-460d-bf40-f57436abfc18',
        'filter_rule_id': None,
        'fw_app_category': None,
        'fw_app_id': None,
        'fw_app_subcategory': None,
        'fw_app_technology': None,
        'fw_device_name': None,
        'fw_email_recipient': None,
        'fw_email_sender': None,
        'fw_email_subject': None,
        'fw_interface_from': None,
        'fw_interface_to': None,
        'fw_is_phishing': 'N/A',
        'fw_misc': None,
        'fw_rule': None,
        'fw_rule_id': None,
        'fw_serial_number': None,
        'fw_url_domain': None,
        'fw_vsys': None,
        'fw_xff': None,
        'host_ip': '130.193.10.21',
        'host_ip_list': [
          '130.193.10.21'
        ],
        'host_name': None,
        'identity_sub_type': 'IAM',
        'identity_type': 'USER',
        'image_name': None,
        'is_pcap': False,
        'is_whitelisted': False,
        'last_modified_ts': 1686650948777,
        'local_insert_ts': 1676281588380,
        'mac': None,
        'malicious_urls': None,
        'matching_service_rule_id': 'ac17179d-68dd-46cc-8d2a-68d506e6626e',
        'matching_status': 'MATCHED',
        'mitre_tactic_id_and_name': 'TA0011 - Command and Control',
        'mitre_technique_id_and_name': 'T1090.003 - Proxy: Multi-hop Proxy',
        'module_id': None,
        'name': 'Suspicious API call from a Tor exit node',
        'operation_name': 'GET',
        'original_tags': 'DS:Amazon/AWS',
        'os_actor_causality_id': None,
        'os_actor_effective_username': None,
        'os_actor_process_causality_id': None,
        'os_actor_process_command_line': None,
        'os_actor_process_image_name': None,
        'os_actor_process_image_path': None,
        'os_actor_process_image_sha256': None,
        'os_actor_process_instance_id': None,
        'os_actor_process_os_pid': None,
        'os_actor_process_signature_status': 'N/A',
        'os_actor_process_signature_vendor': None,
        'os_actor_thread_thread_id': None,
        'project': '666688938958',
        'referenced_resource': None,
        'resolution_comment': None,
        'resolution_status': 'STATUS_020_UNDER_INVESTIGATION',
        'resource_sub_type': None,
        'resource_type': 'IDENTITY_ACCESS_MANAGEMENT',
        'severity': 'high',
        'source': 'XDR Analytics BIOC',
        'starred': False,
        'story_id': None,
        'tags': 'DS:Amazon/AWS',
        'user_agent': 'aws-cli/1.22.34 Python/3.10.4 Linux/5.16.0-kali7-cloud-amd64 botocore/1.27.28',
        'user_name': 'svc_dev'
      }
    ],
    'total_count': 5
  },
  'file_artifacts': {
    'data': [],
    'total_count': 0
  },
  'incident': {
    'aggregated_score': None,
    'alert_categories': [
      'Command and Control',
      'Defense Evasion',
      'Execution',
      'Impact',
      'Initial Access'
    ],
    'alert_count': 5,
    'alerts': [
      {
        'action': 'DETECTED',
        'action_country': 'UNKNOWN',
        'action_external_hostname': None,
        'action_file_macro_sha256': None,
        'action_file_md5': None,
        'action_file_name': None,
        'action_file_path': None,
        'action_file_sha256': None,
        'action_local_ip': None,
        'action_local_ip_v6': None,
        'action_local_port': None,
        'action_pretty': 'Detected',
        'action_process_causality_id': None,
        'action_process_image_command_line': None,
        'action_process_image_name': None,
        'action_process_image_sha256': None,
        'action_process_instance_id': None,
        'action_process_signature_status': 'N/A',
        'action_process_signature_vendor': None,
        'action_registry_data': None,
        'action_registry_full_key': None,
        'action_registry_key_name': None,
        'action_registry_value_name': None,
        'action_remote_ip': None,
        'action_remote_ip_v6': None,
        'action_remote_port': None,
        'actor_causality_id': None,
        'actor_process_causality_id': None,
        'actor_process_command_line': None,
        'actor_process_image_md5': None,
        'actor_process_image_name': None,
        'actor_process_image_path': None,
        'actor_process_image_sha256': None,
        'actor_process_instance_id': None,
        'actor_process_os_pid': None,
        'actor_process_signature_status': 'N/A',
        'actor_process_signature_vendor': None,
        'actor_thread_thread_id': None,
        'agent_data_collection_status': None,
        'agent_device_domain': None,
        'agent_fqdn': None,
        'agent_host_boot_time': None,
        'agent_install_type': 'NA',
        'agent_ip_addresses_v6': None,
        'agent_is_vdi': None,
        'agent_os_sub_type': None,
        'agent_os_type': 'NO_HOST',
        'agent_version': None,
        'alert_id': '14827',
        'alert_type': 'Unclassified',
        'association_strength': 50,
        'attempt_counter': 0,
        'bioc_category_enum_key': None,
        'bioc_indicator': None,
        'case_id': 1284,
        'category': 'Defense Evasion',
        'causality_actor_causality_id': None,
        'causality_actor_process_command_line': None,
        'causality_actor_process_execution_time': None,
        'causality_actor_process_image_md5': None,
        'causality_actor_process_image_name': None,
        'causality_actor_process_image_path': None,
        'causality_actor_process_image_sha256': None,
        'causality_actor_process_signature_status': 'N/A',
        'causality_actor_process_signature_vendor': None,
        'cloud_provider': 'AWS',
        'cluster_name': None,
        'container_id': None,
        'contains_featured_host': 'NO',
        'contains_featured_ip': 'NO',
        'contains_featured_user': 'NO',
        'deduplicate_tokens': None,
        'description': 'An unusual activity was performed in AWS, region eu-west-1. The CREATE operation was performed against a COMPUTE service in the project 666688938958. This behavior was not observed in the last 30 days',
        'detection_timestamp': 1676282755000,
        'dns_query_name': None,
        'dst_action_country': None,
        'dst_action_external_hostname': None,
        'dst_action_external_port': None,
        'dst_agent_id': None,
        'dst_association_strength': None,
        'dst_causality_actor_process_execution_time': None,
        'dynamic_fields': None,
        'end_match_attempt_ts': None,
        'endpoint_id': None,
        'event_id': '2db6ffaa-694d-560c-bdd1-8f22e97331db_4',
        'event_sub_type': 3,
        'event_timestamp': 1672665266000,
        'event_type': 'Cloud Audit Log',
        'events_length': 1,
        'external_id': '8fa790af-ee28-4f27-9e5e-343e4053c44c',
        'filter_rule_id': None,
        'fw_app_category': None,
        'fw_app_id': None,
        'fw_app_subcategory': None,
        'fw_app_technology': None,
        'fw_device_name': None,
        'fw_email_recipient': None,
        'fw_email_sender': None,
        'fw_email_subject': None,
        'fw_interface_from': None,
        'fw_interface_to': None,
        'fw_is_phishing': 'N/A',
        'fw_misc': None,
        'fw_rule': None,
        'fw_rule_id': None,
        'fw_serial_number': None,
        'fw_url_domain': None,
        'fw_vsys': None,
        'fw_xff': None,
        'host_ip': '31.154.166.148',
        'host_ip_list': [
          '31.154.166.148'
        ],
        'host_name': None,
        'identity_sub_type': 'IAM',
        'identity_type': 'USER',
        'image_name': None,
        'is_pcap': False,
        'is_whitelisted': False,
        'last_modified_ts': 1686732679256,
        'local_insert_ts': 1672665528800,
        'mac': None,
        'malicious_urls': None,
        'matching_service_rule_id': '22e661ae-3081-4a2d-9550-c65b6b660af1',
        'matching_status': 'MATCHED',
        'mitre_tactic_id_and_name': 'TA0005 - Defense Evasion',
        'mitre_technique_id_and_name': 'T1535 - Unused/Unsupported Cloud Regions',
        'module_id': None,
        'name': 'A cloud compute instance was created in a dormant region',
        'operation_name': 'CREATE',
        'original_tags': 'DS:Amazon/AWS',
        'os_actor_causality_id': None,
        'os_actor_effective_username': None,
        'os_actor_process_causality_id': None,
        'os_actor_process_command_line': None,
        'os_actor_process_image_name': None,
        'os_actor_process_image_path': None,
        'os_actor_process_image_sha256': None,
        'os_actor_process_instance_id': None,
        'os_actor_process_os_pid': None,
        'os_actor_process_signature_status': 'N/A',
        'os_actor_process_signature_vendor': None,
        'os_actor_thread_thread_id': None,
        'project': '666688938958',
        'referenced_resource': 'arn:aws:ec2:us-west-2:666688938958:vpc/vpc-04cfed27f1f06f385',
        'resolution_comment': None,
        'resolution_status': 'STATUS_020_UNDER_INVESTIGATION',
        'resource_sub_type': 'VPC',
        'resource_type': 'COMPUTE',
        'severity': 'medium',
        'source': 'XDR Analytics BIOC',
        'starred': False,
        'story_id': None,
        'tags': 'DS:Amazon/AWS',
        'user_agent': 'Boto3/1.24.93 Python/3.10.0 Darwin/20.6.0 Botocore/1.27.93',
        'user_name': 'svc_dev'
      },
      {
        'action': 'DETECTED',
        'action_country': 'UNKNOWN',
        'action_external_hostname': None,
        'action_file_macro_sha256': None,
        'action_file_md5': None,
        'action_file_name': None,
        'action_file_path': None,
        'action_file_sha256': None,
        'action_local_ip': None,
        'action_local_ip_v6': None,
        'action_local_port': None,
        'action_pretty': 'Detected',
        'action_process_causality_id': None,
        'action_process_image_command_line': None,
        'action_process_image_name': None,
        'action_process_image_sha256': None,
        'action_process_instance_id': None,
        'action_process_signature_status': 'N/A',
        'action_process_signature_vendor': None,
        'action_registry_data': None,
        'action_registry_full_key': None,
        'action_registry_key_name': None,
        'action_registry_value_name': None,
        'action_remote_ip': None,
        'action_remote_ip_v6': None,
        'action_remote_port': None,
        'actor_causality_id': None,
        'actor_process_causality_id': None,
        'actor_process_command_line': None,
        'actor_process_image_md5': None,
        'actor_process_image_name': None,
        'actor_process_image_path': None,
        'actor_process_image_sha256': None,
        'actor_process_instance_id': None,
        'actor_process_os_pid': None,
        'actor_process_signature_status': 'N/A',
        'actor_process_signature_vendor': None,
        'actor_thread_thread_id': None,
        'agent_data_collection_status': None,
        'agent_device_domain': None,
        'agent_fqdn': None,
        'agent_host_boot_time': None,
        'agent_install_type': 'NA',
        'agent_ip_addresses_v6': None,
        'agent_is_vdi': None,
        'agent_os_sub_type': None,
        'agent_os_type': 'NO_HOST',
        'agent_version': None,
        'alert_id': '16223',
        'alert_type': 'Unclassified',
        'association_strength': None,
        'attempt_counter': 0,
        'bioc_category_enum_key': None,
        'bioc_indicator': None,
        'case_id': 1284,
        'category': 'Impact',
        'causality_actor_causality_id': None,
        'causality_actor_process_command_line': None,
        'causality_actor_process_execution_time': None,
        'causality_actor_process_image_md5': None,
        'causality_actor_process_image_name': None,
        'causality_actor_process_image_path': None,
        'causality_actor_process_image_sha256': None,
        'causality_actor_process_signature_status': 'N/A',
        'causality_actor_process_signature_vendor': None,
        'cloud_provider': 'AWS',
        'cluster_name': None,
        'container_id': None,
        'contains_featured_host': 'NO',
        'contains_featured_ip': 'NO',
        'contains_featured_user': 'NO',
        'deduplicate_tokens': None,
        'description': 'The identity svc_dev created an unusual amount of compute resources. The activity seen on AWS provider within 666688938958 project on eu-west-1 region',
        'detection_timestamp': 1676282745000,
        'dns_query_name': None,
        'dst_action_country': None,
        'dst_action_external_hostname': None,
        'dst_action_external_port': None,
        'dst_agent_id': None,
        'dst_association_strength': None,
        'dst_causality_actor_process_execution_time': None,
        'dynamic_fields': None,
        'end_match_attempt_ts': None,
        'endpoint_id': '-1',
        'event_id': '36451364-79e7-582b-a5df-e331bd45bb1b_4',
        'event_sub_type': 3,
        'event_timestamp': 1676282725000,
        'event_type': 'Cloud Audit Log',
        'events_length': 1,
        'external_id': '5c5beda1-a9ac-4799-959f-0f6b16f23f3a',
        'filter_rule_id': None,
        'fw_app_category': None,
        'fw_app_id': None,
        'fw_app_subcategory': None,
        'fw_app_technology': None,
        'fw_device_name': None,
        'fw_email_recipient': None,
        'fw_email_sender': None,
        'fw_email_subject': None,
        'fw_interface_from': None,
        'fw_interface_to': None,
        'fw_is_phishing': 'N/A',
        'fw_misc': None,
        'fw_rule': None,
        'fw_rule_id': None,
        'fw_serial_number': None,
        'fw_url_domain': None,
        'fw_vsys': None,
        'fw_xff': None,
        'host_ip': None,
        'host_ip_list': [],
        'host_name': None,
        'identity_sub_type': 'IAM',
        'identity_type': 'USER',
        'image_name': None,
        'is_pcap': False,
        'is_whitelisted': False,
        'last_modified_ts': 1686731961937,
        'local_insert_ts': 1676282795282,
        'mac': None,
        'malicious_urls': None,
        'matching_service_rule_id': '653d6d6c-2f5b-11ed-8017-acde48001122',
        'matching_status': 'MATCHED',
        'mitre_tactic_id_and_name': 'TA0040 - Impact',
        'mitre_technique_id_and_name': 'T1496 - Resource Hijacking',
        'module_id': None,
        'name': 'Allocation of multiple cloud compute resources with accelerator gear',
        'operation_name': 'CREATE',
        'original_tags': 'DS:Amazon/AWS',
        'os_actor_causality_id': None,
        'os_actor_effective_username': None,
        'os_actor_process_causality_id': None,
        'os_actor_process_command_line': None,
        'os_actor_process_image_name': None,
        'os_actor_process_image_path': None,
        'os_actor_process_image_sha256': None,
        'os_actor_process_instance_id': None,
        'os_actor_process_os_pid': None,
        'os_actor_process_signature_status': 'N/A',
        'os_actor_process_signature_vendor': None,
        'os_actor_thread_thread_id': None,
        'project': '666688938958',
        'referenced_resource': 'arn:aws:ec2:eu-west-1:666688938958:instance/i-0dc36ef8209f667fb',
        'resolution_comment': None,
        'resolution_status': 'STATUS_020_UNDER_INVESTIGATION',
        'resource_sub_type': 'COMPUTE_INSTANCE',
        'resource_type': 'COMPUTE',
        'severity': 'high',
        'source': 'XDR Analytics',
        'starred': False,
        'story_id': None,
        'tags': 'DS:Amazon/AWS',
        'user_agent': 'Boto3/1.24.93 Python/3.10.0 Darwin/20.6.0 Botocore/1.27.93',
        'user_name': 'svc_dev'
      },
      {
        'action': 'DETECTED',
        'action_country': 'UNKNOWN',
        'action_external_hostname': None,
        'action_file_macro_sha256': None,
        'action_file_md5': None,
        'action_file_name': None,
        'action_file_path': None,
        'action_file_sha256': None,
        'action_local_ip': None,
        'action_local_ip_v6': None,
        'action_local_port': None,
        'action_pretty': 'Detected',
        'action_process_causality_id': None,
        'action_process_image_command_line': None,
        'action_process_image_name': None,
        'action_process_image_sha256': None,
        'action_process_instance_id': None,
        'action_process_signature_status': 'N/A',
        'action_process_signature_vendor': None,
        'action_registry_data': None,
        'action_registry_full_key': None,
        'action_registry_key_name': None,
        'action_registry_value_name': None,
        'action_remote_ip': None,
        'action_remote_ip_v6': None,
        'action_remote_port': None,
        'actor_causality_id': None,
        'actor_process_causality_id': None,
        'actor_process_command_line': None,
        'actor_process_image_md5': None,
        'actor_process_image_name': None,
        'actor_process_image_path': None,
        'actor_process_image_sha256': None,
        'actor_process_instance_id': None,
        'actor_process_os_pid': None,
        'actor_process_signature_status': 'N/A',
        'actor_process_signature_vendor': None,
        'actor_thread_thread_id': None,
        'agent_data_collection_status': None,
        'agent_device_domain': None,
        'agent_fqdn': None,
        'agent_host_boot_time': None,
        'agent_install_type': 'NA',
        'agent_ip_addresses_v6': None,
        'agent_is_vdi': None,
        'agent_os_sub_type': None,
        'agent_os_type': 'NO_HOST',
        'agent_version': None,
        'alert_id': '14873',
        'alert_type': 'Unclassified',
        'association_strength': 50,
        'attempt_counter': 0,
        'bioc_category_enum_key': None,
        'bioc_indicator': None,
        'case_id': 1284,
        'category': 'Execution',
        'causality_actor_causality_id': None,
        'causality_actor_process_command_line': None,
        'causality_actor_process_execution_time': None,
        'causality_actor_process_image_md5': None,
        'causality_actor_process_image_name': None,
        'causality_actor_process_image_path': None,
        'causality_actor_process_image_sha256': None,
        'causality_actor_process_signature_status': 'N/A',
        'causality_actor_process_signature_vendor': None,
        'cloud_provider': 'AWS',
        'cluster_name': None,
        'container_id': None,
        'contains_featured_host': 'NO',
        'contains_featured_ip': 'NO',
        'contains_featured_user': 'NO',
        'deduplicate_tokens': None,
        'description': 'The cloud Identity svc_dev has executed an API call. The identity\'s user-agent call is aws-cli/1.22.34 Python/3.10.4 Linux/5.16.0-kali7-cloud-amd64 botocore/1.27.28. The operation was performed on AWS/666688938958',
        'detection_timestamp': 1676282568000,
        'dns_query_name': None,
        'dst_action_country': None,
        'dst_action_external_hostname': None,
        'dst_action_external_port': None,
        'dst_agent_id': None,
        'dst_association_strength': None,
        'dst_causality_actor_process_execution_time': None,
        'dynamic_fields': None,
        'end_match_attempt_ts': None,
        'endpoint_id': None,
        'event_id': '210db407-f1fa-52c7-9ff5-bc3fd27426a9',
        'event_sub_type': 3,
        'event_timestamp': 1675768999000,
        'event_type': 'Cloud Audit Log',
        'events_length': 1,
        'external_id': '8940f509-5f71-4309-b0ea-4b48eb2d0fd7',
        'filter_rule_id': None,
        'fw_app_category': None,
        'fw_app_id': None,
        'fw_app_subcategory': None,
        'fw_app_technology': None,
        'fw_device_name': None,
        'fw_email_recipient': None,
        'fw_email_sender': None,
        'fw_email_subject': None,
        'fw_interface_from': None,
        'fw_interface_to': None,
        'fw_is_phishing': 'N/A',
        'fw_misc': None,
        'fw_rule': None,
        'fw_rule_id': None,
        'fw_serial_number': None,
        'fw_url_domain': None,
        'fw_vsys': None,
        'fw_xff': None,
        'host_ip': '18.221.214.175',
        'host_ip_list': [
          '18.221.214.175'
        ],
        'host_name': None,
        'identity_sub_type': 'IAM',
        'identity_type': 'USER',
        'image_name': None,
        'is_pcap': False,
        'is_whitelisted': False,
        'last_modified_ts': 1686652368965,
        'local_insert_ts': 1675769251633,
        'mac': None,
        'malicious_urls': None,
        'matching_service_rule_id': 'f6e71c10-dfd2-11eb-8670-acde48001122',
        'matching_status': 'MATCHED',
        'mitre_tactic_id_and_name': 'TA0002 - Execution',
        'mitre_technique_id_and_name': 'T1204 - User Execution',
        'module_id': None,
        'name': 'Penetration testing tool activity',
        'operation_name': 'GET',
        'original_tags': 'DS:Amazon/AWS',
        'os_actor_causality_id': None,
        'os_actor_effective_username': None,
        'os_actor_process_causality_id': None,
        'os_actor_process_command_line': None,
        'os_actor_process_image_name': None,
        'os_actor_process_image_path': None,
        'os_actor_process_image_sha256': None,
        'os_actor_process_instance_id': None,
        'os_actor_process_os_pid': None,
        'os_actor_process_signature_status': 'N/A',
        'os_actor_process_signature_vendor': None,
        'os_actor_thread_thread_id': None,
        'project': '666688938958',
        'referenced_resource': None,
        'resolution_comment': None,
        'resolution_status': 'STATUS_020_UNDER_INVESTIGATION',
        'resource_sub_type': None,
        'resource_type': 'IDENTITY_ACCESS_MANAGEMENT',
        'severity': 'medium',
        'source': 'XDR Analytics BIOC',
        'starred': False,
        'story_id': None,
        'tags': 'DS:Amazon/AWS',
        'user_agent': 'aws-cli/1.22.34 Python/3.10.4 Linux/5.16.0-kali7-cloud-amd64 botocore/1.27.28',
        'user_name': 'svc_dev'
      },
      {
        'action': 'DETECTED',
        'action_country': 'UNKNOWN',
        'action_external_hostname': None,
        'action_file_macro_sha256': None,
        'action_file_md5': None,
        'action_file_name': None,
        'action_file_path': None,
        'action_file_sha256': None,
        'action_local_ip': None,
        'action_local_ip_v6': None,
        'action_local_port': None,
        'action_pretty': 'Detected',
        'action_process_causality_id': None,
        'action_process_image_command_line': None,
        'action_process_image_name': None,
        'action_process_image_sha256': None,
        'action_process_instance_id': None,
        'action_process_signature_status': 'N/A',
        'action_process_signature_vendor': None,
        'action_registry_data': None,
        'action_registry_full_key': None,
        'action_registry_key_name': None,
        'action_registry_value_name': None,
        'action_remote_ip': None,
        'action_remote_ip_v6': None,
        'action_remote_port': None,
        'actor_causality_id': None,
        'actor_process_causality_id': None,
        'actor_process_command_line': None,
        'actor_process_image_md5': None,
        'actor_process_image_name': None,
        'actor_process_image_path': None,
        'actor_process_image_sha256': None,
        'actor_process_instance_id': None,
        'actor_process_os_pid': None,
        'actor_process_signature_status': 'N/A',
        'actor_process_signature_vendor': None,
        'actor_thread_thread_id': None,
        'agent_data_collection_status': None,
        'agent_device_domain': None,
        'agent_fqdn': None,
        'agent_host_boot_time': None,
        'agent_install_type': 'NA',
        'agent_ip_addresses_v6': None,
        'agent_is_vdi': None,
        'agent_os_sub_type': None,
        'agent_os_type': 'NO_HOST',
        'agent_version': None,
        'alert_id': '16217',
        'alert_type': 'Unclassified',
        'association_strength': 50,
        'attempt_counter': 0,
        'bioc_category_enum_key': None,
        'bioc_indicator': None,
        'case_id': 1284,
        'category': 'Initial Access',
        'causality_actor_causality_id': None,
        'causality_actor_process_command_line': None,
        'causality_actor_process_execution_time': None,
        'causality_actor_process_image_md5': None,
        'causality_actor_process_image_name': None,
        'causality_actor_process_image_path': None,
        'causality_actor_process_image_sha256': None,
        'causality_actor_process_signature_status': 'N/A',
        'causality_actor_process_signature_vendor': None,
        'cloud_provider': 'AWS',
        'cluster_name': None,
        'container_id': None,
        'contains_featured_host': 'NO',
        'contains_featured_ip': 'NO',
        'contains_featured_user': 'NO',
        'deduplicate_tokens': None,
        'description': 'The cloud identity svc_dev connected from Czechia. This behavior was not observed in the last 30 days. The country Czechia was not seen in the organization in the last 30 days',
        'detection_timestamp': 1676281911000,
        'dns_query_name': None,
        'dst_action_country': None,
        'dst_action_external_hostname': None,
        'dst_action_external_port': None,
        'dst_agent_id': None,
        'dst_association_strength': None,
        'dst_causality_actor_process_execution_time': None,
        'dynamic_fields': None,
        'end_match_attempt_ts': None,
        'endpoint_id': None,
        'event_id': '44436ab8-bcdf-5753-829c-7de557d7361b',
        'event_sub_type': 3,
        'event_timestamp': 1676281911000,
        'event_type': 'Cloud Audit Log',
        'events_length': 1,
        'external_id': 'e2d60f8e-fc57-497e-8080-82e75802b190',
        'filter_rule_id': None,
        'fw_app_category': None,
        'fw_app_id': None,
        'fw_app_subcategory': None,
        'fw_app_technology': None,
        'fw_device_name': None,
        'fw_email_recipient': None,
        'fw_email_sender': None,
        'fw_email_subject': None,
        'fw_interface_from': None,
        'fw_interface_to': None,
        'fw_is_phishing': 'N/A',
        'fw_misc': None,
        'fw_rule': None,
        'fw_rule_id': None,
        'fw_serial_number': None,
        'fw_url_domain': None,
        'fw_vsys': None,
        'fw_xff': None,
        'host_ip': '130.193.10.21',
        'host_ip_list': [
          '130.193.10.21'
        ],
        'host_name': None,
        'identity_sub_type': 'IAM',
        'identity_type': 'USER',
        'image_name': None,
        'is_pcap': False,
        'is_whitelisted': False,
        'last_modified_ts': 1686735220954,
        'local_insert_ts': 1676282105888,
        'mac': None,
        'malicious_urls': None,
        'matching_service_rule_id': '32cff288-9e1e-11ec-ac34-acde48001122',
        'matching_status': 'MATCHED',
        'mitre_tactic_id_and_name': 'TA0001 - Initial Access',
        'mitre_technique_id_and_name': 'T1078 - Valid Accounts',
        'module_id': None,
        'name': 'A cloud identity executed an API call from an unusual country',
        'operation_name': 'ENUMERATE',
        'original_tags': 'DS:Amazon/AWS',
        'os_actor_causality_id': None,
        'os_actor_effective_username': None,
        'os_actor_process_causality_id': None,
        'os_actor_process_command_line': None,
        'os_actor_process_image_name': None,
        'os_actor_process_image_path': None,
        'os_actor_process_image_sha256': None,
        'os_actor_process_instance_id': None,
        'os_actor_process_os_pid': None,
        'os_actor_process_signature_status': 'N/A',
        'os_actor_process_signature_vendor': None,
        'os_actor_thread_thread_id': None,
        'project': '666688938958',
        'referenced_resource': None,
        'resolution_comment': None,
        'resolution_status': 'STATUS_020_UNDER_INVESTIGATION',
        'resource_sub_type': None,
        'resource_type': 'COMPUTE',
        'severity': 'high',
        'source': 'XDR Analytics BIOC',
        'starred': False,
        'story_id': None,
        'tags': 'DS:Amazon/AWS',
        'user_agent': 'Boto3/1.24.93 Python/3.10.0 Darwin/20.6.0 Botocore/1.27.93',
        'user_name': 'svc_dev'
      },
      {
        'action': 'DETECTED',
        'action_country': 'UNKNOWN',
        'action_external_hostname': None,
        'action_file_macro_sha256': None,
        'action_file_md5': None,
        'action_file_name': None,
        'action_file_path': None,
        'action_file_sha256': None,
        'action_local_ip': None,
        'action_local_ip_v6': None,
        'action_local_port': None,
        'action_pretty': 'Detected',
        'action_process_causality_id': None,
        'action_process_image_command_line': None,
        'action_process_image_name': None,
        'action_process_image_sha256': None,
        'action_process_instance_id': None,
        'action_process_signature_status': 'N/A',
        'action_process_signature_vendor': None,
        'action_registry_data': None,
        'action_registry_full_key': None,
        'action_registry_key_name': None,
        'action_registry_value_name': None,
        'action_remote_ip': None,
        'action_remote_ip_v6': None,
        'action_remote_port': None,
        'actor_causality_id': None,
        'actor_process_causality_id': None,
        'actor_process_command_line': None,
        'actor_process_image_md5': None,
        'actor_process_image_name': None,
        'actor_process_image_path': None,
        'actor_process_image_sha256': None,
        'actor_process_instance_id': None,
        'actor_process_os_pid': None,
        'actor_process_signature_status': 'N/A',
        'actor_process_signature_vendor': None,
        'actor_thread_thread_id': None,
        'agent_data_collection_status': None,
        'agent_device_domain': None,
        'agent_fqdn': None,
        'agent_host_boot_time': None,
        'agent_install_type': 'NA',
        'agent_ip_addresses_v6': None,
        'agent_is_vdi': None,
        'agent_os_sub_type': None,
        'agent_os_type': 'NO_HOST',
        'agent_version': None,
        'alert_id': '16211',
        'alert_type': 'Unclassified',
        'association_strength': 50,
        'attempt_counter': 0,
        'bioc_category_enum_key': None,
        'bioc_indicator': None,
        'case_id': 1284,
        'category': 'Command and Control',
        'causality_actor_causality_id': None,
        'causality_actor_process_command_line': None,
        'causality_actor_process_execution_time': None,
        'causality_actor_process_image_md5': None,
        'causality_actor_process_image_name': None,
        'causality_actor_process_image_path': None,
        'causality_actor_process_image_sha256': None,
        'causality_actor_process_signature_status': 'N/A',
        'causality_actor_process_signature_vendor': None,
        'cloud_provider': 'AWS',
        'cluster_name': None,
        'container_id': None,
        'contains_featured_host': 'NO',
        'contains_featured_ip': 'NO',
        'contains_featured_user': 'NO',
        'deduplicate_tokens': None,
        'description': 'The cloud user svc_dev has called an API from 192.42.116.193. This IP address is known as a Tor exit node\'s IP address in the last 36 hours',
        'detection_timestamp': 1676281453000,
        'dns_query_name': None,
        'dst_action_country': None,
        'dst_action_external_hostname': None,
        'dst_action_external_port': None,
        'dst_agent_id': None,
        'dst_association_strength': None,
        'dst_causality_actor_process_execution_time': None,
        'dynamic_fields': None,
        'end_match_attempt_ts': None,
        'endpoint_id': None,
        'event_id': 'aa5f2e70-3a1e-5244-8b65-47ea323bbce2',
        'event_sub_type': 3,
        'event_timestamp': 1676281453000,
        'event_type': 'Cloud Audit Log',
        'events_length': 1,
        'external_id': 'eb419ce4-a9cc-460d-bf40-f57436abfc18',
        'filter_rule_id': None,
        'fw_app_category': None,
        'fw_app_id': None,
        'fw_app_subcategory': None,
        'fw_app_technology': None,
        'fw_device_name': None,
        'fw_email_recipient': None,
        'fw_email_sender': None,
        'fw_email_subject': None,
        'fw_interface_from': None,
        'fw_interface_to': None,
        'fw_is_phishing': 'N/A',
        'fw_misc': None,
        'fw_rule': None,
        'fw_rule_id': None,
        'fw_serial_number': None,
        'fw_url_domain': None,
        'fw_vsys': None,
        'fw_xff': None,
        'host_ip': '130.193.10.21',
        'host_ip_list': [
          '130.193.10.21'
        ],
        'host_name': None,
        'identity_sub_type': 'IAM',
        'identity_type': 'USER',
        'image_name': None,
        'is_pcap': False,
        'is_whitelisted': False,
        'last_modified_ts': 1686650948777,
        'local_insert_ts': 1676281588380,
        'mac': None,
        'malicious_urls': None,
        'matching_service_rule_id': 'ac17179d-68dd-46cc-8d2a-68d506e6626e',
        'matching_status': 'MATCHED',
        'mitre_tactic_id_and_name': 'TA0011 - Command and Control',
        'mitre_technique_id_and_name': 'T1090.003 - Proxy: Multi-hop Proxy',
        'module_id': None,
        'name': 'Suspicious API call from a Tor exit node',
        'operation_name': 'GET',
        'original_tags': 'DS:Amazon/AWS',
        'os_actor_causality_id': None,
        'os_actor_effective_username': None,
        'os_actor_process_causality_id': None,
        'os_actor_process_command_line': None,
        'os_actor_process_image_name': None,
        'os_actor_process_image_path': None,
        'os_actor_process_image_sha256': None,
        'os_actor_process_instance_id': None,
        'os_actor_process_os_pid': None,
        'os_actor_process_signature_status': 'N/A',
        'os_actor_process_signature_vendor': None,
        'os_actor_thread_thread_id': None,
        'project': '666688938958',
        'referenced_resource': None,
        'resolution_comment': None,
        'resolution_status': 'STATUS_020_UNDER_INVESTIGATION',
        'resource_sub_type': None,
        'resource_type': 'IDENTITY_ACCESS_MANAGEMENT',
        'severity': 'high',
        'source': 'XDR Analytics BIOC',
        'starred': False,
        'story_id': None,
        'tags': 'DS:Amazon/AWS',
        'user_agent': 'aws-cli/1.22.34 Python/3.10.4 Linux/5.16.0-kali7-cloud-amd64 botocore/1.27.28',
        'user_name': 'svc_dev'
      }
    ],
    'alerts_grouping_status': 'Disabled',
    'assigned_user_mail': None,
    'assigned_user_pretty_name': None,
    'creation_time': 1675769271786,
    'critical_severity_alert_count': 0,
    'description': '\'Suspicious API call from a Tor exit node\' along with 4 other alerts generated by XDR Analytics BIOC and XDR Analytics involving user svc_dev',
    'detection_time': None,
    'file_artifacts': [],
    'high_severity_alert_count': 3,
    'host_count': 0,
    'hosts': None,
    'incident_id': '1284',
    'incident_name': None,
    'incident_sources': [
      'XDR Analytics BIOC',
      'XDR Analytics'
    ],
    'is_blocked': False,
    'low_severity_alert_count': 0,
    'manual_description': None,
    'manual_score': None,
    'manual_severity': 'high',
    'med_severity_alert_count': 2,
    'mitre_tactics_ids_and_names': [
      'TA0001 - Initial Access',
      'TA0002 - Execution',
      'TA0005 - Defense Evasion',
      'TA0011 - Command and Control',
      'TA0040 - Impact'
    ],
    'mitre_techniques_ids_and_names': [
      'T1078 - Valid Accounts',
      'T1090.003 - Proxy: Multi-hop Proxy',
      'T1204 - User Execution',
      'T1496 - Resource Hijacking',
      'T1535 - Unused/Unsupported Cloud Regions'
    ],
    'modification_time': 1686735083317,
    'network_artifacts': [],
    'notes': None,
    'original_tags': [
      'DS:Amazon/AWS'
    ],
    'predicted_score': 100,
    'resolve_comment': None,
    'resolved_timestamp': None,
    'rule_based_score': None,
    'severity': 'high',
    'starred': True,
    'status': 'new',
    'tags': [
      'DS:Amazon/AWS'
    ],
    'user_count': 1,
    'users': [
      'svc_dev'
    ],
    'wildfire_hits': 0,
    'xdr_url': 'https://xsiam-ctf-v3.xdr.us.paloaltonetworks.com/incident-view?caseId=1284'
  },
  'network_artifacts': {
    'data': [],
    'total_count': 0
  }
}
    else:
        raw_incident = {
  "alerts": {
    "data": [{
        "action": "DETECTED",
        "action_country": "UNKNOWN",
        "action_external_hostname": "noneofyourbusiness.io",
        "action_file_macro_sha256": None,
        "action_file_md5": None,
        "action_file_name": None,
        "action_file_path": None,
        "action_file_sha256": None,
        "action_local_ip": "172.16.7.41",
        "action_local_ip_v6": None,
        "action_local_port": 42502,
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
        "action_remote_ip": "130.193.10.21",
        "action_remote_ip_v6": None,
        "action_remote_port": 443,
        "actor_causality_id": None,
        "actor_process_causality_id": None,
        "actor_process_command_line": None,
        "actor_process_image_md5": None,
        "actor_process_image_name": None,
        "actor_process_image_path": None,
        "actor_process_image_sha256": None,
        "actor_process_instance_id": None,
        "actor_process_os_pid": None,
        "actor_process_signature_status": "N/A",
        "actor_process_signature_vendor": None,
        "actor_thread_thread_id": None,
        "agent_data_collection_status": None,
        "agent_device_domain": None,
        "agent_fqdn": None,
        "agent_host_boot_time": None,
        "agent_install_type": "NA",
        "agent_ip_addresses_v6": None,
        "agent_is_vdi": None,
        "agent_os_sub_type": None,
        "agent_os_type": "NO_HOST",
        "agent_version": None,
        "alert_id": "1423244",
        "alert_type": "Unclassified",
        "association_strength": 10,
        "attempt_counter": 0,
        "bioc_category_enum_key": None,
        "bioc_indicator": None,
        "case_id": 4331,
        "category": "Exfiltration",
        "causality_actor_causality_id": None,
        "causality_actor_process_command_line": None,
        "causality_actor_process_execution_time": None,
        "causality_actor_process_image_md5": None,
        "causality_actor_process_image_name": None,
        "causality_actor_process_image_path": None,
        "causality_actor_process_image_sha256": None,
        "causality_actor_process_signature_status": "N/A",
        "causality_actor_process_signature_vendor": None,
        "cloud_provider": None,
        "cluster_name": None,
        "container_id": None,
        "contains_featured_host": "NO",
        "contains_featured_ip": "NO",
        "contains_featured_user": "NO",
        "deduplicate_tokens": None,
        "description": "172.16.7.41 uploaded 1.6GB to the external host noneofyourbusiness.io over 110 sessions in the last 24 hours. During that time, 172.16.7.41 downloaded 1.4MB from the same external host. In the past 30 days, the host uploaded data via HTTPS protocol to this external host an average of 3.4GB a day. Similar events of data upload to this external host, was seen from other endpoints in the network 2 times in the last 30 days",
        "detection_timestamp": 1682842685000,
        "dns_query_name": None,
        "dst_action_country": "US",
        "dst_action_external_hostname": "noneofyourbusiness.io",
        "dst_action_external_port": None,
        "dst_agent_id": "34.210.121.51",
        "dst_association_strength": 10,
        "dst_causality_actor_process_execution_time": None,
        "dynamic_fields": None,
        "end_match_attempt_ts": None,
        "endpoint_id": "172.16.7.41",
        "event_id": "ODI1OTMyMTQ2NDMyNzgyODQyMA==",
        "event_sub_type": 3,
        "event_timestamp": 1682804032000,
        "event_type": "Network Connections",
        "events_length": 1,
        "external_id": "b04c2b19-e84b-4429-8c86-e9e5e813fcbd",
        "filter_rule_id": None,
        "fw_app_category": None,
        "fw_app_id": "ip,tcp,ssl",
        "fw_app_subcategory": None,
        "fw_app_technology": None,
        "fw_device_name": "DC1ENV12APFW02",
        "fw_email_recipient": None,
        "fw_email_sender": None,
        "fw_email_subject": None,
        "fw_interface_from": "TAP",
        "fw_interface_to": "TAP",
        "fw_is_phishing": "N/A",
        "fw_misc": None,
        "fw_rule": "DC1ENV12APFW02|TAP",
        "fw_rule_id": None,
        "fw_serial_number": "007051000212107",
        "fw_url_domain": None,
        "fw_vsys": None,
        "fw_xff": None,
        "host_ip": "172.16.7.41",
        "host_ip_list": [
          "172.16.7.41"
        ],
        "host_name": "172.16.7.41",
        "identity_sub_type": None,
        "identity_type": None,
        "image_name": None,
        "is_pcap": False,
        "is_whitelisted": False,
        "last_modified_ts": None,
        "local_insert_ts": 1682843480516,
        "mac": "00:50:56:9f:24:41",
        "malicious_urls": None,
        "matching_service_rule_id": "81bfe385-c6a1-11ea-be5e-acde48001122",
        "matching_status": "MATCHED",
        "mitre_tactic_id_and_name": "TA0010 - Exfiltration",
        "mitre_technique_id_and_name": "T1048 - Exfiltration Over Alternative Protocol",
        "module_id": None,
        "name": "Large Upload (HTTPS)",
        "operation_name": None,
        "original_tags": "DS:PANW/NGFW",
        "os_actor_causality_id": None,
        "os_actor_effective_username": None,
        "os_actor_process_causality_id": None,
        "os_actor_process_command_line": None,
        "os_actor_process_image_name": None,
        "os_actor_process_image_path": None,
        "os_actor_process_image_sha256": None,
        "os_actor_process_instance_id": None,
        "os_actor_process_os_pid": None,
        "os_actor_process_signature_status": "N/A",
        "os_actor_process_signature_vendor": None,
        "os_actor_thread_thread_id": None,
        "project": None,
        "referenced_resource": None,
        "resolution_comment": None,
        "resolution_status": "STATUS_010_NEW",
        "resource_sub_type": None,
        "resource_type": None,
        "severity": "low",
        "source": "XDR Analytics",
        "starred": False,
        "story_id": "ODI1OTMyMTQ2NDMyNzgyODQyMA==",
        "tags": "DS:PANW/NGFW",
        "user_agent": None,
        "user_name": None}
        ],
    "total_count": 1
  },
  "file_artifacts": {
    "data": [],
    "total_count": 0
  },
  "incident": {
    "aggregated_score": None,
    "alert_categories": [
      "Exfiltration"
    ],
    "alert_count": 1,
    "alerts": [
      {
        "action": "DETECTED",
        "action_country": "UNKNOWN",
        "action_external_hostname": "noneofyourbusiness.io",
        "action_file_macro_sha256": None,
        "action_file_md5": None,
        "action_file_name": None,
        "action_file_path": None,
        "action_file_sha256": None,
        "action_local_ip": "172.16.7.41",
        "action_local_ip_v6": None,
        "action_local_port": 42502,
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
        "action_remote_ip": "130.193.10.21",
        "action_remote_ip_v6": None,
        "action_remote_port": 443,
        "actor_causality_id": None,
        "actor_process_causality_id": None,
        "actor_process_command_line": None,
        "actor_process_image_md5": None,
        "actor_process_image_name": None,
        "actor_process_image_path": None,
        "actor_process_image_sha256": None,
        "actor_process_instance_id": None,
        "actor_process_os_pid": None,
        "actor_process_signature_status": "N/A",
        "actor_process_signature_vendor": None,
        "actor_thread_thread_id": None,
        "agent_data_collection_status": None,
        "agent_device_domain": None,
        "agent_fqdn": None,
        "agent_host_boot_time": None,
        "agent_install_type": "NA",
        "agent_ip_addresses_v6": None,
        "agent_is_vdi": None,
        "agent_os_sub_type": None,
        "agent_os_type": "NO_HOST",
        "agent_version": None,
        "alert_id": "1423244",
        "alert_type": "Unclassified",
        "association_strength": 10,
        "attempt_counter": 0,
        "bioc_category_enum_key": None,
        "bioc_indicator": None,
        "case_id": 4331,
        "category": "Exfiltration",
        "causality_actor_causality_id": None,
        "causality_actor_process_command_line": None,
        "causality_actor_process_execution_time": None,
        "causality_actor_process_image_md5": None,
        "causality_actor_process_image_name": None,
        "causality_actor_process_image_path": None,
        "causality_actor_process_image_sha256": None,
        "causality_actor_process_signature_status": "N/A",
        "causality_actor_process_signature_vendor": None,
        "cloud_provider": None,
        "cluster_name": None,
        "container_id": None,
        "contains_featured_host": "NO",
        "contains_featured_ip": "NO",
        "contains_featured_user": "NO",
        "deduplicate_tokens": None,
        "description": "172.16.7.41 uploaded 1.6GB to the external host noneofyourbusiness.io over 110 sessions in the last 24 hours. During that time, 172.16.7.41 downloaded 1.4MB from the same external host. In the past 30 days, the host uploaded data via HTTPS protocol to this external host an average of 3.4GB a day. Similar events of data upload to this external host, was seen from other endpoints in the network 2 times in the last 30 days",
        "detection_timestamp": 1682842685000,
        "dns_query_name": None,
        "dst_action_country": "US",
        "dst_action_external_hostname": "noneofyourbusiness.io",
        "dst_action_external_port": None,
        "dst_agent_id": "34.210.121.51",
        "dst_association_strength": 10,
        "dst_causality_actor_process_execution_time": None,
        "dynamic_fields": None,
        "end_match_attempt_ts": None,
        "endpoint_id": "172.16.7.41",
        "event_id": "ODI1OTMyMTQ2NDMyNzgyODQyMA==",
        "event_sub_type": 3,
        "event_timestamp": 1682804032000,
        "event_type": "Network Connections",
        "events_length": 1,
        "external_id": "b04c2b19-e84b-4429-8c86-e9e5e813fcbd",
        "filter_rule_id": None,
        "fw_app_category": None,
        "fw_app_id": "ip,tcp,ssl",
        "fw_app_subcategory": None,
        "fw_app_technology": None,
        "fw_device_name": "DC1ENV12APFW02",
        "fw_email_recipient": None,
        "fw_email_sender": None,
        "fw_email_subject": None,
        "fw_interface_from": "TAP",
        "fw_interface_to": "TAP",
        "fw_is_phishing": "N/A",
        "fw_misc": None,
        "fw_rule": "DC1ENV12APFW02|TAP",
        "fw_rule_id": None,
        "fw_serial_number": "007051000212107",
        "fw_url_domain": None,
        "fw_vsys": None,
        "fw_xff": None,
        "host_ip": "172.16.7.41",
        "host_ip_list": [
          "172.16.7.41"
        ],
        "host_name": "172.16.7.41",
        "identity_sub_type": None,
        "identity_type": None,
        "image_name": None,
        "is_pcap": False,
        "is_whitelisted": False,
        "last_modified_ts": None,
        "local_insert_ts": 1682843480516,
        "mac": "00:50:56:9f:24:41",
        "malicious_urls": None,
        "matching_service_rule_id": "81bfe385-c6a1-11ea-be5e-acde48001122",
        "matching_status": "MATCHED",
        "mitre_tactic_id_and_name": "TA0010 - Exfiltration",
        "mitre_technique_id_and_name": "T1048 - Exfiltration Over Alternative Protocol",
        "module_id": None,
        "name": "Large Upload (HTTPS)",
        "operation_name": None,
        "original_tags": "DS:PANW/NGFW",
        "os_actor_causality_id": None,
        "os_actor_effective_username": None,
        "os_actor_process_causality_id": None,
        "os_actor_process_command_line": None,
        "os_actor_process_image_name": None,
        "os_actor_process_image_path": None,
        "os_actor_process_image_sha256": None,
        "os_actor_process_instance_id": None,
        "os_actor_process_os_pid": None,
        "os_actor_process_signature_status": "N/A",
        "os_actor_process_signature_vendor": None,
        "os_actor_thread_thread_id": None,
        "project": None,
        "referenced_resource": None,
        "resolution_comment": None,
        "resolution_status": "STATUS_010_NEW",
        "resource_sub_type": None,
        "resource_type": None,
        "severity": "low",
        "source": "XDR Analytics",
        "starred": False,
        "story_id": "ODI1OTMyMTQ2NDMyNzgyODQyMA==",
        "tags": "DS:PANW/NGFW",
        "user_agent": None,
        "user_name": None}],
    "alerts_grouping_status": "Disabled",
    "assigned_user_mail": None,
    "assigned_user_pretty_name": None,
    "creation_time": 1680614903363,
    "critical_severity_alert_count": 0,
    "description": "1 'Large Upload (HTTPS)' alerts detected by XDR Analytics on host 172.16.7.41",
    "detection_time": None,
    "file_artifacts": [],
    "high_severity_alert_count": 0,
    "host_count": 1,
    "hosts": [
      "172.16.7.41:00:50:56:9f:24:41"
    ],
    "incident_id": "4331",
    "incident_name": None,
    "incident_sources": [
      "XDR Analytics"
    ],
    "is_blocked": False,
    "low_severity_alert_count": 1,
    "manual_description": "1 'Large Upload (HTTPS)' alert detected by XDR Analytics on host 172.16.7.41",
    "manual_score": None,
    "manual_severity": None,
    "med_severity_alert_count": 0,
    "mitre_tactics_ids_and_names": [
      "TA0010 - Exfiltration"
    ],
    "mitre_techniques_ids_and_names": [
      "T1048 - Exfiltration Over Alternative Protocol"
    ],
    "modification_time": 1690373750764,
    "network_artifacts": [
      {
        "alert_count": 16,
        "is_manual": False,
        "network_country": "US",
        "network_domain": "noneofyourbusiness.io",
        "network_remote_ip": "130.193.10.21",
        "network_remote_port": 443,
        "type": "DOMAIN"
      }
    ],
    "notes": None,
    "original_tags": [
      "DS:PANW/NGFW"
    ],
    "predicted_score": None,
    "resolve_comment": None,
    "resolved_timestamp": None,
    "rule_based_score": None,
    "severity": "low",
    "starred": False,
    "status": "new",
    "tags": [
      "DS:PANW/NGFW"
    ],
    "user_count": 0,
    "users": [],
    "wildfire_hits": 0,
    "xdr_url": "https://xsiam-ctf-v3.xdr.us.paloaltonetworks.com/incident-view?caseId=1284"
  },
  "network_artifacts": {
    "data": [
      {
        "alert_count": 1,
        "is_manual": False,
        "network_country": "US",
        "network_domain": "noneofyourbusiness.io",
        "network_remote_ip": "130.193.10.21",
        "network_remote_port": 443,
        "type": "DOMAIN"
      }
    ],
    "total_count": 1
  }
  }

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
    "aggregated_score": None,
    "alert_categories": [
      "Command and Control",
      "Defense Evasion",
      "Execution",
      "Impact",
      "Initial Access"
    ],
    "alert_count": 5,
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
        "action_process_signature_status": "N//A",
        "action_process_signature_vendor": None,
        "action_registry_data": None,
        "action_registry_full_key": None,
        "action_registry_key_name": None,
        "action_registry_value_name": None,
        "action_remote_ip": None,
        "action_remote_ip_v6": None,
        "action_remote_port": None,
        "actor_causality_id": None,
        "actor_process_causality_id": None,
        "actor_process_command_line": None,
        "actor_process_image_md5": None,
        "actor_process_image_name": None,
        "actor_process_image_path": None,
        "actor_process_image_sha256": None,
        "actor_process_instance_id": None,
        "actor_process_os_pid": None,
        "actor_process_signature_status": "N//A",
        "actor_process_signature_vendor": None,
        "actor_thread_thread_id": None,
        "agent_data_collection_status": None,
        "agent_device_domain": None,
        "agent_fqdn": None,
        "agent_host_boot_time": None,
        "agent_install_type": "NA",
        "agent_ip_addresses_v6": None,
        "agent_is_vdi": None,
        "agent_os_sub_type": None,
        "agent_os_type": "NO_HOST",
        "agent_version": None,
        "alert_id": "14827",
        "alert_type": "Unclassified",
        "association_strength": 50,
        "attempt_counter": 0,
        "bioc_category_enum_key": None,
        "bioc_indicator": None,
        "case_id": 1284,
        "category": "Defense Evasion",
        "causality_actor_causality_id": None,
        "causality_actor_process_command_line": None,
        "causality_actor_process_execution_time": None,
        "causality_actor_process_image_md5": None,
        "causality_actor_process_image_name": None,
        "causality_actor_process_image_path": None,
        "causality_actor_process_image_sha256": None,
        "causality_actor_process_signature_status": "N//A",
        "causality_actor_process_signature_vendor": None,
        "cloud_provider": "AWS",
        "cluster_name": None,
        "container_id": None,
        "contains_featured_host": "NO",
        "contains_featured_ip": "NO",
        "contains_featured_user": "NO",
        "deduplicate_tokens": None,
        "description": "An unusual activity was performed in AWS, region eu-west-1. The CREATE operation was performed against a COMPUTE service in the project 666688938958. This behavior was not observed in the last 30 days",
        "detection_timestamp": 1676282755000,
        "dns_query_name": None,
        "dst_action_country": None,
        "dst_action_external_hostname": None,
        "dst_action_external_port": None,
        "dst_agent_id": None,
        "dst_association_strength": None,
        "dst_causality_actor_process_execution_time": None,
        "dynamic_fields": None,
        "end_match_attempt_ts": None,
        "endpoint_id": None,
        "event_id": "2db6ffaa-694d-560c-bdd1-8f22e97331db_4",
        "event_sub_type": 3,
        "event_timestamp": 1672665266000,
        "event_type": "Cloud Audit Log",
        "events_length": 1,
        "external_id": "8fa790af-ee28-4f27-9e5e-343e4053c44c",
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
        "fw_is_phishing": "N//A",
        "fw_misc": None,
        "fw_rule": None,
        "fw_rule_id": None,
        "fw_serial_number": None,
        "fw_url_domain": None,
        "fw_vsys": None,
        "fw_xff": None,
        "host_ip": "31.154.166.148",
        "host_ip_list": [
          "31.154.166.148"
        ],
        "host_name": None,
        "identity_sub_type": "IAM",
        "identity_type": "USER",
        "image_name": None,
        "is_pcap": False,
        "is_whitelisted": False,
        "last_modified_ts": 1686732679256,
        "local_insert_ts": 1672665528800,
        "mac": None,
        "malicious_urls": None,
        "matching_service_rule_id": "22e661ae-3081-4a2d-9550-c65b6b660af1",
        "matching_status": "MATCHED",
        "mitre_tactic_id_and_name": "TA0005 - Defense Evasion",
        "mitre_technique_id_and_name": "T1535 - Unused//Unsupported Cloud Regions",
        "module_id": None,
        "name": "A cloud compute instance was created in a dormant region",
        "operation_name": "CREATE",
        "original_tags": "DS:Amazon//AWS",
        "os_actor_causality_id": None,
        "os_actor_effective_username": None,
        "os_actor_process_causality_id": None,
        "os_actor_process_command_line": None,
        "os_actor_process_image_name": None,
        "os_actor_process_image_path": None,
        "os_actor_process_image_sha256": None,
        "os_actor_process_instance_id": None,
        "os_actor_process_os_pid": None,
        "os_actor_process_signature_status": "N//A",
        "os_actor_process_signature_vendor": None,
        "os_actor_thread_thread_id": None,
        "project": "666688938958",
        "referenced_resource": "arn:aws:ec2:us-west-2:666688938958:vpc//vpc-04cfed27f1f06f385",
        "resolution_comment": None,
        "resolution_status": "STATUS_020_UNDER_INVESTIGATION",
        "resource_sub_type": "VPC",
        "resource_type": "COMPUTE",
        "severity": "medium",
        "source": "XDR Analytics BIOC",
        "starred": False,
        "story_id": None,
        "tags": "DS:Amazon//AWS",
        "user_agent": "Boto3//1.24.93 Python//3.10.0 Darwin//20.6.0 Botocore//1.27.93",
        "user_name": "svc_dev"
      },
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
        "action_process_signature_status": "N//A",
        "action_process_signature_vendor": None,
        "action_registry_data": None,
        "action_registry_full_key": None,
        "action_registry_key_name": None,
        "action_registry_value_name": None,
        "action_remote_ip": None,
        "action_remote_ip_v6": None,
        "action_remote_port": None,
        "actor_causality_id": None,
        "actor_process_causality_id": None,
        "actor_process_command_line": None,
        "actor_process_image_md5": None,
        "actor_process_image_name": None,
        "actor_process_image_path": None,
        "actor_process_image_sha256": None,
        "actor_process_instance_id": None,
        "actor_process_os_pid": None,
        "actor_process_signature_status": "N//A",
        "actor_process_signature_vendor": None,
        "actor_thread_thread_id": None,
        "agent_data_collection_status": None,
        "agent_device_domain": None,
        "agent_fqdn": None,
        "agent_host_boot_time": None,
        "agent_install_type": "NA",
        "agent_ip_addresses_v6": None,
        "agent_is_vdi": None,
        "agent_os_sub_type": None,
        "agent_os_type": "NO_HOST",
        "agent_version": None,
        "alert_id": "16223",
        "alert_type": "Unclassified",
        "association_strength": None,
        "attempt_counter": 0,
        "bioc_category_enum_key": None,
        "bioc_indicator": None,
        "case_id": 1284,
        "category": "Impact",
        "causality_actor_causality_id": None,
        "causality_actor_process_command_line": None,
        "causality_actor_process_execution_time": None,
        "causality_actor_process_image_md5": None,
        "causality_actor_process_image_name": None,
        "causality_actor_process_image_path": None,
        "causality_actor_process_image_sha256": None,
        "causality_actor_process_signature_status": "N//A",
        "causality_actor_process_signature_vendor": None,
        "cloud_provider": "AWS",
        "cluster_name": None,
        "container_id": None,
        "contains_featured_host": "NO",
        "contains_featured_ip": "NO",
        "contains_featured_user": "NO",
        "deduplicate_tokens": None,
        "description": "The identity svc_dev created an unusual amount of compute resources. The activity seen on AWS provider within 666688938958 project on eu-west-1 region",
        "detection_timestamp": 1676282745000,
        "dns_query_name": None,
        "dst_action_country": None,
        "dst_action_external_hostname": None,
        "dst_action_external_port": None,
        "dst_agent_id": None,
        "dst_association_strength": None,
        "dst_causality_actor_process_execution_time": None,
        "dynamic_fields": None,
        "end_match_attempt_ts": None,
        "endpoint_id": "-1",
        "event_id": "36451364-79e7-582b-a5df-e331bd45bb1b_4",
        "event_sub_type": 3,
        "event_timestamp": 1676282725000,
        "event_type": "Cloud Audit Log",
        "events_length": 1,
        "external_id": "5c5beda1-a9ac-4799-959f-0f6b16f23f3a",
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
        "fw_is_phishing": "N//A",
        "fw_misc": None,
        "fw_rule": None,
        "fw_rule_id": None,
        "fw_serial_number": None,
        "fw_url_domain": None,
        "fw_vsys": None,
        "fw_xff": None,
        "host_ip": None,
        "host_ip_list": [],
        "host_name": None,
        "identity_sub_type": "IAM",
        "identity_type": "USER",
        "image_name": None,
        "is_pcap": False,
        "is_whitelisted": False,
        "last_modified_ts": 1686731961937,
        "local_insert_ts": 1676282795282,
        "mac": None,
        "malicious_urls": None,
        "matching_service_rule_id": "653d6d6c-2f5b-11ed-8017-acde48001122",
        "matching_status": "MATCHED",
        "mitre_tactic_id_and_name": "TA0040 - Impact",
        "mitre_technique_id_and_name": "T1496 - Resource Hijacking",
        "module_id": None,
        "name": "Allocation of multiple cloud compute resources with accelerator gear",
        "operation_name": "CREATE",
        "original_tags": "DS:Amazon//AWS",
        "os_actor_causality_id": None,
        "os_actor_effective_username": None,
        "os_actor_process_causality_id": None,
        "os_actor_process_command_line": None,
        "os_actor_process_image_name": None,
        "os_actor_process_image_path": None,
        "os_actor_process_image_sha256": None,
        "os_actor_process_instance_id": None,
        "os_actor_process_os_pid": None,
        "os_actor_process_signature_status": "N//A",
        "os_actor_process_signature_vendor": None,
        "os_actor_thread_thread_id": None,
        "project": "666688938958",
        "referenced_resource": "arn:aws:ec2:eu-west-1:666688938958:instance//i-0dc36ef8209f667fb",
        "resolution_comment": None,
        "resolution_status": "STATUS_020_UNDER_INVESTIGATION",
        "resource_sub_type": "COMPUTE_INSTANCE",
        "resource_type": "COMPUTE",
        "severity": "high",
        "source": "XDR Analytics",
        "starred": False,
        "story_id": None,
        "tags": "DS:Amazon//AWS",
        "user_agent": "Boto3//1.24.93 Python//3.10.0 Darwin//20.6.0 Botocore//1.27.93",
        "user_name": "svc_dev"
      },
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
        "action_process_signature_status": "N//A",
        "action_process_signature_vendor": None,
        "action_registry_data": None,
        "action_registry_full_key": None,
        "action_registry_key_name": None,
        "action_registry_value_name": None,
        "action_remote_ip": None,
        "action_remote_ip_v6": None,
        "action_remote_port": None,
        "actor_causality_id": None,
        "actor_process_causality_id": None,
        "actor_process_command_line": None,
        "actor_process_image_md5": None,
        "actor_process_image_name": None,
        "actor_process_image_path": None,
        "actor_process_image_sha256": None,
        "actor_process_instance_id": None,
        "actor_process_os_pid": None,
        "actor_process_signature_status": "N//A",
        "actor_process_signature_vendor": None,
        "actor_thread_thread_id": None,
        "agent_data_collection_status": None,
        "agent_device_domain": None,
        "agent_fqdn": None,
        "agent_host_boot_time": None,
        "agent_install_type": "NA",
        "agent_ip_addresses_v6": None,
        "agent_is_vdi": None,
        "agent_os_sub_type": None,
        "agent_os_type": "NO_HOST",
        "agent_version": None,
        "alert_id": "14873",
        "alert_type": "Unclassified",
        "association_strength": 50,
        "attempt_counter": 0,
        "bioc_category_enum_key": None,
        "bioc_indicator": None,
        "case_id": 1284,
        "category": "Execution",
        "causality_actor_causality_id": None,
        "causality_actor_process_command_line": None,
        "causality_actor_process_execution_time": None,
        "causality_actor_process_image_md5": None,
        "causality_actor_process_image_name": None,
        "causality_actor_process_image_path": None,
        "causality_actor_process_image_sha256": None,
        "causality_actor_process_signature_status": "N//A",
        "causality_actor_process_signature_vendor": None,
        "cloud_provider": "AWS",
        "cluster_name": None,
        "container_id": None,
        "contains_featured_host": "NO",
        "contains_featured_ip": "NO",
        "contains_featured_user": "NO",
        "deduplicate_tokens": None,
        "description": "The cloud Identity svc_dev has executed an API call. The identity's user-agent call is aws-cli//1.22.34 Python//3.10.4 Linux//5.16.0-kali7-cloud-amd64 botocore//1.27.28. The operation was performed on AWS//666688938958",
        "detection_timestamp": 1676282568000,
        "dns_query_name": None,
        "dst_action_country": None,
        "dst_action_external_hostname": None,
        "dst_action_external_port": None,
        "dst_agent_id": None,
        "dst_association_strength": None,
        "dst_causality_actor_process_execution_time": None,
        "dynamic_fields": None,
        "end_match_attempt_ts": None,
        "endpoint_id": None,
        "event_id": "210db407-f1fa-52c7-9ff5-bc3fd27426a9",
        "event_sub_type": 3,
        "event_timestamp": 1675768999000,
        "event_type": "Cloud Audit Log",
        "events_length": 1,
        "external_id": "8940f509-5f71-4309-b0ea-4b48eb2d0fd7",
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
        "fw_is_phishing": "N//A",
        "fw_misc": None,
        "fw_rule": None,
        "fw_rule_id": None,
        "fw_serial_number": None,
        "fw_url_domain": None,
        "fw_vsys": None,
        "fw_xff": None,
        "host_ip": "18.221.214.175",
        "host_ip_list": [
          "18.221.214.175"
        ],
        "host_name": None,
        "identity_sub_type": "IAM",
        "identity_type": "USER",
        "image_name": None,
        "is_pcap": False,
        "is_whitelisted": False,
        "last_modified_ts": 1686652368965,
        "local_insert_ts": 1675769251633,
        "mac": None,
        "malicious_urls": None,
        "matching_service_rule_id": "f6e71c10-dfd2-11eb-8670-acde48001122",
        "matching_status": "MATCHED",
        "mitre_tactic_id_and_name": "TA0002 - Execution",
        "mitre_technique_id_and_name": "T1204 - User Execution",
        "module_id": None,
        "name": "Penetration testing tool activity",
        "operation_name": "GET",
        "original_tags": "DS:Amazon//AWS",
        "os_actor_causality_id": None,
        "os_actor_effective_username": None,
        "os_actor_process_causality_id": None,
        "os_actor_process_command_line": None,
        "os_actor_process_image_name": None,
        "os_actor_process_image_path": None,
        "os_actor_process_image_sha256": None,
        "os_actor_process_instance_id": None,
        "os_actor_process_os_pid": None,
        "os_actor_process_signature_status": "N//A",
        "os_actor_process_signature_vendor": None,
        "os_actor_thread_thread_id": None,
        "project": "666688938958",
        "referenced_resource": None,
        "resolution_comment": None,
        "resolution_status": "STATUS_020_UNDER_INVESTIGATION",
        "resource_sub_type": None,
        "resource_type": "IDENTITY_ACCESS_MANAGEMENT",
        "severity": "medium",
        "source": "XDR Analytics BIOC",
        "starred": False,
        "story_id": None,
        "tags": "DS:Amazon//AWS",
        "user_agent": "aws-cli//1.22.34 Python//3.10.4 Linux//5.16.0-kali7-cloud-amd64 botocore//1.27.28",
        "user_name": "svc_dev"
      },
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
        "action_process_signature_status": "N//A",
        "action_process_signature_vendor": None,
        "action_registry_data": None,
        "action_registry_full_key": None,
        "action_registry_key_name": None,
        "action_registry_value_name": None,
        "action_remote_ip": None,
        "action_remote_ip_v6": None,
        "action_remote_port": None,
        "actor_causality_id": None,
        "actor_process_causality_id": None,
        "actor_process_command_line": None,
        "actor_process_image_md5": None,
        "actor_process_image_name": None,
        "actor_process_image_path": None,
        "actor_process_image_sha256": None,
        "actor_process_instance_id": None,
        "actor_process_os_pid": None,
        "actor_process_signature_status": "N//A",
        "actor_process_signature_vendor": None,
        "actor_thread_thread_id": None,
        "agent_data_collection_status": None,
        "agent_device_domain": None,
        "agent_fqdn": None,
        "agent_host_boot_time": None,
        "agent_install_type": "NA",
        "agent_ip_addresses_v6": None,
        "agent_is_vdi": None,
        "agent_os_sub_type": None,
        "agent_os_type": "NO_HOST",
        "agent_version": None,
        "alert_id": "16217",
        "alert_type": "Unclassified",
        "association_strength": 50,
        "attempt_counter": 0,
        "bioc_category_enum_key": None,
        "bioc_indicator": None,
        "case_id": 1284,
        "category": "Initial Access",
        "causality_actor_causality_id": None,
        "causality_actor_process_command_line": None,
        "causality_actor_process_execution_time": None,
        "causality_actor_process_image_md5": None,
        "causality_actor_process_image_name": None,
        "causality_actor_process_image_path": None,
        "causality_actor_process_image_sha256": None,
        "causality_actor_process_signature_status": "N//A",
        "causality_actor_process_signature_vendor": None,
        "cloud_provider": "AWS",
        "cluster_name": None,
        "container_id": None,
        "contains_featured_host": "NO",
        "contains_featured_ip": "NO",
        "contains_featured_user": "NO",
        "deduplicate_tokens": None,
        "description": "The cloud identity svc_dev connected from Czechia. This behavior was not observed in the last 30 days. The country Czechia was not seen in the organization in the last 30 days",
        "detection_timestamp": 1676281911000,
        "dns_query_name": None,
        "dst_action_country": None,
        "dst_action_external_hostname": None,
        "dst_action_external_port": None,
        "dst_agent_id": None,
        "dst_association_strength": None,
        "dst_causality_actor_process_execution_time": None,
        "dynamic_fields": None,
        "end_match_attempt_ts": None,
        "endpoint_id": None,
        "event_id": "44436ab8-bcdf-5753-829c-7de557d7361b",
        "event_sub_type": 3,
        "event_timestamp": 1676281911000,
        "event_type": "Cloud Audit Log",
        "events_length": 1,
        "external_id": "e2d60f8e-fc57-497e-8080-82e75802b190",
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
        "fw_is_phishing": "N//A",
        "fw_misc": None,
        "fw_rule": None,
        "fw_rule_id": None,
        "fw_serial_number": None,
        "fw_url_domain": None,
        "fw_vsys": None,
        "fw_xff": None,
        "host_ip": "130.193.10.21",
        "host_ip_list": [
          "130.193.10.21"
        ],
        "host_name": None,
        "identity_sub_type": "IAM",
        "identity_type": "USER",
        "image_name": None,
        "is_pcap": False,
        "is_whitelisted": False,
        "last_modified_ts": 1686735220954,
        "local_insert_ts": 1676282105888,
        "mac": None,
        "malicious_urls": None,
        "matching_service_rule_id": "32cff288-9e1e-11ec-ac34-acde48001122",
        "matching_status": "MATCHED",
        "mitre_tactic_id_and_name": "TA0001 - Initial Access",
        "mitre_technique_id_and_name": "T1078 - Valid Accounts",
        "module_id": None,
        "name": "A cloud identity executed an API call from an unusual country",
        "operation_name": "ENUMERATE",
        "original_tags": "DS:Amazon//AWS",
        "os_actor_causality_id": None,
        "os_actor_effective_username": None,
        "os_actor_process_causality_id": None,
        "os_actor_process_command_line": None,
        "os_actor_process_image_name": None,
        "os_actor_process_image_path": None,
        "os_actor_process_image_sha256": None,
        "os_actor_process_instance_id": None,
        "os_actor_process_os_pid": None,
        "os_actor_process_signature_status": "N//A",
        "os_actor_process_signature_vendor": None,
        "os_actor_thread_thread_id": None,
        "project": "666688938958",
        "referenced_resource": None,
        "resolution_comment": None,
        "resolution_status": "STATUS_020_UNDER_INVESTIGATION",
        "resource_sub_type": None,
        "resource_type": "COMPUTE",
        "severity": "high",
        "source": "XDR Analytics BIOC",
        "starred": False,
        "story_id": None,
        "tags": "DS:Amazon//AWS",
        "user_agent": "Boto3//1.24.93 Python//3.10.0 Darwin//20.6.0 Botocore//1.27.93",
        "user_name": "svc_dev"
      },
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
        "action_process_signature_status": "N//A",
        "action_process_signature_vendor": None,
        "action_registry_data": None,
        "action_registry_full_key": None,
        "action_registry_key_name": None,
        "action_registry_value_name": None,
        "action_remote_ip": None,
        "action_remote_ip_v6": None,
        "action_remote_port": None,
        "actor_causality_id": None,
        "actor_process_causality_id": None,
        "actor_process_command_line": None,
        "actor_process_image_md5": None,
        "actor_process_image_name": None,
        "actor_process_image_path": None,
        "actor_process_image_sha256": None,
        "actor_process_instance_id": None,
        "actor_process_os_pid": None,
        "actor_process_signature_status": "N//A",
        "actor_process_signature_vendor": None,
        "actor_thread_thread_id": None,
        "agent_data_collection_status": None,
        "agent_device_domain": None,
        "agent_fqdn": None,
        "agent_host_boot_time": None,
        "agent_install_type": "NA",
        "agent_ip_addresses_v6": None,
        "agent_is_vdi": None,
        "agent_os_sub_type": None,
        "agent_os_type": "NO_HOST",
        "agent_version": None,
        "alert_id": "16211",
        "alert_type": "Unclassified",
        "association_strength": 50,
        "attempt_counter": 0,
        "bioc_category_enum_key": None,
        "bioc_indicator": None,
        "case_id": 1284,
        "category": "Command and Control",
        "causality_actor_causality_id": None,
        "causality_actor_process_command_line": None,
        "causality_actor_process_execution_time": None,
        "causality_actor_process_image_md5": None,
        "causality_actor_process_image_name": None,
        "causality_actor_process_image_path": None,
        "causality_actor_process_image_sha256": None,
        "causality_actor_process_signature_status": "N//A",
        "causality_actor_process_signature_vendor": None,
        "cloud_provider": "AWS",
        "cluster_name": None,
        "container_id": None,
        "contains_featured_host": "NO",
        "contains_featured_ip": "NO",
        "contains_featured_user": "NO",
        "deduplicate_tokens": None,
        "description": "The cloud user svc_dev has called an API from 192.42.116.193. This IP address is known as a Tor exit node's IP address in the last 36 hours",
        "detection_timestamp": 1676281453000,
        "dns_query_name": None,
        "dst_action_country": None,
        "dst_action_external_hostname": None,
        "dst_action_external_port": None,
        "dst_agent_id": None,
        "dst_association_strength": None,
        "dst_causality_actor_process_execution_time": None,
        "dynamic_fields": None,
        "end_match_attempt_ts": None,
        "endpoint_id": None,
        "event_id": "aa5f2e70-3a1e-5244-8b65-47ea323bbce2",
        "event_sub_type": 3,
        "event_timestamp": 1676281453000,
        "event_type": "Cloud Audit Log",
        "events_length": 1,
        "external_id": "eb419ce4-a9cc-460d-bf40-f57436abfc18",
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
        "fw_is_phishing": "N//A",
        "fw_misc": None,
        "fw_rule": None,
        "fw_rule_id": None,
        "fw_serial_number": None,
        "fw_url_domain": None,
        "fw_vsys": None,
        "fw_xff": None,
        "host_ip": "130.193.10.21",
        "host_ip_list": [
          "130.193.10.21"
        ],
        "host_name": None,
        "identity_sub_type": "IAM",
        "identity_type": "USER",
        "image_name": None,
        "is_pcap": False,
        "is_whitelisted": False,
        "last_modified_ts": 1686650948777,
        "local_insert_ts": 1676281588380,
        "mac": None,
        "malicious_urls": None,
        "matching_service_rule_id": "ac17179d-68dd-46cc-8d2a-68d506e6626e",
        "matching_status": "MATCHED",
        "mitre_tactic_id_and_name": "TA0011 - Command and Control",
        "mitre_technique_id_and_name": "T1090.003 - Proxy: Multi-hop Proxy",
        "module_id": None,
        "name": "Suspicious API call from a Tor exit node",
        "operation_name": "GET",
        "original_tags": "DS:Amazon//AWS",
        "os_actor_causality_id": None,
        "os_actor_effective_username": None,
        "os_actor_process_causality_id": None,
        "os_actor_process_command_line": None,
        "os_actor_process_image_name": None,
        "os_actor_process_image_path": None,
        "os_actor_process_image_sha256": None,
        "os_actor_process_instance_id": None,
        "os_actor_process_os_pid": None,
        "os_actor_process_signature_status": "N//A",
        "os_actor_process_signature_vendor": None,
        "os_actor_thread_thread_id": None,
        "project": "666688938958",
        "referenced_resource": None,
        "resolution_comment": None,
        "resolution_status": "STATUS_020_UNDER_INVESTIGATION",
        "resource_sub_type": None,
        "resource_type": "IDENTITY_ACCESS_MANAGEMENT",
        "severity": "high",
        "source": "XDR Analytics BIOC",
        "starred": False,
        "story_id": None,
        "tags": "DS:Amazon//AWS",
        "user_agent": "aws-cli//1.22.34 Python//3.10.4 Linux//5.16.0-kali7-cloud-amd64 botocore//1.27.28",
        "user_name": "svc_dev"
      }
    ],
    "alerts_grouping_status": "Disabled",
    "assigned_user_mail": None,
    "assigned_user_pretty_name": None,
    "creation_time": 1675769271786,
    "critical_severity_alert_count": 0,
    "description": "'Suspicious API call from a Tor exit node' along with 4 other alerts generated by XDR Analytics BIOC and XDR Analytics involving user svc_dev",
    "detection_time": None,
    "file_artifacts": [],
    "high_severity_alert_count": 3,
    "host_count": 0,
    "hosts": None,
    "incident_id": "1284",
    "incident_name": None,
    "incident_sources": [
      "XDR Analytics BIOC",
      "XDR Analytics"
    ],
    "is_blocked": False,
    "low_severity_alert_count": 0,
    "manual_description": None,
    "manual_score": None,
    "manual_severity": "high",
    "med_severity_alert_count": 2,
    "mitre_tactics_ids_and_names": [
      "TA0001 - Initial Access",
      "TA0002 - Execution",
      "TA0005 - Defense Evasion",
      "TA0011 - Command and Control",
      "TA0040 - Impact"
    ],
    "mitre_techniques_ids_and_names": [
      "T1078 - Valid Accounts",
      "T1090.003 - Proxy: Multi-hop Proxy",
      "T1204 - User Execution",
      "T1496 - Resource Hijacking",
      "T1535 - Unused//Unsupported Cloud Regions"
    ],
    "modification_time": 1686735083317,
    "network_artifacts": [],
    "notes": None,
    "original_tags": [
      "DS:Amazon//AWS"
    ],
    "predicted_score": 100,
    "resolve_comment": None,
    "resolved_timestamp": None,
    "rule_based_score": None,
    "severity": "high",
    "starred": True,
    "status": "new",
    "tags": [
      "DS:Amazon//AWS"
    ],
    "user_count": 1,
    "users": [
      "svc_dev"
    ],
    "wildfire_hits": 0,
    "xdr_url": "https:////xsiam-ctf-v3.xdr.us.paloaltonetworks.com//incident-view?caseId=1284"
  }
    incidents = [{
    "aggregated_score": None,
    "alert_categories": [
      "Exfiltration"
    ],
    "alert_count": 1,
    "alerts": [
      {
        "action": "DETECTED",
        "action_country": "UNKNOWN",
        "action_external_hostname": "noneofyourbusiness.io",
        "action_file_macro_sha256": None,
        "action_file_md5": None,
        "action_file_name": None,
        "action_file_path": None,
        "action_file_sha256": None,
        "action_local_ip": "172.16.7.41",
        "action_local_ip_v6": None,
        "action_local_port": 42502,
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
        "action_remote_ip": "130.193.10.21",
        "action_remote_ip_v6": None,
        "action_remote_port": 443,
        "actor_causality_id": None,
        "actor_process_causality_id": None,
        "actor_process_command_line": None,
        "actor_process_image_md5": None,
        "actor_process_image_name": None,
        "actor_process_image_path": None,
        "actor_process_image_sha256": None,
        "actor_process_instance_id": None,
        "actor_process_os_pid": None,
        "actor_process_signature_status": "N/A",
        "actor_process_signature_vendor": None,
        "actor_thread_thread_id": None,
        "agent_data_collection_status": None,
        "agent_device_domain": None,
        "agent_fqdn": None,
        "agent_host_boot_time": None,
        "agent_install_type": "NA",
        "agent_ip_addresses_v6": None,
        "agent_is_vdi": None,
        "agent_os_sub_type": None,
        "agent_os_type": "NO_HOST",
        "agent_version": None,
        "alert_id": "1423244",
        "alert_type": "Unclassified",
        "association_strength": 10,
        "attempt_counter": 0,
        "bioc_category_enum_key": None,
        "bioc_indicator": None,
        "case_id": 4331,
        "category": "Exfiltration",
        "causality_actor_causality_id": None,
        "causality_actor_process_command_line": None,
        "causality_actor_process_execution_time": None,
        "causality_actor_process_image_md5": None,
        "causality_actor_process_image_name": None,
        "causality_actor_process_image_path": None,
        "causality_actor_process_image_sha256": None,
        "causality_actor_process_signature_status": "N/A",
        "causality_actor_process_signature_vendor": None,
        "cloud_provider": None,
        "cluster_name": None,
        "container_id": None,
        "contains_featured_host": "NO",
        "contains_featured_ip": "NO",
        "contains_featured_user": "NO",
        "deduplicate_tokens": None,
        "description": "172.16.7.41 uploaded 1.6GB to the external host noneofyourbusiness.io over 110 sessions in the last 24 hours. During that time, 172.16.7.41 downloaded 1.4MB from the same external host. In the past 30 days, the host uploaded data via HTTPS protocol to this external host an average of 3.4GB a day. Similar events of data upload to this external host, was seen from other endpoints in the network 2 times in the last 30 days",
        "detection_timestamp": 1682842685000,
        "dns_query_name": None,
        "dst_action_country": "US",
        "dst_action_external_hostname": "noneofyourbusiness.io",
        "dst_action_external_port": None,
        "dst_agent_id": "34.210.121.51",
        "dst_association_strength": 10,
        "dst_causality_actor_process_execution_time": None,
        "dynamic_fields": None,
        "end_match_attempt_ts": None,
        "endpoint_id": "172.16.7.41",
        "event_id": "ODI1OTMyMTQ2NDMyNzgyODQyMA==",
        "event_sub_type": 3,
        "event_timestamp": 1682804032000,
        "event_type": "Network Connections",
        "events_length": 1,
        "external_id": "b04c2b19-e84b-4429-8c86-e9e5e813fcbd",
        "filter_rule_id": None,
        "fw_app_category": None,
        "fw_app_id": "ip,tcp,ssl",
        "fw_app_subcategory": None,
        "fw_app_technology": None,
        "fw_device_name": "DC1ENV12APFW02",
        "fw_email_recipient": None,
        "fw_email_sender": None,
        "fw_email_subject": None,
        "fw_interface_from": "TAP",
        "fw_interface_to": "TAP",
        "fw_is_phishing": "N/A",
        "fw_misc": None,
        "fw_rule": "DC1ENV12APFW02|TAP",
        "fw_rule_id": None,
        "fw_serial_number": "007051000212107",
        "fw_url_domain": None,
        "fw_vsys": None,
        "fw_xff": None,
        "host_ip": "172.16.7.41",
        "host_ip_list": [
          "172.16.7.41"
        ],
        "host_name": "172.16.7.41",
        "identity_sub_type": None,
        "identity_type": None,
        "image_name": None,
        "is_pcap": False,
        "is_whitelisted": False,
        "last_modified_ts": None,
        "local_insert_ts": 1682843480516,
        "mac": "00:50:56:9f:24:41",
        "malicious_urls": None,
        "matching_service_rule_id": "81bfe385-c6a1-11ea-be5e-acde48001122",
        "matching_status": "MATCHED",
        "mitre_tactic_id_and_name": "TA0010 - Exfiltration",
        "mitre_technique_id_and_name": "T1048 - Exfiltration Over Alternative Protocol",
        "module_id": None,
        "name": "Large Upload (HTTPS)",
        "operation_name": None,
        "original_tags": "DS:PANW/NGFW",
        "os_actor_causality_id": None,
        "os_actor_effective_username": None,
        "os_actor_process_causality_id": None,
        "os_actor_process_command_line": None,
        "os_actor_process_image_name": None,
        "os_actor_process_image_path": None,
        "os_actor_process_image_sha256": None,
        "os_actor_process_instance_id": None,
        "os_actor_process_os_pid": None,
        "os_actor_process_signature_status": "N/A",
        "os_actor_process_signature_vendor": None,
        "os_actor_thread_thread_id": None,
        "project": None,
        "referenced_resource": None,
        "resolution_comment": None,
        "resolution_status": "STATUS_010_NEW",
        "resource_sub_type": None,
        "resource_type": None,
        "severity": "low",
        "source": "XDR Analytics",
        "starred": False,
        "story_id": "ODI1OTMyMTQ2NDMyNzgyODQyMA==",
        "tags": "DS:PANW/NGFW",
        "user_agent": None,
        "user_name": None}],
    "alerts_grouping_status": "Disabled",
    "assigned_user_mail": None,
    "assigned_user_pretty_name": None,
    "creation_time": 1680614903363,
    "critical_severity_alert_count": 0,
    "description": "1 'Large Upload (HTTPS)' alerts detected by XDR Analytics on host 172.16.7.41",
    "detection_time": None,
    "file_artifacts": [],
    "high_severity_alert_count": 0,
    "host_count": 1,
    "hosts": [
      "172.16.7.41:00:50:56:9f:24:41"
    ],
    "incident_id": "4331",
    "incident_name": None,
    "incident_sources": [
      "XDR Analytics"
    ],
    "is_blocked": False,
    "low_severity_alert_count": 1,
    "manual_description": "1 'Large Upload (HTTPS)' alert detected by XDR Analytics on host 172.16.7.41",
    "manual_score": None,
    "manual_severity": None,
    "med_severity_alert_count": 0,
    "mitre_tactics_ids_and_names": [
      "TA0010 - Exfiltration"
    ],
    "mitre_techniques_ids_and_names": [
      "T1048 - Exfiltration Over Alternative Protocol"
    ],
    "modification_time": 1690373750764,
    "network_artifacts": [
      {
        "alert_count": 16,
        "is_manual": False,
        "network_country": "US",
        "network_domain": "noneofyourbusiness.io",
        "network_remote_ip": "130.193.10.21",
        "network_remote_port": 443,
        "type": "DOMAIN"
      }
    ],
    "notes": None,
    "original_tags": [
      "DS:PANW/NGFW"
    ],
    "predicted_score": None,
    "resolve_comment": None,
    "resolved_timestamp": None,
    "rule_based_score": None,
    "severity": "low",
    "starred": False,
    "status": "new",
    "tags": [
      "DS:PANW/NGFW"
    ],
    "user_count": 0,
    "users": [],
    "wildfire_hits": 0,
    "xdr_url": "https://xsiam-ctf-v3.xdr.us.paloaltonetworks.com/incident-view?caseId=1284"
  }
]

    for i in range(1, max_fetch):
        new_data = rawJson
        new_data["description"] = f"'Suspicious API call from a Tor exit node' along with 4 other alerts generated by XDR Analytics BIOC and XDR Analytics involving user svc_dev"
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
            raw_incidents = createIncidentsListCTF3(2)
        else:
            # raw_incidents = client.get_incidents(gte_creation_time_milliseconds=last_fetch, limit=max_fetch,
            #                                    sort_by_creation_time='asc', starred=starred,
            #                                    starred_incidents_fetch_window=starred_incidents_fetch_window)
            raw_incidents = createIncidentsListCTF3(2)

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
    return None

def get_alerts_by_filter_command_ctf(client: CoreClient, args: Dict) -> CommandResults:

    prefix = "PaloAltoNetworksXDR"
    #filter_data['filter'] = filter_res
    #demisto.debug(f'sending the following request data: {request_data}')
    #raw_response = client.get_alerts_by_filter_data(request_data)
    raw_response = {
  "alerts": {
    "data": [
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
        "action_process_signature_status": "N//A",
        "action_process_signature_vendor": None,
        "action_registry_data": None,
        "action_registry_full_key": None,
        "action_registry_key_name": None,
        "action_registry_value_name": None,
        "action_remote_ip": None,
        "action_remote_ip_v6": None,
        "action_remote_port": None,
        "actor_causality_id": None,
        "actor_process_causality_id": None,
        "actor_process_command_line": None,
        "actor_process_image_md5": None,
        "actor_process_image_name": None,
        "actor_process_image_path": None,
        "actor_process_image_sha256": None,
        "actor_process_instance_id": None,
        "actor_process_os_pid": None,
        "actor_process_signature_status": "N//A",
        "actor_process_signature_vendor": None,
        "actor_thread_thread_id": None,
        "agent_data_collection_status": None,
        "agent_device_domain": None,
        "agent_fqdn": None,
        "agent_host_boot_time": None,
        "agent_install_type": "NA",
        "agent_ip_addresses_v6": None,
        "agent_is_vdi": None,
        "agent_os_sub_type": None,
        "agent_os_type": "NO_HOST",
        "agent_version": None,
        "alert_id": "14827",
        "alert_type": "Unclassified",
        "association_strength": 50,
        "attempt_counter": 0,
        "bioc_category_enum_key": None,
        "bioc_indicator": None,
        "case_id": 1284,
        "category": "Defense Evasion",
        "causality_actor_causality_id": None,
        "causality_actor_process_command_line": None,
        "causality_actor_process_execution_time": None,
        "causality_actor_process_image_md5": None,
        "causality_actor_process_image_name": None,
        "causality_actor_process_image_path": None,
        "causality_actor_process_image_sha256": None,
        "causality_actor_process_signature_status": "N//A",
        "causality_actor_process_signature_vendor": None,
        "cloud_provider": "AWS",
        "cluster_name": None,
        "container_id": None,
        "contains_featured_host": "NO",
        "contains_featured_ip": "NO",
        "contains_featured_user": "NO",
        "deduplicate_tokens": None,
        "description": "An unusual activity was performed in AWS, region eu-west-1. The CREATE operation was performed against a COMPUTE service in the project 666688938958. This behavior was not observed in the last 30 days",
        "detection_timestamp": 1676282755000,
        "dns_query_name": None,
        "dst_action_country": None,
        "dst_action_external_hostname": None,
        "dst_action_external_port": None,
        "dst_agent_id": None,
        "dst_association_strength": None,
        "dst_causality_actor_process_execution_time": None,
        "dynamic_fields": None,
        "end_match_attempt_ts": None,
        "endpoint_id": None,
        "event_id": "2db6ffaa-694d-560c-bdd1-8f22e97331db_4",
        "event_sub_type": 3,
        "event_timestamp": 1672665266000,
        "event_type": "Cloud Audit Log",
        "events_length": 1,
        "external_id": "8fa790af-ee28-4f27-9e5e-343e4053c44c",
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
        "fw_is_phishing": "N//A",
        "fw_misc": None,
        "fw_rule": None,
        "fw_rule_id": None,
        "fw_serial_number": None,
        "fw_url_domain": None,
        "fw_vsys": None,
        "fw_xff": None,
        "host_ip": "31.154.166.148",
        "host_ip_list": [
          "31.154.166.148"
        ],
        "host_name": None,
        "identity_sub_type": "IAM",
        "identity_type": "USER",
        "image_name": None,
        "is_pcap": False,
        "is_whitelisted": False,
        "last_modified_ts": 1686732679256,
        "local_insert_ts": 1672665528800,
        "mac": None,
        "malicious_urls": None,
        "matching_service_rule_id": "22e661ae-3081-4a2d-9550-c65b6b660af1",
        "matching_status": "MATCHED",
        "mitre_tactic_id_and_name": "TA0005 - Defense Evasion",
        "mitre_technique_id_and_name": "T1535 - Unused//Unsupported Cloud Regions",
        "module_id": None,
        "name": "A cloud compute instance was created in a dormant region",
        "operation_name": "CREATE",
        "original_tags": "DS:Amazon//AWS",
        "os_actor_causality_id": None,
        "os_actor_effective_username": None,
        "os_actor_process_causality_id": None,
        "os_actor_process_command_line": None,
        "os_actor_process_image_name": None,
        "os_actor_process_image_path": None,
        "os_actor_process_image_sha256": None,
        "os_actor_process_instance_id": None,
        "os_actor_process_os_pid": None,
        "os_actor_process_signature_status": "N//A",
        "os_actor_process_signature_vendor": None,
        "os_actor_thread_thread_id": None,
        "project": "666688938958",
        "referenced_resource": "arn:aws:ec2:us-west-2:666688938958:vpc//vpc-04cfed27f1f06f385",
        "resolution_comment": None,
        "resolution_status": "STATUS_020_UNDER_INVESTIGATION",
        "resource_sub_type": "VPC",
        "resource_type": "COMPUTE",
        "severity": "medium",
        "source": "XDR Analytics BIOC",
        "starred": False,
        "story_id": None,
        "tags": "DS:Amazon//AWS",
        "user_agent": "Boto3////1.24.93 Python//3.10.0 Darwin//20.6.0 Botocore//1.27.93",
        "user_name": "svc_dev"
      },
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
        "action_process_signature_status": "N//A",
        "action_process_signature_vendor": None,
        "action_registry_data": None,
        "action_registry_full_key": None,
        "action_registry_key_name": None,
        "action_registry_value_name": None,
        "action_remote_ip": None,
        "action_remote_ip_v6": None,
        "action_remote_port": None,
        "actor_causality_id": None,
        "actor_process_causality_id": None,
        "actor_process_command_line": None,
        "actor_process_image_md5": None,
        "actor_process_image_name": None,
        "actor_process_image_path": None,
        "actor_process_image_sha256": None,
        "actor_process_instance_id": None,
        "actor_process_os_pid": None,
        "actor_process_signature_status": "N//A",
        "actor_process_signature_vendor": None,
        "actor_thread_thread_id": None,
        "agent_data_collection_status": None,
        "agent_device_domain": None,
        "agent_fqdn": None,
        "agent_host_boot_time": None,
        "agent_install_type": "NA",
        "agent_ip_addresses_v6": None,
        "agent_is_vdi": None,
        "agent_os_sub_type": None,
        "agent_os_type": "NO_HOST",
        "agent_version": None,
        "alert_id": "16223",
        "alert_type": "Unclassified",
        "association_strength": None,
        "attempt_counter": 0,
        "bioc_category_enum_key": None,
        "bioc_indicator": None,
        "case_id": 1284,
        "category": "Impact",
        "causality_actor_causality_id": None,
        "causality_actor_process_command_line": None,
        "causality_actor_process_execution_time": None,
        "causality_actor_process_image_md5": None,
        "causality_actor_process_image_name": None,
        "causality_actor_process_image_path": None,
        "causality_actor_process_image_sha256": None,
        "causality_actor_process_signature_status": "N//A",
        "causality_actor_process_signature_vendor": None,
        "cloud_provider": "AWS",
        "cluster_name": None,
        "container_id": None,
        "contains_featured_host": "NO",
        "contains_featured_ip": "NO",
        "contains_featured_user": "NO",
        "deduplicate_tokens": None,
        "description": "The identity svc_dev created an unusual amount of compute resources. The activity seen on AWS provider within 666688938958 project on eu-west-1 region",
        "detection_timestamp": 1676282745000,
        "dns_query_name": None,
        "dst_action_country": None,
        "dst_action_external_hostname": None,
        "dst_action_external_port": None,
        "dst_agent_id": None,
        "dst_association_strength": None,
        "dst_causality_actor_process_execution_time": None,
        "dynamic_fields": None,
        "end_match_attempt_ts": None,
        "endpoint_id": "-1",
        "event_id": "36451364-79e7-582b-a5df-e331bd45bb1b_4",
        "event_sub_type": 3,
        "event_timestamp": 1676282725000,
        "event_type": "Cloud Audit Log",
        "events_length": 1,
        "external_id": "5c5beda1-a9ac-4799-959f-0f6b16f23f3a",
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
        "fw_is_phishing": "N//A",
        "fw_misc": None,
        "fw_rule": None,
        "fw_rule_id": None,
        "fw_serial_number": None,
        "fw_url_domain": None,
        "fw_vsys": None,
        "fw_xff": None,
        "host_ip": None,
        "host_ip_list": [],
        "host_name": None,
        "identity_sub_type": "IAM",
        "identity_type": "USER",
        "image_name": None,
        "is_pcap": False,
        "is_whitelisted": False,
        "last_modified_ts": 1686731961937,
        "local_insert_ts": 1676282795282,
        "mac": None,
        "malicious_urls": None,
        "matching_service_rule_id": "653d6d6c-2f5b-11ed-8017-acde48001122",
        "matching_status": "MATCHED",
        "mitre_tactic_id_and_name": "TA0040 - Impact",
        "mitre_technique_id_and_name": "T1496 - Resource Hijacking",
        "module_id": None,
        "name": "Allocation of multiple cloud compute resources with accelerator gear",
        "operation_name": "CREATE",
        "original_tags": "DS:Amazon//AWS",
        "os_actor_causality_id": None,
        "os_actor_effective_username": None,
        "os_actor_process_causality_id": None,
        "os_actor_process_command_line": None,
        "os_actor_process_image_name": None,
        "os_actor_process_image_path": None,
        "os_actor_process_image_sha256": None,
        "os_actor_process_instance_id": None,
        "os_actor_process_os_pid": None,
        "os_actor_process_signature_status": "N//A",
        "os_actor_process_signature_vendor": None,
        "os_actor_thread_thread_id": None,
        "project": "666688938958",
        "referenced_resource": "arn:aws:ec2:eu-west-1:666688938958:instance//i-0dc36ef8209f667fb",
        "resolution_comment": None,
        "resolution_status": "STATUS_020_UNDER_INVESTIGATION",
        "resource_sub_type": "COMPUTE_INSTANCE",
        "resource_type": "COMPUTE",
        "severity": "high",
        "source": "XDR Analytics",
        "starred": False,
        "story_id": None,
        "tags": "DS:Amazon//AWS",
        "user_agent": "Boto3//1.24.93 Python//3.10.0 Darwin//20.6.0 Botocore//1.27.93",
        "user_name": "svc_dev"
      },
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
        "action_process_signature_status": "N//A",
        "action_process_signature_vendor": None,
        "action_registry_data": None,
        "action_registry_full_key": None,
        "action_registry_key_name": None,
        "action_registry_value_name": None,
        "action_remote_ip": None,
        "action_remote_ip_v6": None,
        "action_remote_port": None,
        "actor_causality_id": None,
        "actor_process_causality_id": None,
        "actor_process_command_line": None,
        "actor_process_image_md5": None,
        "actor_process_image_name": None,
        "actor_process_image_path": None,
        "actor_process_image_sha256": None,
        "actor_process_instance_id": None,
        "actor_process_os_pid": None,
        "actor_process_signature_status": "N//A",
        "actor_process_signature_vendor": None,
        "actor_thread_thread_id": None,
        "agent_data_collection_status": None,
        "agent_device_domain": None,
        "agent_fqdn": None,
        "agent_host_boot_time": None,
        "agent_install_type": "NA",
        "agent_ip_addresses_v6": None,
        "agent_is_vdi": None,
        "agent_os_sub_type": None,
        "agent_os_type": "NO_HOST",
        "agent_version": None,
        "alert_id": "14873",
        "alert_type": "Unclassified",
        "association_strength": 50,
        "attempt_counter": 0,
        "bioc_category_enum_key": None,
        "bioc_indicator": None,
        "case_id": 1284,
        "category": "Execution",
        "causality_actor_causality_id": None,
        "causality_actor_process_command_line": None,
        "causality_actor_process_execution_time": None,
        "causality_actor_process_image_md5": None,
        "causality_actor_process_image_name": None,
        "causality_actor_process_image_path": None,
        "causality_actor_process_image_sha256": None,
        "causality_actor_process_signature_status": "N//A",
        "causality_actor_process_signature_vendor": None,
        "cloud_provider": "AWS",
        "cluster_name": None,
        "container_id": None,
        "contains_featured_host": "NO",
        "contains_featured_ip": "NO",
        "contains_featured_user": "NO",
        "deduplicate_tokens": None,
        "description": "The cloud Identity svc_dev has executed an API call. The identity's user-agent call is aws-cli//1.22.34 Python//3.10.4 Linux//5.16.0-kali7-cloud-amd64 botocore//1.27.28. The operation was performed on AWS//666688938958",
        "detection_timestamp": 1676282568000,
        "dns_query_name": None,
        "dst_action_country": None,
        "dst_action_external_hostname": None,
        "dst_action_external_port": None,
        "dst_agent_id": None,
        "dst_association_strength": None,
        "dst_causality_actor_process_execution_time": None,
        "dynamic_fields": None,
        "end_match_attempt_ts": None,
        "endpoint_id": None,
        "event_id": "210db407-f1fa-52c7-9ff5-bc3fd27426a9",
        "event_sub_type": 3,
        "event_timestamp": 1675768999000,
        "event_type": "Cloud Audit Log",
        "events_length": 1,
        "external_id": "8940f509-5f71-4309-b0ea-4b48eb2d0fd7",
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
        "fw_is_phishing": "N//A",
        "fw_misc": None,
        "fw_rule": None,
        "fw_rule_id": None,
        "fw_serial_number": None,
        "fw_url_domain": None,
        "fw_vsys": None,
        "fw_xff": None,
        "host_ip": "18.221.214.175",
        "host_ip_list": [
          "18.221.214.175"
        ],
        "host_name": None,
        "identity_sub_type": "IAM",
        "identity_type": "USER",
        "image_name": None,
        "is_pcap": False,
        "is_whitelisted": False,
        "last_modified_ts": 1686652368965,
        "local_insert_ts": 1675769251633,
        "mac": None,
        "malicious_urls": None,
        "matching_service_rule_id": "f6e71c10-dfd2-11eb-8670-acde48001122",
        "matching_status": "MATCHED",
        "mitre_tactic_id_and_name": "TA0002 - Execution",
        "mitre_technique_id_and_name": "T1204 - User Execution",
        "module_id": None,
        "name": "Penetration testing tool activity",
        "operation_name": "GET",
        "original_tags": "DS:Amazon//AWS",
        "os_actor_causality_id": None,
        "os_actor_effective_username": None,
        "os_actor_process_causality_id": None,
        "os_actor_process_command_line": None,
        "os_actor_process_image_name": None,
        "os_actor_process_image_path": None,
        "os_actor_process_image_sha256": None,
        "os_actor_process_instance_id": None,
        "os_actor_process_os_pid": None,
        "os_actor_process_signature_status": "N//A",
        "os_actor_process_signature_vendor": None,
        "os_actor_thread_thread_id": None,
        "project": "666688938958",
        "referenced_resource": None,
        "resolution_comment": None,
        "resolution_status": "STATUS_020_UNDER_INVESTIGATION",
        "resource_sub_type": None,
        "resource_type": "IDENTITY_ACCESS_MANAGEMENT",
        "severity": "medium",
        "source": "XDR Analytics BIOC",
        "starred": False,
        "story_id": None,
        "tags": "DS:Amazon//AWS",
        "user_agent": "aws-cli//1.22.34 Python//3.10.4 Linux//5.16.0-kali7-cloud-amd64 botocore//1.27.28",
        "user_name": "svc_dev"
      },
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
        "action_process_signature_status": "N//A",
        "action_process_signature_vendor": None,
        "action_registry_data": None,
        "action_registry_full_key": None,
        "action_registry_key_name": None,
        "action_registry_value_name": None,
        "action_remote_ip": None,
        "action_remote_ip_v6": None,
        "action_remote_port": None,
        "actor_causality_id": None,
        "actor_process_causality_id": None,
        "actor_process_command_line": None,
        "actor_process_image_md5": None,
        "actor_process_image_name": None,
        "actor_process_image_path": None,
        "actor_process_image_sha256": None,
        "actor_process_instance_id": None,
        "actor_process_os_pid": None,
        "actor_process_signature_status": "N//A",
        "actor_process_signature_vendor": None,
        "actor_thread_thread_id": None,
        "agent_data_collection_status": None,
        "agent_device_domain": None,
        "agent_fqdn": None,
        "agent_host_boot_time": None,
        "agent_install_type": "NA",
        "agent_ip_addresses_v6": None,
        "agent_is_vdi": None,
        "agent_os_sub_type": None,
        "agent_os_type": "NO_HOST",
        "agent_version": None,
        "alert_id": "16217",
        "alert_type": "Unclassified",
        "association_strength": 50,
        "attempt_counter": 0,
        "bioc_category_enum_key": None,
        "bioc_indicator": None,
        "case_id": 1284,
        "category": "Initial Access",
        "causality_actor_causality_id": None,
        "causality_actor_process_command_line": None,
        "causality_actor_process_execution_time": None,
        "causality_actor_process_image_md5": None,
        "causality_actor_process_image_name": None,
        "causality_actor_process_image_path": None,
        "causality_actor_process_image_sha256": None,
        "causality_actor_process_signature_status": "N//A",
        "causality_actor_process_signature_vendor": None,
        "cloud_provider": "AWS",
        "cluster_name": None,
        "container_id": None,
        "contains_featured_host": "NO",
        "contains_featured_ip": "NO",
        "contains_featured_user": "NO",
        "deduplicate_tokens": None,
        "description": "The cloud identity svc_dev connected from Czechia. This behavior was not observed in the last 30 days. The country Czechia was not seen in the organization in the last 30 days",
        "detection_timestamp": 1676281911000,
        "dns_query_name": None,
        "dst_action_country": None,
        "dst_action_external_hostname": None,
        "dst_action_external_port": None,
        "dst_agent_id": None,
        "dst_association_strength": None,
        "dst_causality_actor_process_execution_time": None,
        "dynamic_fields": None,
        "end_match_attempt_ts": None,
        "endpoint_id": None,
        "event_id": "44436ab8-bcdf-5753-829c-7de557d7361b",
        "event_sub_type": 3,
        "event_timestamp": 1676281911000,
        "event_type": "Cloud Audit Log",
        "events_length": 1,
        "external_id": "e2d60f8e-fc57-497e-8080-82e75802b190",
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
        "fw_is_phishing": "N//A",
        "fw_misc": None,
        "fw_rule": None,
        "fw_rule_id": None,
        "fw_serial_number": None,
        "fw_url_domain": None,
        "fw_vsys": None,
        "fw_xff": None,
        "host_ip": "130.193.10.21",
        "host_ip_list": [
          "130.193.10.21"
        ],
        "host_name": None,
        "identity_sub_type": "IAM",
        "identity_type": "USER",
        "image_name": None,
        "is_pcap": False,
        "is_whitelisted": False,
        "last_modified_ts": 1686735220954,
        "local_insert_ts": 1676282105888,
        "mac": None,
        "malicious_urls": None,
        "matching_service_rule_id": "32cff288-9e1e-11ec-ac34-acde48001122",
        "matching_status": "MATCHED",
        "mitre_tactic_id_and_name": "TA0001 - Initial Access",
        "mitre_technique_id_and_name": "T1078 - Valid Accounts",
        "module_id": None,
        "name": "A cloud identity executed an API call from an unusual country",
        "operation_name": "ENUMERATE",
        "original_tags": "DS:Amazon//AWS",
        "os_actor_causality_id": None,
        "os_actor_effective_username": None,
        "os_actor_process_causality_id": None,
        "os_actor_process_command_line": None,
        "os_actor_process_image_name": None,
        "os_actor_process_image_path": None,
        "os_actor_process_image_sha256": None,
        "os_actor_process_instance_id": None,
        "os_actor_process_os_pid": None,
        "os_actor_process_signature_status": "N//A",
        "os_actor_process_signature_vendor": None,
        "os_actor_thread_thread_id": None,
        "project": "666688938958",
        "referenced_resource": None,
        "resolution_comment": None,
        "resolution_status": "STATUS_020_UNDER_INVESTIGATION",
        "resource_sub_type": None,
        "resource_type": "COMPUTE",
        "severity": "high",
        "source": "XDR Analytics BIOC",
        "starred": False,
        "story_id": None,
        "tags": "DS:Amazon//AWS",
        "user_agent": "Boto3//1.24.93 Python//3.10.0 Darwin//20.6.0 Botocore//1.27.93",
        "user_name": "svc_dev"
      },
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
        "action_process_signature_status": "N//A",
        "action_process_signature_vendor": None,
        "action_registry_data": None,
        "action_registry_full_key": None,
        "action_registry_key_name": None,
        "action_registry_value_name": None,
        "action_remote_ip": None,
        "action_remote_ip_v6": None,
        "action_remote_port": None,
        "actor_causality_id": None,
        "actor_process_causality_id": None,
        "actor_process_command_line": None,
        "actor_process_image_md5": None,
        "actor_process_image_name": None,
        "actor_process_image_path": None,
        "actor_process_image_sha256": None,
        "actor_process_instance_id": None,
        "actor_process_os_pid": None,
        "actor_process_signature_status": "N//A",
        "actor_process_signature_vendor": None,
        "actor_thread_thread_id": None,
        "agent_data_collection_status": None,
        "agent_device_domain": None,
        "agent_fqdn": None,
        "agent_host_boot_time": None,
        "agent_install_type": "NA",
        "agent_ip_addresses_v6": None,
        "agent_is_vdi": None,
        "agent_os_sub_type": None,
        "agent_os_type": "NO_HOST",
        "agent_version": None,
        "alert_id": "16211",
        "alert_type": "Unclassified",
        "association_strength": 50,
        "attempt_counter": 0,
        "bioc_category_enum_key": None,
        "bioc_indicator": None,
        "case_id": 1284,
        "category": "Command and Control",
        "causality_actor_causality_id": None,
        "causality_actor_process_command_line": None,
        "causality_actor_process_execution_time": None,
        "causality_actor_process_image_md5": None,
        "causality_actor_process_image_name": None,
        "causality_actor_process_image_path": None,
        "causality_actor_process_image_sha256": None,
        "causality_actor_process_signature_status": "N//A",
        "causality_actor_process_signature_vendor": None,
        "cloud_provider": "AWS",
        "cluster_name": None,
        "container_id": None,
        "contains_featured_host": "NO",
        "contains_featured_ip": "NO",
        "contains_featured_user": "NO",
        "deduplicate_tokens": None,
        "description": "The cloud user svc_dev has called an API from 192.42.116.193. This IP address is known as a Tor exit node's IP address in the last 36 hours",
        "detection_timestamp": 1676281453000,
        "dns_query_name": None,
        "dst_action_country": None,
        "dst_action_external_hostname": None,
        "dst_action_external_port": None,
        "dst_agent_id": None,
        "dst_association_strength": None,
        "dst_causality_actor_process_execution_time": None,
        "dynamic_fields": None,
        "end_match_attempt_ts": None,
        "endpoint_id": None,
        "event_id": "aa5f2e70-3a1e-5244-8b65-47ea323bbce2",
        "event_sub_type": 3,
        "event_timestamp": 1676281453000,
        "event_type": "Cloud Audit Log",
        "events_length": 1,
        "external_id": "eb419ce4-a9cc-460d-bf40-f57436abfc18",
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
        "fw_is_phishing": "N//A",
        "fw_misc": None,
        "fw_rule": None,
        "fw_rule_id": None,
        "fw_serial_number": None,
        "fw_url_domain": None,
        "fw_vsys": None,
        "fw_xff": None,
        "host_ip": "130.193.10.21",
        "host_ip_list": [
          "130.193.10.21"
        ],
        "host_name": None,
        "identity_sub_type": "IAM",
        "identity_type": "USER",
        "image_name": None,
        "is_pcap": False,
        "is_whitelisted": False,
        "last_modified_ts": 1686650948777,
        "local_insert_ts": 1676281588380,
        "mac": None,
        "malicious_urls": None,
        "matching_service_rule_id": "ac17179d-68dd-46cc-8d2a-68d506e6626e",
        "matching_status": "MATCHED",
        "mitre_tactic_id_and_name": "TA0011 - Command and Control",
        "mitre_technique_id_and_name": "T1090.003 - Proxy: Multi-hop Proxy",
        "module_id": None,
        "name": "Suspicious API call from a Tor exit node",
        "operation_name": "GET",
        "original_tags": "DS:Amazon//AWS",
        "os_actor_causality_id": None,
        "os_actor_effective_username": None,
        "os_actor_process_causality_id": None,
        "os_actor_process_command_line": None,
        "os_actor_process_image_name": None,
        "os_actor_process_image_path": None,
        "os_actor_process_image_sha256": None,
        "os_actor_process_instance_id": None,
        "os_actor_process_os_pid": None,
        "os_actor_process_signature_status": "N//A",
        "os_actor_process_signature_vendor": None,
        "os_actor_thread_thread_id": None,
        "project": "666688938958",
        "referenced_resource": None,
        "resolution_comment": None,
        "resolution_status": "STATUS_020_UNDER_INVESTIGATION",
        "resource_sub_type": None,
        "resource_type": "IDENTITY_ACCESS_MANAGEMENT",
        "severity": "high",
        "source": "XDR Analytics BIOC",
        "starred": False,
        "story_id": None,
        "tags": "DS:Amazon//AWS",
        "user_agent": "aws-cli//1.22.34 Python//3.10.4 Linux//5.16.0-kali7-cloud-amd64 botocore//1.27.28",
        "user_name": "svc_dev"
      }
    ],
    "total_count": 5
  },
  "file_artifacts": {
    "data": [],
    "total_count": 0
  },
  "incident": {
    "aggregated_score": None,
    "alert_categories": [
      "Command and Control",
      "Defense Evasion",
      "Execution",
      "Impact",
      "Initial Access"
    ],
    "alert_count": 5,
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
        "action_process_signature_status": "N//A",
        "action_process_signature_vendor": None,
        "action_registry_data": None,
        "action_registry_full_key": None,
        "action_registry_key_name": None,
        "action_registry_value_name": None,
        "action_remote_ip": None,
        "action_remote_ip_v6": None,
        "action_remote_port": None,
        "actor_causality_id": None,
        "actor_process_causality_id": None,
        "actor_process_command_line": None,
        "actor_process_image_md5": None,
        "actor_process_image_name": None,
        "actor_process_image_path": None,
        "actor_process_image_sha256": None,
        "actor_process_instance_id": None,
        "actor_process_os_pid": None,
        "actor_process_signature_status": "N//A",
        "actor_process_signature_vendor": None,
        "actor_thread_thread_id": None,
        "agent_data_collection_status": None,
        "agent_device_domain": None,
        "agent_fqdn": None,
        "agent_host_boot_time": None,
        "agent_install_type": "NA",
        "agent_ip_addresses_v6": None,
        "agent_is_vdi": None,
        "agent_os_sub_type": None,
        "agent_os_type": "NO_HOST",
        "agent_version": None,
        "alert_id": "14827",
        "alert_type": "Unclassified",
        "association_strength": 50,
        "attempt_counter": 0,
        "bioc_category_enum_key": None,
        "bioc_indicator": None,
        "case_id": 1284,
        "category": "Defense Evasion",
        "causality_actor_causality_id": None,
        "causality_actor_process_command_line": None,
        "causality_actor_process_execution_time": None,
        "causality_actor_process_image_md5": None,
        "causality_actor_process_image_name": None,
        "causality_actor_process_image_path": None,
        "causality_actor_process_image_sha256": None,
        "causality_actor_process_signature_status": "N//A",
        "causality_actor_process_signature_vendor": None,
        "cloud_provider": "AWS",
        "cluster_name": None,
        "container_id": None,
        "contains_featured_host": "NO",
        "contains_featured_ip": "NO",
        "contains_featured_user": "NO",
        "deduplicate_tokens": None,
        "description": "An unusual activity was performed in AWS, region eu-west-1. The CREATE operation was performed against a COMPUTE service in the project 666688938958. This behavior was not observed in the last 30 days",
        "detection_timestamp": 1676282755000,
        "dns_query_name": None,
        "dst_action_country": None,
        "dst_action_external_hostname": None,
        "dst_action_external_port": None,
        "dst_agent_id": None,
        "dst_association_strength": None,
        "dst_causality_actor_process_execution_time": None,
        "dynamic_fields": None,
        "end_match_attempt_ts": None,
        "endpoint_id": None,
        "event_id": "2db6ffaa-694d-560c-bdd1-8f22e97331db_4",
        "event_sub_type": 3,
        "event_timestamp": 1672665266000,
        "event_type": "Cloud Audit Log",
        "events_length": 1,
        "external_id": "8fa790af-ee28-4f27-9e5e-343e4053c44c",
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
        "fw_is_phishing": "N//A",
        "fw_misc": None,
        "fw_rule": None,
        "fw_rule_id": None,
        "fw_serial_number": None,
        "fw_url_domain": None,
        "fw_vsys": None,
        "fw_xff": None,
        "host_ip": "31.154.166.148",
        "host_ip_list": [
          "31.154.166.148"
        ],
        "host_name": None,
        "identity_sub_type": "IAM",
        "identity_type": "USER",
        "image_name": None,
        "is_pcap": False,
        "is_whitelisted": False,
        "last_modified_ts": 1686732679256,
        "local_insert_ts": 1672665528800,
        "mac": None,
        "malicious_urls": None,
        "matching_service_rule_id": "22e661ae-3081-4a2d-9550-c65b6b660af1",
        "matching_status": "MATCHED",
        "mitre_tactic_id_and_name": "TA0005 - Defense Evasion",
        "mitre_technique_id_and_name": "T1535 - Unused//Unsupported Cloud Regions",
        "module_id": None,
        "name": "A cloud compute instance was created in a dormant region",
        "operation_name": "CREATE",
        "original_tags": "DS:Amazon//AWS",
        "os_actor_causality_id": None,
        "os_actor_effective_username": None,
        "os_actor_process_causality_id": None,
        "os_actor_process_command_line": None,
        "os_actor_process_image_name": None,
        "os_actor_process_image_path": None,
        "os_actor_process_image_sha256": None,
        "os_actor_process_instance_id": None,
        "os_actor_process_os_pid": None,
        "os_actor_process_signature_status": "N//A",
        "os_actor_process_signature_vendor": None,
        "os_actor_thread_thread_id": None,
        "project": "666688938958",
        "referenced_resource": "arn:aws:ec2:us-west-2:666688938958:vpc//vpc-04cfed27f1f06f385",
        "resolution_comment": None,
        "resolution_status": "STATUS_020_UNDER_INVESTIGATION",
        "resource_sub_type": "VPC",
        "resource_type": "COMPUTE",
        "severity": "medium",
        "source": "XDR Analytics BIOC",
        "starred": False,
        "story_id": None,
        "tags": "DS:Amazon//AWS",
        "user_agent": "Boto3//1.24.93 Python//3.10.0 Darwin//20.6.0 Botocore//1.27.93",
        "user_name": "svc_dev"
      },
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
        "action_process_signature_status": "N//A",
        "action_process_signature_vendor": None,
        "action_registry_data": None,
        "action_registry_full_key": None,
        "action_registry_key_name": None,
        "action_registry_value_name": None,
        "action_remote_ip": None,
        "action_remote_ip_v6": None,
        "action_remote_port": None,
        "actor_causality_id": None,
        "actor_process_causality_id": None,
        "actor_process_command_line": None,
        "actor_process_image_md5": None,
        "actor_process_image_name": None,
        "actor_process_image_path": None,
        "actor_process_image_sha256": None,
        "actor_process_instance_id": None,
        "actor_process_os_pid": None,
        "actor_process_signature_status": "N//A",
        "actor_process_signature_vendor": None,
        "actor_thread_thread_id": None,
        "agent_data_collection_status": None,
        "agent_device_domain": None,
        "agent_fqdn": None,
        "agent_host_boot_time": None,
        "agent_install_type": "NA",
        "agent_ip_addresses_v6": None,
        "agent_is_vdi": None,
        "agent_os_sub_type": None,
        "agent_os_type": "NO_HOST",
        "agent_version": None,
        "alert_id": "16223",
        "alert_type": "Unclassified",
        "association_strength": None,
        "attempt_counter": 0,
        "bioc_category_enum_key": None,
        "bioc_indicator": None,
        "case_id": 1284,
        "category": "Impact",
        "causality_actor_causality_id": None,
        "causality_actor_process_command_line": None,
        "causality_actor_process_execution_time": None,
        "causality_actor_process_image_md5": None,
        "causality_actor_process_image_name": None,
        "causality_actor_process_image_path": None,
        "causality_actor_process_image_sha256": None,
        "causality_actor_process_signature_status": "N//A",
        "causality_actor_process_signature_vendor": None,
        "cloud_provider": "AWS",
        "cluster_name": None,
        "container_id": None,
        "contains_featured_host": "NO",
        "contains_featured_ip": "NO",
        "contains_featured_user": "NO",
        "deduplicate_tokens": None,
        "description": "The identity svc_dev created an unusual amount of compute resources. The activity seen on AWS provider within 666688938958 project on eu-west-1 region",
        "detection_timestamp": 1676282745000,
        "dns_query_name": None,
        "dst_action_country": None,
        "dst_action_external_hostname": None,
        "dst_action_external_port": None,
        "dst_agent_id": None,
        "dst_association_strength": None,
        "dst_causality_actor_process_execution_time": None,
        "dynamic_fields": None,
        "end_match_attempt_ts": None,
        "endpoint_id": "-1",
        "event_id": "36451364-79e7-582b-a5df-e331bd45bb1b_4",
        "event_sub_type": 3,
        "event_timestamp": 1676282725000,
        "event_type": "Cloud Audit Log",
        "events_length": 1,
        "external_id": "5c5beda1-a9ac-4799-959f-0f6b16f23f3a",
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
        "fw_is_phishing": "N//A",
        "fw_misc": None,
        "fw_rule": None,
        "fw_rule_id": None,
        "fw_serial_number": None,
        "fw_url_domain": None,
        "fw_vsys": None,
        "fw_xff": None,
        "host_ip": None,
        "host_ip_list": [],
        "host_name": None,
        "identity_sub_type": "IAM",
        "identity_type": "USER",
        "image_name": None,
        "is_pcap": False,
        "is_whitelisted": False,
        "last_modified_ts": 1686731961937,
        "local_insert_ts": 1676282795282,
        "mac": None,
        "malicious_urls": None,
        "matching_service_rule_id": "653d6d6c-2f5b-11ed-8017-acde48001122",
        "matching_status": "MATCHED",
        "mitre_tactic_id_and_name": "TA0040 - Impact",
        "mitre_technique_id_and_name": "T1496 - Resource Hijacking",
        "module_id": None,
        "name": "Allocation of multiple cloud compute resources with accelerator gear",
        "operation_name": "CREATE",
        "original_tags": "DS:Amazon//AWS",
        "os_actor_causality_id": None,
        "os_actor_effective_username": None,
        "os_actor_process_causality_id": None,
        "os_actor_process_command_line": None,
        "os_actor_process_image_name": None,
        "os_actor_process_image_path": None,
        "os_actor_process_image_sha256": None,
        "os_actor_process_instance_id": None,
        "os_actor_process_os_pid": None,
        "os_actor_process_signature_status": "N//A",
        "os_actor_process_signature_vendor": None,
        "os_actor_thread_thread_id": None,
        "project": "666688938958",
        "referenced_resource": "arn:aws:ec2:eu-west-1:666688938958:instance//i-0dc36ef8209f667fb",
        "resolution_comment": None,
        "resolution_status": "STATUS_020_UNDER_INVESTIGATION",
        "resource_sub_type": "COMPUTE_INSTANCE",
        "resource_type": "COMPUTE",
        "severity": "high",
        "source": "XDR Analytics",
        "starred": False,
        "story_id": None,
        "tags": "DS:Amazon//AWS",
        "user_agent": "Boto3//1.24.93 Python//3.10.0 Darwin//20.6.0 Botocore//1.27.93",
        "user_name": "svc_dev"
      },
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
        "action_process_signature_status": "N//A",
        "action_process_signature_vendor": None,
        "action_registry_data": None,
        "action_registry_full_key": None,
        "action_registry_key_name": None,
        "action_registry_value_name": None,
        "action_remote_ip": None,
        "action_remote_ip_v6": None,
        "action_remote_port": None,
        "actor_causality_id": None,
        "actor_process_causality_id": None,
        "actor_process_command_line": None,
        "actor_process_image_md5": None,
        "actor_process_image_name": None,
        "actor_process_image_path": None,
        "actor_process_image_sha256": None,
        "actor_process_instance_id": None,
        "actor_process_os_pid": None,
        "actor_process_signature_status": "N//A",
        "actor_process_signature_vendor": None,
        "actor_thread_thread_id": None,
        "agent_data_collection_status": None,
        "agent_device_domain": None,
        "agent_fqdn": None,
        "agent_host_boot_time": None,
        "agent_install_type": "NA",
        "agent_ip_addresses_v6": None,
        "agent_is_vdi": None,
        "agent_os_sub_type": None,
        "agent_os_type": "NO_HOST",
        "agent_version": None,
        "alert_id": "14873",
        "alert_type": "Unclassified",
        "association_strength": 50,
        "attempt_counter": 0,
        "bioc_category_enum_key": None,
        "bioc_indicator": None,
        "case_id": 1284,
        "category": "Execution",
        "causality_actor_causality_id": None,
        "causality_actor_process_command_line": None,
        "causality_actor_process_execution_time": None,
        "causality_actor_process_image_md5": None,
        "causality_actor_process_image_name": None,
        "causality_actor_process_image_path": None,
        "causality_actor_process_image_sha256": None,
        "causality_actor_process_signature_status": "N//A",
        "causality_actor_process_signature_vendor": None,
        "cloud_provider": "AWS",
        "cluster_name": None,
        "container_id": None,
        "contains_featured_host": "NO",
        "contains_featured_ip": "NO",
        "contains_featured_user": "NO",
        "deduplicate_tokens": None,
        "description": "The cloud Identity svc_dev has executed an API call. The identity's user-agent call is aws-cli//1.22.34 Python//3.10.4 Linux//5.16.0-kali7-cloud-amd64 botocore//1.27.28. The operation was performed on AWS//666688938958",
        "detection_timestamp": 1676282568000,
        "dns_query_name": None,
        "dst_action_country": None,
        "dst_action_external_hostname": None,
        "dst_action_external_port": None,
        "dst_agent_id": None,
        "dst_association_strength": None,
        "dst_causality_actor_process_execution_time": None,
        "dynamic_fields": None,
        "end_match_attempt_ts": None,
        "endpoint_id": None,
        "event_id": "210db407-f1fa-52c7-9ff5-bc3fd27426a9",
        "event_sub_type": 3,
        "event_timestamp": 1675768999000,
        "event_type": "Cloud Audit Log",
        "events_length": 1,
        "external_id": "8940f509-5f71-4309-b0ea-4b48eb2d0fd7",
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
        "fw_is_phishing": "N//A",
        "fw_misc": None,
        "fw_rule": None,
        "fw_rule_id": None,
        "fw_serial_number": None,
        "fw_url_domain": None,
        "fw_vsys": None,
        "fw_xff": None,
        "host_ip": "18.221.214.175",
        "host_ip_list": [
          "18.221.214.175"
        ],
        "host_name": None,
        "identity_sub_type": "IAM",
        "identity_type": "USER",
        "image_name": None,
        "is_pcap": False,
        "is_whitelisted": False,
        "last_modified_ts": 1686652368965,
        "local_insert_ts": 1675769251633,
        "mac": None,
        "malicious_urls": None,
        "matching_service_rule_id": "f6e71c10-dfd2-11eb-8670-acde48001122",
        "matching_status": "MATCHED",
        "mitre_tactic_id_and_name": "TA0002 - Execution",
        "mitre_technique_id_and_name": "T1204 - User Execution",
        "module_id": None,
        "name": "Penetration testing tool activity",
        "operation_name": "GET",
        "original_tags": "DS:Amazon//AWS",
        "os_actor_causality_id": None,
        "os_actor_effective_username": None,
        "os_actor_process_causality_id": None,
        "os_actor_process_command_line": None,
        "os_actor_process_image_name": None,
        "os_actor_process_image_path": None,
        "os_actor_process_image_sha256": None,
        "os_actor_process_instance_id": None,
        "os_actor_process_os_pid": None,
        "os_actor_process_signature_status": "N//A",
        "os_actor_process_signature_vendor": None,
        "os_actor_thread_thread_id": None,
        "project": "666688938958",
        "referenced_resource": None,
        "resolution_comment": None,
        "resolution_status": "STATUS_020_UNDER_INVESTIGATION",
        "resource_sub_type": None,
        "resource_type": "IDENTITY_ACCESS_MANAGEMENT",
        "severity": "medium",
        "source": "XDR Analytics BIOC",
        "starred": False,
        "story_id": None,
        "tags": "DS:Amazon//AWS",
        "user_agent": "aws-cli//1.22.34 Python//3.10.4 Linux//5.16.0-kali7-cloud-amd64 botocore//1.27.28",
        "user_name": "svc_dev"
      },
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
        "action_process_signature_status": "N//A",
        "action_process_signature_vendor": None,
        "action_registry_data": None,
        "action_registry_full_key": None,
        "action_registry_key_name": None,
        "action_registry_value_name": None,
        "action_remote_ip": None,
        "action_remote_ip_v6": None,
        "action_remote_port": None,
        "actor_causality_id": None,
        "actor_process_causality_id": None,
        "actor_process_command_line": None,
        "actor_process_image_md5": None,
        "actor_process_image_name": None,
        "actor_process_image_path": None,
        "actor_process_image_sha256": None,
        "actor_process_instance_id": None,
        "actor_process_os_pid": None,
        "actor_process_signature_status": "N//A",
        "actor_process_signature_vendor": None,
        "actor_thread_thread_id": None,
        "agent_data_collection_status": None,
        "agent_device_domain": None,
        "agent_fqdn": None,
        "agent_host_boot_time": None,
        "agent_install_type": "NA",
        "agent_ip_addresses_v6": None,
        "agent_is_vdi": None,
        "agent_os_sub_type": None,
        "agent_os_type": "NO_HOST",
        "agent_version": None,
        "alert_id": "16217",
        "alert_type": "Unclassified",
        "association_strength": 50,
        "attempt_counter": 0,
        "bioc_category_enum_key": None,
        "bioc_indicator": None,
        "case_id": 1284,
        "category": "Initial Access",
        "causality_actor_causality_id": None,
        "causality_actor_process_command_line": None,
        "causality_actor_process_execution_time": None,
        "causality_actor_process_image_md5": None,
        "causality_actor_process_image_name": None,
        "causality_actor_process_image_path": None,
        "causality_actor_process_image_sha256": None,
        "causality_actor_process_signature_status": "N//A",
        "causality_actor_process_signature_vendor": None,
        "cloud_provider": "AWS",
        "cluster_name": None,
        "container_id": None,
        "contains_featured_host": "NO",
        "contains_featured_ip": "NO",
        "contains_featured_user": "NO",
        "deduplicate_tokens": None,
        "description": "The cloud identity svc_dev connected from Czechia. This behavior was not observed in the last 30 days. The country Czechia was not seen in the organization in the last 30 days",
        "detection_timestamp": 1676281911000,
        "dns_query_name": None,
        "dst_action_country": None,
        "dst_action_external_hostname": None,
        "dst_action_external_port": None,
        "dst_agent_id": None,
        "dst_association_strength": None,
        "dst_causality_actor_process_execution_time": None,
        "dynamic_fields": None,
        "end_match_attempt_ts": None,
        "endpoint_id": None,
        "event_id": "44436ab8-bcdf-5753-829c-7de557d7361b",
        "event_sub_type": 3,
        "event_timestamp": 1676281911000,
        "event_type": "Cloud Audit Log",
        "events_length": 1,
        "external_id": "e2d60f8e-fc57-497e-8080-82e75802b190",
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
        "fw_is_phishing": "N//A",
        "fw_misc": None,
        "fw_rule": None,
        "fw_rule_id": None,
        "fw_serial_number": None,
        "fw_url_domain": None,
        "fw_vsys": None,
        "fw_xff": None,
        "host_ip": "130.193.10.21",
        "host_ip_list": [
          "130.193.10.21"
        ],
        "host_name": None,
        "identity_sub_type": "IAM",
        "identity_type": "USER",
        "image_name": None,
        "is_pcap": False,
        "is_whitelisted": False,
        "last_modified_ts": 1686735220954,
        "local_insert_ts": 1676282105888,
        "mac": None,
        "malicious_urls": None,
        "matching_service_rule_id": "32cff288-9e1e-11ec-ac34-acde48001122",
        "matching_status": "MATCHED",
        "mitre_tactic_id_and_name": "TA0001 - Initial Access",
        "mitre_technique_id_and_name": "T1078 - Valid Accounts",
        "module_id": None,
        "name": "A cloud identity executed an API call from an unusual country",
        "operation_name": "ENUMERATE",
        "original_tags": "DS:Amazon//AWS",
        "os_actor_causality_id": None,
        "os_actor_effective_username": None,
        "os_actor_process_causality_id": None,
        "os_actor_process_command_line": None,
        "os_actor_process_image_name": None,
        "os_actor_process_image_path": None,
        "os_actor_process_image_sha256": None,
        "os_actor_process_instance_id": None,
        "os_actor_process_os_pid": None,
        "os_actor_process_signature_status": "N//A",
        "os_actor_process_signature_vendor": None,
        "os_actor_thread_thread_id": None,
        "project": "666688938958",
        "referenced_resource": None,
        "resolution_comment": None,
        "resolution_status": "STATUS_020_UNDER_INVESTIGATION",
        "resource_sub_type": None,
        "resource_type": "COMPUTE",
        "severity": "high",
        "source": "XDR Analytics BIOC",
        "starred": False,
        "story_id": None,
        "tags": "DS:Amazon//AWS",
        "user_agent": "Boto3//1.24.93 Python//3.10.0 Darwin//20.6.0 Botocore//1.27.93",
        "user_name": "svc_dev"
      },
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
        "action_process_signature_status": "N//A",
        "action_process_signature_vendor": None,
        "action_registry_data": None,
        "action_registry_full_key": None,
        "action_registry_key_name": None,
        "action_registry_value_name": None,
        "action_remote_ip": None,
        "action_remote_ip_v6": None,
        "action_remote_port": None,
        "actor_causality_id": None,
        "actor_process_causality_id": None,
        "actor_process_command_line": None,
        "actor_process_image_md5": None,
        "actor_process_image_name": None,
        "actor_process_image_path": None,
        "actor_process_image_sha256": None,
        "actor_process_instance_id": None,
        "actor_process_os_pid": None,
        "actor_process_signature_status": "N//A",
        "actor_process_signature_vendor": None,
        "actor_thread_thread_id": None,
        "agent_data_collection_status": None,
        "agent_device_domain": None,
        "agent_fqdn": None,
        "agent_host_boot_time": None,
        "agent_install_type": "NA",
        "agent_ip_addresses_v6": None,
        "agent_is_vdi": None,
        "agent_os_sub_type": None,
        "agent_os_type": "NO_HOST",
        "agent_version": None,
        "alert_id": "16211",
        "alert_type": "Unclassified",
        "association_strength": 50,
        "attempt_counter": 0,
        "bioc_category_enum_key": None,
        "bioc_indicator": None,
        "case_id": 1284,
        "category": "Command and Control",
        "causality_actor_causality_id": None,
        "causality_actor_process_command_line": None,
        "causality_actor_process_execution_time": None,
        "causality_actor_process_image_md5": None,
        "causality_actor_process_image_name": None,
        "causality_actor_process_image_path": None,
        "causality_actor_process_image_sha256": None,
        "causality_actor_process_signature_status": "N//A",
        "causality_actor_process_signature_vendor": None,
        "cloud_provider": "AWS",
        "cluster_name": None,
        "container_id": None,
        "contains_featured_host": "NO",
        "contains_featured_ip": "NO",
        "contains_featured_user": "NO",
        "deduplicate_tokens": None,
        "description": "The cloud user svc_dev has called an API from 192.42.116.193. This IP address is known as a Tor exit node's IP address in the last 36 hours",
        "detection_timestamp": 1676281453000,
        "dns_query_name": None,
        "dst_action_country": None,
        "dst_action_external_hostname": None,
        "dst_action_external_port": None,
        "dst_agent_id": None,
        "dst_association_strength": None,
        "dst_causality_actor_process_execution_time": None,
        "dynamic_fields": None,
        "end_match_attempt_ts": None,
        "endpoint_id": None,
        "event_id": "aa5f2e70-3a1e-5244-8b65-47ea323bbce2",
        "event_sub_type": 3,
        "event_timestamp": 1676281453000,
        "event_type": "Cloud Audit Log",
        "events_length": 1,
        "external_id": "eb419ce4-a9cc-460d-bf40-f57436abfc18",
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
        "fw_is_phishing": "N//A",
        "fw_misc": None,
        "fw_rule": None,
        "fw_rule_id": None,
        "fw_serial_number": None,
        "fw_url_domain": None,
        "fw_vsys": None,
        "fw_xff": None,
        "host_ip": "130.193.10.21",
        "host_ip_list": [
          "130.193.10.21"
        ],
        "host_name": None,
        "identity_sub_type": "IAM",
        "identity_type": "USER",
        "image_name": None,
        "is_pcap": False,
        "is_whitelisted": False,
        "last_modified_ts": 1686650948777,
        "local_insert_ts": 1676281588380,
        "mac": None,
        "malicious_urls": None,
        "matching_service_rule_id": "ac17179d-68dd-46cc-8d2a-68d506e6626e",
        "matching_status": "MATCHED",
        "mitre_tactic_id_and_name": "TA0011 - Command and Control",
        "mitre_technique_id_and_name": "T1090.003 - Proxy: Multi-hop Proxy",
        "module_id": None,
        "name": "Suspicious API call from a Tor exit node",
        "operation_name": "GET",
        "original_tags": "DS:Amazon//AWS",
        "os_actor_causality_id": None,
        "os_actor_effective_username": None,
        "os_actor_process_causality_id": None,
        "os_actor_process_command_line": None,
        "os_actor_process_image_name": None,
        "os_actor_process_image_path": None,
        "os_actor_process_image_sha256": None,
        "os_actor_process_instance_id": None,
        "os_actor_process_os_pid": None,
        "os_actor_process_signature_status": "N//A",
        "os_actor_process_signature_vendor": None,
        "os_actor_thread_thread_id": None,
        "project": "666688938958",
        "referenced_resource": None,
        "resolution_comment": None,
        "resolution_status": "STATUS_020_UNDER_INVESTIGATION",
        "resource_sub_type": None,
        "resource_type": "IDENTITY_ACCESS_MANAGEMENT",
        "severity": "high",
        "source": "XDR Analytics BIOC",
        "starred": False,
        "story_id": None,
        "tags": "DS:Amazon//AWS",
        "user_agent": "aws-cli//1.22.34 Python//3.10.4 Linux//5.16.0-kali7-cloud-amd64 botocore//1.27.28",
        "user_name": "svc_dev"
      }
    ],
    "alerts_grouping_status": "Disabled",
    "assigned_user_mail": None,
    "assigned_user_pretty_name": None,
    "creation_time": 1675769271786,
    "critical_severity_alert_count": 0,
    "description": "'Suspicious API call from a Tor exit node' along with 4 other alerts generated by XDR Analytics BIOC and XDR Analytics involving user svc_dev",
    "detection_time": None,
    "file_artifacts": [],
    "high_severity_alert_count": 3,
    "host_count": 0,
    "hosts": None,
    "incident_id": "1284",
    "incident_name": None,
    "incident_sources": [
      "XDR Analytics BIOC",
      "XDR Analytics"
    ],
    "is_blocked": False,
    "low_severity_alert_count": 0,
    "manual_description": None,
    "manual_score": None,
    "manual_severity": "high",
    "med_severity_alert_count": 2,
    "mitre_tactics_ids_and_names": [
      "TA0001 - Initial Access",
      "TA0002 - Execution",
      "TA0005 - Defense Evasion",
      "TA0011 - Command and Control",
      "TA0040 - Impact"
    ],
    "mitre_techniques_ids_and_names": [
      "T1078 - Valid Accounts",
      "T1090.003 - Proxy: Multi-hop Proxy",
      "T1204 - User Execution",
      "T1496 - Resource Hijacking",
      "T1535 - Unused//Unsupported Cloud Regions"
    ],
    "modification_time": 1686735083317,
    "network_artifacts": [],
    "notes": None,
    "original_tags": [
      "DS:Amazon//AWS"
    ],
    "predicted_score": 100,
    "resolve_comment": None,
    "resolved_timestamp": None,
    "rule_based_score": None,
    "severity": "high",
    "starred": True,
    "status": "new",
    "tags": [
      "DS:Amazon//AWS"
    ],
    "user_count": 1,
    "users": [
      "svc_dev"
    ],
    "wildfire_hits": 0,
    "xdr_url": "https:////xsiam-ctf-v3.xdr.us.paloaltonetworks.com//incident-view?caseId=1284"
  },
  "network_artifacts": {
    "data": [],
    "total_count": 0
  }
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

        elif command == 'xdr-script-run':  # used with polling =  always
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

        elif command == 'xdr-get-cloud-original-alerts-ctf':
            return_results(get_original_alerts_command(client, args))

        elif command == 'xdr-get-alerts-ctf':
            return_results(get_alerts_by_filter_command_ctf(client, args))

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

