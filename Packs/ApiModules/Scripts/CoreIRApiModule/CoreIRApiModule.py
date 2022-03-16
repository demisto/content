import demistomock as demisto  # noqa: F401
import urllib3
from CommonServerPython import *  # noqa: F401

# Disable insecure warnings
urllib3.disable_warnings()

ALERT_GENERAL_FIELDS = {
    'detection_modules',
    'alert_full_description',
    'matching_service_rule_id',
    'variation_rule_id',
    'content_version',
    'detector_id',
    'mitre_technique_id_and_name',
    'silent',
    'mitre_technique_ids',
    'activity_first_seet_at',
    '_type',
    'dst_association_strength',
    'alert_description',
}

ALERT_EVENT_GENERAL_FIELDS = {
    "_time",
    "vendor",
    "event_timestamp",
    "event_type",
    "event_id",
    "cloud_provider",
    "project",
    "cloud_provider_event_id",
    "cloud_correlation_id",
    "operation_name_orig",
    "operation_name",
    "identity_orig",
    "identity_name",
    "identity_uuid",
    "identity_type",
    "identity_sub_type",
    "identity_invoked_by_name",
    "identity_invoked_by_uuid",
    "identity_invoked_by_type",
    "identity_invoked_by_sub_type",
    "operation_status",
    "operation_status_orig",
    "operation_status_orig_code",
    "operation_status_reason_provided",
    "resource_type",
    "resource_type_orig",
    "resource_sub_type",
    "resource_sub_type_orig",
    "region",
    "zone",
    "referenced_resource",
    "referenced_resource_name",
    "referenced_resources_count",
    "user_agent",
    "caller_ip",
    'caller_ip_geolocation',
    "caller_ip_asn",
    'caller_project',
    'raw_log',
    "log_name",
    "caller_ip_asn_org",
    "event_base_id",
    "ingestion_time",
}


ALERT_EVENT_GENERAL_FIELDS = {
    "_time",
    "vendor",
    "event_timestamp",
    "event_type",
    "event_id",
    "cloud_provider",
    "project",
    "cloud_provider_event_id",
    "cloud_correlation_id",
    "operation_name_orig",
    "operation_name",
    "identity_orig",
    "identity_name",
    "identity_uuid",
    "identity_type",
    "identity_sub_type",
    "identity_invoked_by_name",
    "identity_invoked_by_uuid",
    "identity_invoked_by_type",
    "identity_invoked_by_sub_type",
    "operation_status",
    "operation_status_orig",
    "operation_status_orig_code",
    "operation_status_reason_provided",
    "resource_type",
    "resource_type_orig",
    "resource_sub_type",
    "resource_sub_type_orig",
    "region",
    "zone",
    "referenced_resource",
    "referenced_resource_name",
    "referenced_resources_count",
    "user_agent",
    "caller_ip",
    'caller_ip_geolocation',
    "caller_ip_asn",
    'caller_project',
    'raw_log',
    "log_name",
    "caller_ip_asn_org",
    "event_base_id",
    "ingestion_time",
}

ALERT_EVENT_AWS_FIELDS = {
    "eventVersion",
    "userIdentity",
    "eventTime",
    "eventSource",
    "eventName",
    "awsRegion",
    "sourceIPAddress",
    "userAgent",
    "requestID",
    "eventID",
    "readOnly",
    "eventType",
    "apiVersion",
    "managementEvent",
    "recipientAccountId",
    "eventCategory",
    "errorCode",
    "errorMessage",
    "resources",
}

ALERT_EVENT_GCP_FIELDS = {
    "labels",
    "operation",
    "protoPayload",
    "resource",
    "severity",
    "timestamp",
}

ALERT_EVENT_AZURE_FIELDS = {
    "time",
    "resourceId",
    "category",
    "operationName",
    "operationVersion",
    "schemaVersion",
    "statusCode",
    "statusText",
    "callerIpAddress",
    "correlationId",
    "identity",
    "level",
    "properties",
    "uri",
    "protocol",
    "resourceType",
    "tenantId",
}


class CoreClient(BaseClient):

    def __init__(self, base_url: str, headers: dict, timeout: int = 120, proxy: bool = False, verify: bool = False):
        self.timeout = timeout
        super().__init__(base_url=base_url, headers=headers, proxy=proxy, verify=verify)

    def get_incidents(self, incident_id_list=None, lte_modification_time=None, gte_modification_time=None,
                      lte_creation_time=None, gte_creation_time=None, status=None, sort_by_modification_time=None,
                      sort_by_creation_time=None, page_number=0, limit=100, gte_creation_time_milliseconds=0):
        """
        Filters and returns incidents

        :param incident_id_list: List of incident ids - must be list
        :param lte_modification_time: string of time format "2019-12-31T23:59:00"
        :param gte_modification_time: string of time format "2019-12-31T23:59:00"
        :param lte_creation_time: string of time format "2019-12-31T23:59:00"
        :param gte_creation_time: string of time format "2019-12-31T23:59:00"
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

        if status:
            filters.append({
                'field': 'status',
                'operator': 'eq',
                'value': status
            })

        if len(filters) > 0:
            request_data['filters'] = filters
        res = self._http_request(
            method='POST',
            url_suffix='/incidents/get_incidents/',
            json_data={'request_data': request_data},
            timeout=self.timeout
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
            'update_data': update_data,
        }

        self._http_request(
            method='POST',
            url_suffix='/incidents/update_incident/',
            json_data={'request_data': request_data},
            timeout=self.timeout
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
                      status=None,
                      no_filter=False
                      ):

        search_from = page_number * limit
        search_to = search_from + limit

        request_data = {
            'search_from': search_from,
            'search_to': search_to,
        }

        if no_filter:
            reply = self._http_request(
                method='POST',
                url_suffix='/endpoints/get_endpoints/',
                json_data={},
                timeout=self.timeout
            )
            endpoints = reply.get('reply')[search_from:search_to]
            for endpoint in endpoints:
                if not endpoint.get('endpoint_id'):
                    endpoint['endpoint_id'] = endpoint.get('agent_id')

        else:
            filters = []

            if status:
                filters.append({
                    'field': 'endpoint_status',
                    'operator': 'IN',
                    'value': [status]
                })

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
                    'field': 'alias',
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
                json_data={'request_data': request_data},
                timeout=self.timeout
            )

            endpoints = reply.get('reply').get('endpoints', [])
        return endpoints

    def isolate_endpoint(self, endpoint_id, incident_id=None):
        request_data = {
            'endpoint_id': endpoint_id,
        }
        if incident_id:
            request_data['incident_id'] = incident_id

        reply = self._http_request(
            method='POST',
            url_suffix='/endpoints/isolate',
            json_data={'request_data': request_data},
            timeout=self.timeout
        )
        return reply.get('reply')

    def unisolate_endpoint(self, endpoint_id, incident_id=None):
        request_data = {
            'endpoint_id': endpoint_id,
        }
        if incident_id:
            request_data['incident_id'] = incident_id

        reply = self._http_request(
            method='POST',
            url_suffix='/endpoints/unisolate',
            json_data={'request_data': request_data},
            timeout=self.timeout
        )
        return reply.get('reply')

    def get_distribution_url(self, distribution_id, package_type):
        reply = self._http_request(
            method='POST',
            url_suffix='/distributions/get_dist_url/',
            json_data={
                'request_data': {
                    'distribution_id': distribution_id,
                    'package_type': package_type
                }
            },
            timeout=self.timeout
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
            },
            timeout=self.timeout
        )

        return reply.get('reply').get('status')

    def get_distribution_versions(self):
        reply = self._http_request(
            method='POST',
            url_suffix='/distributions/get_versions/',
            json_data={},
            timeout=self.timeout
        )

        return reply.get('reply')

    def create_distribution(self, name, platform, package_type, agent_version, description):
        request_data = {}
        if package_type == 'standalone':
            request_data = {
                'name': name,
                'platform': platform,
                'package_type': package_type,
                'agent_version': agent_version,
                'description': description,
            }
        elif package_type == 'upgrade':
            request_data = {
                'name': name,
                'package_type': package_type,
                'description': description,
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
            },
            timeout=self.timeout
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
            json_data={'request_data': request_data},
            timeout=self.timeout
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
            json_data={'request_data': request_data},
            timeout=self.timeout
        )

        return reply.get('reply').get('data', [])

    def blocklist_files(self, hash_list, comment=None, incident_id=None, detailed_response=False):
        request_data: Dict[str, Any] = {"hash_list": hash_list}
        if comment:
            request_data["comment"] = comment
        if incident_id:
            request_data['incident_id'] = incident_id
        if detailed_response:
            request_data['detailed_response'] = detailed_response

        self._headers['content-type'] = 'application/json'
        reply = self._http_request(
            method='POST',
            url_suffix='/hash_exceptions/blocklist/',
            json_data={'request_data': request_data},
            ok_codes=(200, 201, 500,),
            timeout=self.timeout
        )
        return reply.get('reply')

    def remove_blocklist_files(self, hash_list, comment=None, incident_id=None):
        request_data: Dict[str, Any] = {"hash_list": hash_list}
        if comment:
            request_data["comment"] = comment
        if incident_id:
            request_data['incident_id'] = incident_id

        self._headers['content-type'] = 'application/json'
        reply = self._http_request(
            method='POST',
            url_suffix='/hash_exceptions/blocklist/remove/',
            json_data={'request_data': request_data},
            timeout=self.timeout
        )
        return reply.get('reply')

    def allowlist_files(self, hash_list, comment=None, incident_id=None, detailed_response=False):
        request_data: Dict[str, Any] = {"hash_list": hash_list}
        if comment:
            request_data["comment"] = comment
        if incident_id:
            request_data['incident_id'] = incident_id
        if detailed_response:
            request_data['detailed_response'] = detailed_response

        self._headers['content-type'] = 'application/json'
        reply = self._http_request(
            method='POST',
            url_suffix='/hash_exceptions/allowlist/',
            json_data={'request_data': request_data},
            ok_codes=(201, 200),
            timeout=self.timeout
        )
        return reply.get('reply')

    def remove_allowlist_files(self, hash_list, comment=None, incident_id=None):
        request_data: Dict[str, Any] = {"hash_list": hash_list}
        if comment:
            request_data["comment"] = comment
        if incident_id:
            request_data['incident_id'] = incident_id

        self._headers['content-type'] = 'application/json'
        reply = self._http_request(
            method='POST',
            url_suffix='/hash_exceptions/allowlist/remove/',
            json_data={'request_data': request_data},
            timeout=self.timeout
        )
        return reply.get('reply')

    def quarantine_files(self, endpoint_id_list, file_path, file_hash, incident_id):
        request_data: Dict[str, Any] = {}
        filters = []
        if endpoint_id_list:
            filters.append({
                'field': 'endpoint_id_list',
                'operator': 'in',
                'value': endpoint_id_list
            })

        if filters:
            request_data['filters'] = filters

        request_data['file_path'] = file_path
        request_data['file_hash'] = file_hash
        if incident_id:
            request_data['incident_id'] = incident_id

        self._headers['content-type'] = 'application/json'
        reply = self._http_request(
            method='POST',
            url_suffix='/endpoints/quarantine/',
            json_data={'request_data': request_data},
            ok_codes=(200, 201),
            timeout=self.timeout
        )

        return reply.get('reply')

    def restore_file(self, file_hash, endpoint_id=None, incident_id=None):
        request_data: Dict[str, Any] = {'file_hash': file_hash}
        if incident_id:
            request_data['incident_id'] = incident_id
        if endpoint_id:
            request_data['endpoint_id'] = endpoint_id

        self._headers['content-type'] = 'application/json'
        reply = self._http_request(
            method='POST',
            url_suffix='/endpoints/restore/',
            json_data={'request_data': request_data},
            ok_codes=(200, 201),
            timeout=self.timeout
        )
        return reply.get('reply')

    def endpoint_scan(self, url_suffix, endpoint_id_list=None, dist_name=None, gte_first_seen=None, gte_last_seen=None,
                      lte_first_seen=None,
                      lte_last_seen=None, ip_list=None, group_name=None, platform=None, alias=None, isolate=None,
                      hostname: list = None, incident_id=None):
        request_data: Dict[str, Any] = {}
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

        if alias:
            filters.append({
                'field': 'alias',
                'operator': 'in',
                'value': alias
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

        if gte_first_seen:
            filters.append({
                'field': 'first_seen',
                'operator': 'gte',
                'value': gte_first_seen
            })

        if lte_first_seen:
            filters.append({
                'field': 'first_seen',
                'operator': 'lte',
                'value': lte_first_seen
            })

        if gte_last_seen:
            filters.append({
                'field': 'last_seen',
                'operator': 'gte',
                'value': gte_last_seen
            })

        if lte_last_seen:
            filters.append({
                'field': 'last_seen',
                'operator': 'lte',
                'value': lte_last_seen
            })

        if filters:
            request_data['filters'] = filters
        else:
            request_data['filters'] = 'all'
        if incident_id:
            request_data['incident_id'] = incident_id

        self._headers['content-type'] = 'application/json'
        reply = self._http_request(
            method='POST',
            url_suffix=url_suffix,
            json_data={'request_data': request_data},
            ok_codes=(200, 201),
            timeout=self.timeout
        )
        return reply.get('reply')

    def get_quarantine_status(self, file_path, file_hash, endpoint_id):
        request_data: Dict[str, Any] = {'files': [{
            'endpoint_id': endpoint_id,
            'file_path': file_path,
            'file_hash': file_hash
        }]}
        self._headers['content-type'] = 'application/json'
        reply = self._http_request(
            method='POST',
            url_suffix='/quarantine/status/',
            json_data={'request_data': request_data},
            timeout=self.timeout
        )

        reply_content = reply.get('reply')
        if isinstance(reply_content, list):
            return reply_content[0]
        else:
            raise TypeError(f'got unexpected response from api: {reply_content}\n')

    def delete_endpoints(self, endpoint_ids: list):
        request_data: Dict[str, Any] = {
            'filters': [
                {
                    'field': 'endpoint_id_list',
                    'operator': 'in',
                    'value': endpoint_ids
                }
            ]
        }

        self._http_request(
            method='POST',
            url_suffix='/endpoints/delete/',
            json_data={'request_data': request_data},
            timeout=self.timeout
        )

    def get_policy(self, endpoint_id) -> Dict[str, Any]:
        request_data: Dict[str, Any] = {
            'endpoint_id': endpoint_id
        }

        reply = self._http_request(
            method='POST',
            url_suffix='/endpoints/get_policy/',
            json_data={'request_data': request_data},
            timeout=self.timeout
        )

        return reply.get('reply')

    def report_incorrect_wildfire(self, file_hash: str, new_verdict: int, reason: str, email: str) -> Dict[str, Any]:
        request_data: Dict[str, Any] = {
            "hash": file_hash,
            "new_verdict": new_verdict,
            "reason": reason,
            "email": email,
        }

        reply = demisto._apiCall(name="wfReportIncorrectVerdict",
                                 params=None,
                                 data=json.dumps(request_data))

        return reply

    def get_original_alerts(self, alert_id_list):
        res = self._http_request(
            method='POST',
            url_suffix='/alerts/get_original_alerts/',
            json_data={
                'request_data': {
                    'alert_id_list': alert_id_list,
                }
            },
        )
        return res.get('reply', {})

    def get_endpoint_device_control_violations(self, endpoint_ids: list, type_of_violation, timestamp_gte: int,
                                               timestamp_lte: int,
                                               ip_list: list, vendor: list, vendor_id: list, product: list,
                                               product_id: list,
                                               serial: list,
                                               hostname: list, violation_ids: list, username: list) \
            -> Dict[str, Any]:
        arg_list = {'type': type_of_violation,
                    'endpoint_id_list': endpoint_ids,
                    'ip_list': ip_list,
                    'vendor': vendor,
                    'vendor_id': vendor_id,
                    'product': product,
                    'product_id': product_id,
                    'serial': serial,
                    'hostname': hostname,
                    'violation_id_list': violation_ids,
                    'username': username
                    }

        filters: list = [{
            'field': arg_key,
            'operator': 'in',
            'value': arg_val
        } for arg_key, arg_val in arg_list.items() if arg_val and arg_val[0]]

        if timestamp_lte:
            filters.append({
                'field': 'timestamp',
                'operator': 'lte',
                'value': timestamp_lte
            })
        if timestamp_gte:
            filters.append({
                'field': 'timestamp',
                'operator': 'gte',
                'value': timestamp_gte})

        request_data: Dict[str, Any] = {
            'filters': filters
        }

        reply = self._http_request(
            method='POST',
            url_suffix='/device_control/get_violations/',
            json_data={'request_data': request_data},
            timeout=self.timeout
        )

        return reply.get('reply')

    def generate_files_dict_with_specific_os(self, windows: list, linux: list, macos: list) -> Dict[str, list]:
        if not windows and not linux and not macos:
            raise ValueError('You should enter at least one path.')

        files = {}
        if windows:
            files['windows'] = windows
        if linux:
            files['linux'] = linux
        if macos:
            files['macos'] = macos

        return files

    def retrieve_file(self, endpoint_id_list: list, windows: list, linux: list, macos: list, file_path_list: list,
                      incident_id: Optional[int]) -> Dict[str, Any]:
        # there are 2 options, either the paths are given with separation to a specific os or without
        # it using generic_file_path
        if file_path_list:
            files = self.generate_files_dict(
                endpoint_id_list=endpoint_id_list,
                file_path_list=file_path_list
            )
        else:
            files = self.generate_files_dict_with_specific_os(windows=windows, linux=linux, macos=macos)

        request_data: Dict[str, Any] = {
            'filters': [
                {
                    'field': 'endpoint_id_list',
                    'operator': 'in',
                    'value': endpoint_id_list
                }
            ],
            'files': files,
        }
        if incident_id:
            request_data['incident_id'] = incident_id

        reply = self._http_request(
            method='POST',
            url_suffix='/endpoints/file_retrieval/',
            json_data={'request_data': request_data},
            timeout=self.timeout
        )
        return reply.get('reply')

    def generate_files_dict(self, endpoint_id_list: list, file_path_list: list) -> Dict[str, Any]:
        files: dict = {"windows": [], "linux": [], "macos": []}

        if len(endpoint_id_list) != len(file_path_list):
            raise ValueError("The endpoint_ids list must be in the same length as the generic_file_path")

        for endpoint_id, file_path in zip(endpoint_id_list, file_path_list):
            endpoints = self.get_endpoints(endpoint_id_list=[endpoint_id])

            if len(endpoints) == 0 or not isinstance(endpoints, list):
                raise ValueError(f'Error: Endpoint {endpoint_id} was not found')

            endpoint = endpoints[0]
            endpoint_os_type = endpoint.get('os_type')

            if 'windows' in endpoint_os_type.lower():
                files['windows'].append(file_path)
            elif 'linux' in endpoint_os_type.lower():
                files['linux'].append(file_path)
            elif 'macos' in endpoint_os_type.lower():
                files['macos'].append(file_path)

        # remove keys with no value
        files = {k: v for k, v in files.items() if v}

        return files

    def retrieve_file_details(self, action_id: int) -> Dict[str, Any]:
        request_data: Dict[str, Any] = {
            'group_action_id': action_id
        }

        reply = self._http_request(
            method='POST',
            url_suffix='/actions/file_retrieval_details/',
            json_data={'request_data': request_data},
            timeout=self.timeout
        )

        return reply.get('reply').get('data')

    def get_scripts(self, name: list, description: list, created_by: list, windows_supported,
                    linux_supported, macos_supported, is_high_risk) -> Dict[str, Any]:

        arg_list = {'name': name,
                    'description': description,
                    'created_by': created_by,
                    'windows_supported': windows_supported,
                    'linux_supported': linux_supported,
                    'macos_supported': macos_supported,
                    'is_high_risk': is_high_risk
                    }

        filters: list = [{
            'field': arg_key,
            'operator': 'in',
            'value': arg_val
        } for arg_key, arg_val in arg_list.items() if arg_val and arg_val[0]]

        request_data: Dict[str, Any] = {
            'filters': filters
        }

        reply = self._http_request(
            method='POST',
            url_suffix='/scripts/get_scripts/',
            json_data={'request_data': request_data},
            timeout=self.timeout
        )

        return reply.get('reply')

    def get_script_metadata(self, script_uid) -> Dict[str, Any]:
        request_data: Dict[str, Any] = {
            'script_uid': script_uid
        }

        reply = self._http_request(
            method='POST',
            url_suffix='/scripts/get_script_metadata/',
            json_data={'request_data': request_data},
            timeout=self.timeout
        )

        return reply.get('reply')

    def get_script_code(self, script_uid) -> Dict[str, Any]:
        request_data: Dict[str, Any] = {
            'script_uid': script_uid
        }

        reply = self._http_request(
            method='POST',
            url_suffix='/scripts/get_script_code/',
            json_data={'request_data': request_data},
            timeout=self.timeout
        )

        return reply.get('reply')

    @logger
    def run_script(self,
                   script_uid: str, endpoint_ids: list, parameters: Dict[str, Any], timeout: int, incident_id: Optional[int],
                   ) -> Dict[str, Any]:
        filters: list = [{
            'field': 'endpoint_id_list',
            'operator': 'in',
            'value': endpoint_ids
        }]
        request_data: Dict[str, Any] = {'script_uid': script_uid, 'timeout': timeout, 'filters': filters,
                                        'parameters_values': parameters}
        if incident_id:
            request_data['incident_id'] = incident_id

        return self._http_request(
            method='POST',
            url_suffix='/scripts/run_script/',
            json_data={'request_data': request_data},
            timeout=self.timeout
        )

    @logger
    def run_snippet_code_script(self, snippet_code: str, endpoint_ids: list,
                                incident_id: Optional[int] = None) -> Dict[str, Any]:
        request_data: Dict[str, Any] = {
            'filters': [{
                'field': 'endpoint_id_list',
                'operator': 'in',
                'value': endpoint_ids
            }],
            'snippet_code': snippet_code,
        }

        if incident_id:
            request_data['incident_id'] = incident_id

        return self._http_request(
            method='POST',
            url_suffix='/scripts/run_snippet_code_script',
            json_data={
                'request_data': request_data
            },
            timeout=self.timeout,
        )

    @logger
    def get_script_execution_status(self, action_id: str) -> Dict[str, Any]:
        request_data: Dict[str, Any] = {
            'action_id': action_id
        }

        return self._http_request(
            method='POST',
            url_suffix='/scripts/get_script_execution_status/',
            json_data={'request_data': request_data},
            timeout=self.timeout
        )

    @logger
    def get_script_execution_results(self, action_id: str) -> Dict[str, Any]:
        return self._http_request(
            method='POST',
            url_suffix='/scripts/get_script_execution_results',
            json_data={
                'request_data': {
                    'action_id': action_id
                }
            },
            timeout=self.timeout,
        )

    @logger
    def get_script_execution_result_files(self, action_id: str, endpoint_id: str) -> Dict[str, Any]:
        response = self._http_request(
            method='POST',
            url_suffix='/scripts/get_script_execution_results_files',
            json_data={
                'request_data': {
                    'action_id': action_id,
                    'endpoint_id': endpoint_id,
                }
            },
            timeout=self.timeout,
        )
        link = response.get('reply', {}).get('DATA')
        return self._http_request(
            method='GET',
            full_url=link,
            resp_type='response',
        )

    def action_status_get(self, action_id) -> Dict[str, Any]:
        request_data: Dict[str, Any] = {
            'group_action_id': action_id,
        }

        reply = self._http_request(
            method='POST',
            url_suffix='/actions/get_action_status/',
            json_data={'request_data': request_data},
            timeout=self.timeout
        )
        return reply.get('reply').get('data')

    def get_file(self, file_link):
        reply = self._http_request(
            method='GET',
            full_url=file_link,
            timeout=self.timeout,
            resp_type='content'
        )
        return reply

    def save_modified_incidents_to_integration_context(self):
        last_modified_incidents = self.get_incidents(limit=100, sort_by_modification_time='desc')
        modified_incidents_context = {}
        for incident in last_modified_incidents:
            incident_id = incident.get('incident_id')
            modified_incidents_context[incident_id] = incident.get('modification_time')

        set_integration_context({'modified_incidents': modified_incidents_context})

    def get_endpoints_by_status(self, status, last_seen_gte=None, last_seen_lte=None):
        filters = []

        filters.append({
            'field': 'endpoint_status',
            'operator': 'IN',
            'value': [status]
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

        reply = self._http_request(
            method='POST',
            url_suffix='/endpoints/get_endpoint/',
            json_data={'request_data': {'filters': filters}},
            timeout=self.timeout
        )

        endpoints_count = reply.get('reply').get('total_count', 0)
        return endpoints_count, reply

    def get_original_alerts(self, alert_id_list):
        res = self._http_request(
            method='POST',
            url_suffix='/alerts/get_original_alerts/',
            json_data={
                'request_data': {
                    'alert_id_list': alert_id_list,
                }
            },
        )
        return res.get('reply', {})


    def add_exclusion(self, indicator, name, status="ENABLED", comment=None):
        request_data: Dict[str, Any] = {
            'indicator': indicator,
            'status': status,
            'name': name
        }

        res = self._http_request(
            method='POST',
            url_suffix='/alerts_exclusion/add/',
            json_data={'request_data': request_data},
            timeout=self.timeout
        )
        return res.get("reply")

    def delete_exclusion(self, alert_exclusion_id: int):
        request_data: Dict[str, Any] = {
            'alert_exclusion_id': alert_exclusion_id,
        }

        res = self._http_request(
            method='POST',
            url_suffix='/alerts_exclusion/delete/',
            json_data={'request_data': request_data},
            timeout=self.timeout
        )
        return res.get("reply")

    def get_exclusion(self, limit, tenant_id=None, filter=None):
        request_data: Dict[str, Any] = {}
        if tenant_id:
            request_data['tenant_id'] = tenant_id
        if filter:
            request_data['filter_data'] = filter
        res = self._http_request(
            method='POST',
            url_suffix='/alerts_exclusion/',
            json_data={'request_data': request_data},
            timeout=self.timeout
        )
        reply = res.get("reply")
        return reply[:limit]
