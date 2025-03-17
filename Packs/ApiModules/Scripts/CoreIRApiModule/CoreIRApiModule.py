import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import urllib3
import copy
import re
from operator import itemgetter
import json
from typing import Tuple, Callable
import base64

# Disable insecure warnings
urllib3.disable_warnings()
TIME_FORMAT = "%Y-%m-%dT%H:%M:%S"

XSOAR_RESOLVED_STATUS_TO_XDR = {
    'Other': 'resolved_other',
    'Duplicate': 'resolved_duplicate',
    'False Positive': 'resolved_false_positive',
    'Resolved': 'resolved_true_positive',
    'Security Testing': 'resolved_security_testing',
}

XDR_RESOLVED_STATUS_TO_XSOAR = {
    'resolved_known_issue': 'Other',
    'resolved_duplicate_incident': 'Duplicate',
    'resolved_duplicate': 'Duplicate',
    'resolved_false_positive': 'False Positive',
    'resolved_true_positive': 'Resolved',
    'resolved_security_testing': 'Security Testing',
    'resolved_other': 'Other',
    'resolved_auto': 'Resolved',
    'resolved_auto_resolve': 'Resolved'
}

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

RBAC_VALIDATIONS_VERSION = '8.6.0'
RBAC_VALIDATIONS_BUILD_NUMBER = '992980'
FORWARD_USER_RUN_RBAC = is_xsiam() and is_demisto_version_ge(version=RBAC_VALIDATIONS_VERSION,
                                                             build_number=RBAC_VALIDATIONS_BUILD_NUMBER) and not is_using_engine()

ALLOW_BIN_CONTENT_RESPONSE_BUILD_NUM = '1230614'
ALLOW_BIN_CONTENT_RESPONSE_SERVER_VERSION = '8.7.0'
ALLOW_RESPONSE_AS_BINARY = is_demisto_version_ge(version=ALLOW_BIN_CONTENT_RESPONSE_SERVER_VERSION,
                                                 build_number=ALLOW_BIN_CONTENT_RESPONSE_BUILD_NUM)


class CoreClient(BaseClient):

    def __init__(self, base_url: str, headers: dict, timeout: int = 120, proxy: bool = False, verify: bool = False):
        super().__init__(base_url=base_url, headers=headers, proxy=proxy, verify=verify)
        self.timeout = timeout
        # For Xpanse tenants requiring direct use of the base client HTTP request instead of the _apiCall,

    def _http_request(self, method, url_suffix='', full_url=None, headers=None, json_data=None,  # type: ignore[override]
                      params=None, data=None, timeout=None, raise_on_status=False, ok_codes=None,
                      error_handler=None, with_metrics=False, resp_type='json'):
        '''
        """A wrapper for requests lib to send our requests and handle requests and responses better.

            :type method: ``str``
            :param method: The HTTP method, for example: GET, POST, and so on.


            :type url_suffix: ``str``
            :param url_suffix: The API endpoint.


            :type full_url: ``str``
            :param full_url:
                Bypasses the use of self._base_url + url_suffix. This is useful if you need to
                make a request to an address outside of the scope of the integration
                API.


            :type headers: ``dict``
            :param headers: Headers to send in the request. If None, will use self._headers.


            :type params: ``dict``
            :param params: URL parameters to specify the query.


            :type data: ``dict``
            :param data: The data to send in a 'POST' request.


            :type raise_on_status ``bool``
                :param raise_on_status: Similar meaning to ``raise_on_redirect``:
                    whether we should raise an exception, or return a response,
                    if status falls in ``status_forcelist`` range and retries have
                    been exhausted.


            :type timeout: ``float`` or ``tuple``
            :param timeout:
                The amount of time (in seconds) that a request will wait for a client to
                establish a connection to a remote machine before a timeout occurs.
                can be only float (Connection Timeout) or a tuple (Connection Timeout, Read Timeout).
        '''
        if not FORWARD_USER_RUN_RBAC:
            return BaseClient._http_request(self,  # we use the standard base_client http_request without overriding it
                                            method=method,
                                            url_suffix=url_suffix,
                                            full_url=full_url,
                                            headers=headers,
                                            json_data=json_data, params=params, data=data,
                                            timeout=timeout,
                                            raise_on_status=raise_on_status,
                                            ok_codes=ok_codes,
                                            error_handler=error_handler,
                                            with_metrics=with_metrics,
                                            resp_type=resp_type)
        headers = headers if headers else self._headers
        data = json.dumps(json_data) if json_data else data
        address = full_url if full_url else urljoin(self._base_url, url_suffix)
        response_data_type = "bin" if resp_type == 'content' and ALLOW_RESPONSE_AS_BINARY else None
        if resp_type == 'content' and not ALLOW_RESPONSE_AS_BINARY:
            allowed_version = f'{ALLOW_BIN_CONTENT_RESPONSE_SERVER_VERSION}-{ALLOW_BIN_CONTENT_RESPONSE_BUILD_NUM}'
            raise DemistoException('getting binary data from server is allowed from '
                                   f'version: {allowed_version} and above')
        params = assign_params(
            method=method,
            path=address,
            data=data,
            headers=headers,
            timeout=timeout,
            response_data_type=response_data_type
        )
        response = demisto._apiCall(**params)
        if ok_codes and response.get('status') not in ok_codes:
            self._handle_error(error_handler, response, with_metrics)
        try:
            decoder = base64.b64decode if response_data_type == "bin" else json.loads
            demisto.debug(f'{response_data_type=}, {decoder.__name__=}')
            return decoder(response['data'])  # type: ignore[operator]
        except json.JSONDecodeError:
            demisto.debug(f"Converting data to json was failed. Return it as is. The data's type is {type(response['data'])}")
            return response['data']

    def get_incidents(self, incident_id_list=None, lte_modification_time=None, gte_modification_time=None,
                      lte_creation_time=None, gte_creation_time=None, status=None, starred=None,
                      starred_incidents_fetch_window=None, sort_by_modification_time=None, sort_by_creation_time=None,
                      page_number=0, limit=100, gte_creation_time_milliseconds=0,
                      gte_modification_time_milliseconds=None, lte_modification_time_milliseconds=None):
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
        :param gte_modification_time_milliseconds: greater than modification time in milliseconds
        :param lte_modification_time_milliseconds: greater than modification time in milliseconds
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

        if starred and starred_incidents_fetch_window and demisto.command() == 'fetch-incidents':
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

            if len(filters) > 0:
                request_data['filters'] = filters
            incidents = self.handle_fetch_starred_incidents(limit, page_number, request_data)
            return incidents

        if starred is not None and demisto.command() != 'fetch-incidents':
            filters.append({
                'field': 'starred',
                'operator': 'eq',
                'value': starred
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
        elif starred and starred_incidents_fetch_window and demisto.command() != 'fetch-incidents':
            # backwards compatibility of starred_incidents_fetch_window
            filters.append({
                'field': 'creation_time',
                'operator': 'gte',
                'value': starred_incidents_fetch_window
            })

        if lte_modification_time and lte_modification_time_milliseconds:
            raise ValueError('Either lte_modification_time or '
                             'lte_modification_time_milliseconds should be provided . Can\'t provide both')

        if gte_modification_time and gte_modification_time_milliseconds:
            raise ValueError('Either gte_modification_time or '
                             'gte_modification_time_milliseconds should be provide. Can\'t provide both')

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

        if gte_creation_time_milliseconds:
            filters.append({
                'field': 'creation_time',
                'operator': 'gte',
                'value': date_to_timestamp(gte_creation_time_milliseconds)
            })

        if gte_modification_time_milliseconds:
            filters.append({
                'field': 'modification_time',
                'operator': 'gte',
                'value': date_to_timestamp(gte_modification_time_milliseconds)
            })

        if lte_modification_time_milliseconds:
            filters.append({
                'field': 'modification_time',
                'operator': 'lte',
                'value': date_to_timestamp(lte_modification_time_milliseconds)
            })

        if len(filters) > 0:
            request_data['filters'] = filters
        res = self._http_request(
            method='POST',
            url_suffix='/incidents/get_incidents/',
            json_data={'request_data': request_data},
            headers=self._headers,
            timeout=self.timeout
        )
        incidents = res.get('reply', {}).get('incidents', [])

        return incidents

    def handle_fetch_starred_incidents(self, limit: int, page_number: int, request_data: Dict[Any, Any]) -> List[Any]:
        """Called from get_incidents if the command is fetch-incidents. Implement in child classes."""
        return []

    def get_endpoints(self,
                      endpoint_id_list=None,
                      dist_name=None,
                      ip_list=None,
                      public_ip_list=None,
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
                      username=None
                      ):

        search_from = page_number * limit
        search_to = search_from + limit

        request_data = {
            'search_from': search_from,
            'search_to': search_to,
        }

        filters = create_request_filters(
            status=status, username=username, endpoint_id_list=endpoint_id_list, dist_name=dist_name,
            ip_list=ip_list, group_name=group_name, platform=platform, alias_name=alias_name, isolate=isolate,
            hostname=hostname, first_seen_gte=first_seen_gte, first_seen_lte=first_seen_lte,
            last_seen_gte=last_seen_gte, last_seen_lte=last_seen_lte, public_ip_list=public_ip_list
        )

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

        response = self._http_request(
            method='POST',
            url_suffix='/endpoints/get_endpoint/',
            json_data={'request_data': request_data},
            timeout=self.timeout
        )
        endpoints = response.get('reply', {}).get('endpoints', [])
        return endpoints

    def set_endpoints_alias(self, filters: list[dict[str, str]], new_alias_name: str | None) -> dict:  # pragma: no cover
        """
        This func is used to set the alias name of an endpoint.

        args:
            filters: list of filters to get the endpoints
            new_alias_name: the new alias name to set

        returns: dict of the response(True if success else error message)
        """

        request_data = {'filters': filters, 'alias': new_alias_name}

        return self._http_request(
            method='POST',
            url_suffix='/endpoints/update_agent_name/',
            json_data={'request_data': request_data},
            timeout=self.timeout,
        )

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

    def insert_alerts(self, alerts):
        self._http_request(
            method='POST',
            url_suffix='/alerts/insert_parsed_alerts/',
            json_data={
                'request_data': {
                    'alerts': alerts
                }
            },
            timeout=self.timeout
        )

    def insert_cef_alerts(self, alerts):
        self._http_request(
            method='POST',
            url_suffix='/alerts/insert_cef_alerts/',
            json_data={
                'request_data': {
                    'alerts': alerts
                }
            },
            timeout=self.timeout
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
            ok_codes=(200, 201, 500),
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
            ok_codes=(200, 201, 500),
            timeout=self.timeout
        )
        res = reply.get('reply')
        if isinstance(res, dict) and res.get('err_code') == 500:
            raise DemistoException(f"{res.get('err_msg')}\nThe requested hash might not be in the blocklist.")
        return res

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

    def get_alerts_by_filter_data(self, request_data: dict):
        res = self._http_request(
            method='POST',
            url_suffix='/alerts/get_alerts_by_filter_data/',
            json_data={
                'request_data': request_data
            },
        )
        return res.get('reply', {})

    def get_endpoint_device_control_violations(self, endpoint_ids: list, type_of_violation, timestamp_gte: int,
                                               timestamp_lte: int,
                                               ip_list: list, vendor: list, vendor_id: list, product: list,
                                               product_id: list,
                                               serial: list,
                                               hostname: list, violation_ids: list, username: list) -> Dict[str, Any]:
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
        demisto.debug(f"retrieve_file = {reply}")

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
            elif 'mac' in endpoint_os_type.lower():
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
        demisto.debug(f"retrieve_file_details = {reply}")

        return reply.get('reply').get('data')

    @logger
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
        demisto.debug(f"From the previous API call, this link was returned {link=}")
        # If the link is None, the API call will result in a 'Connection Timeout Error', so we raise an exception
        if not link:
            raise DemistoException(f'Failed getting response files for {action_id=}, {endpoint_id=}')
        return self._http_request(
            method='GET',
            url_suffix=re.findall('download.*', link)[0],
            resp_type='response',
        )

    def action_status_get(self, action_id) -> Dict[str, Dict[str, Any]]:
        request_data: Dict[str, Any] = {
            'group_action_id': action_id,
        }

        reply = self._http_request(
            method='POST',
            url_suffix='/actions/get_action_status/',
            json_data={'request_data': request_data},
            timeout=self.timeout
        )
        demisto.debug(f"action_status_get = {reply}")

        return reply.get('reply')

    @logger
    def get_file(self, file_link):
        reply = self._http_request(
            method='GET',
            full_url=file_link,
            timeout=self.timeout,
            resp_type='content'
        )
        return reply

    def get_file_by_url_suffix(self, url_suffix):
        reply = self._http_request(
            method='GET',
            url_suffix=url_suffix,
            timeout=self.timeout,
            resp_type='content'
        )
        return reply

    @logger
    def get_endpoints_by_status(self, status, last_seen_gte=None, last_seen_lte=None):
        filters = []

        if not isinstance(status, list):
            status = [status]

        filters.append({
            'field': 'endpoint_status',
            'operator': 'IN',
            'value': status
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

    def add_tag_endpoint(self, endpoint_ids, tag, args):
        """
        Add tag to an endpoint
        """
        return self.call_tag_endpoint(endpoint_ids=endpoint_ids, tag=tag, args=args, url_suffix='/tags/agents/assign/')

    def remove_tag_endpoint(self, endpoint_ids, tag, args):
        """
        Remove tag from an endpoint.
        """
        return self.call_tag_endpoint(endpoint_ids=endpoint_ids, tag=tag, args=args, url_suffix='/tags/agents/remove/')

    def call_tag_endpoint(self, endpoint_ids, tag, args, url_suffix):
        """
        Add or remove a tag from an endpoint.
        """
        filters = args_to_request_filters(args)

        body_request = {
            'context': {
                'lcaas_id': endpoint_ids,
            },
            'request_data': {
                'filters': filters,
                'tag': tag
            },
        }

        return self._http_request(
            method='POST',
            url_suffix=url_suffix,
            json_data=body_request,
            timeout=self.timeout
        )

    def list_users(self) -> dict[str, list[dict[str, Any]]]:
        return self._http_request(
            method='POST',
            url_suffix='/rbac/get_users/',
            json_data={"request_data": {}},
        )

    def risk_score_user_or_host(self, user_or_host_id: str) -> dict[str, dict[str, Any]]:
        return self._http_request(
            method='POST',
            url_suffix='/get_risk_score/',
            json_data={"request_data": {"id": user_or_host_id}},
        )

    def list_risky_users(self) -> dict[str, list[dict[str, Any]]]:
        return self._http_request(
            method='POST',
            url_suffix='/get_risky_users/',
        )

    def list_risky_hosts(self) -> dict[str, list[dict[str, Any]]]:
        return self._http_request(
            method='POST',
            url_suffix='/get_risky_hosts/',
        )

    def list_user_groups(self, group_names: list[str]) -> dict[str, list[dict[str, Any]]]:
        return self._http_request(
            method='POST',
            url_suffix='/rbac/get_user_group/',
            json_data={"request_data": {"group_names": group_names}},
        )

    def list_roles(self, role_names: list[str]) -> dict[str, list[list[dict[str, Any]]]]:
        return self._http_request(
            method='POST',
            url_suffix='/rbac/get_roles/',
            json_data={"request_data": {"role_names": role_names}},
        )

    def set_user_role(self, user_emails: list[str], role_name: str) -> dict[str, dict[str, str]]:
        return self._http_request(
            method='POST',
            url_suffix='/rbac/set_user_role/',
            json_data={"request_data": {
                "user_emails": user_emails,
                "role_name": role_name
            }},
        )

    def remove_user_role(self, user_emails: list[str]) -> dict[str, dict[str, str]]:
        return self._http_request(
            method='POST',
            url_suffix='/rbac/set_user_role/',
            json_data={"request_data": {
                "user_emails": user_emails,
                "role_name": ""
            }},
        )

    def terminate_on_agent(self,
                           url_suffix_endpoint: str,
                           id_key: str,
                           id_value: str,
                           agent_id: str,
                           process_name: Optional[str],
                           incident_id: Optional[str]) -> dict[str, dict[str, str]]:
        """
            Terminate a specific process or a the causality on an agent.

            :type url_suffix_endpoint: ``str``
            :param agent_id: The endpoint of the command(terminate_causality or terminate_process).

            :type agent_id: ``str``
            :param agent_id: The ID of the agent.

            :type id_key: ``str``
            :param id_key: The key name ID- causality_id or process_id.

            :type id_key: ``str``
            :param id_key: The ID data- causality_id or process_id.

            :type process_name: ``Optional[str]``
            :param process_name: The name of the process. Optional.

            :type incident_id: ``Optional[str]``
            :param incident_id: The ID of the incident. Optional.

            :return: The response from the API.
            :rtype: ``dict[str, dict[str, str]]``
        """
        request_data: Dict[str, Any] = {
            "agent_id": agent_id,
            id_key: id_value,
        }
        if process_name:
            request_data["process_name"] = process_name
        if incident_id:
            request_data["incident_id"] = incident_id
        response = self._http_request(
            method='POST',
            url_suffix=f'/endpoints/{url_suffix_endpoint}/',
            json_data={"request_data": request_data},
        )
        return response.get('reply')


class AlertFilterArg:
    def __init__(self, search_field: str, search_type: Optional[str], arg_type: str, option_mapper: dict = None):
        self.search_field = search_field
        self.search_type = search_type
        self.arg_type = arg_type
        self.option_mapper = option_mapper


def catch_and_exit_gracefully(e):
    """

    Args:
        e: DemistoException caught while running a command.

    Returns:
        CommandResult if the error is internal XDR error, else, the exception.
    """
    if e.res.status_code == 500 and 'no endpoint was found for creating the requested action' in str(e).lower():
        return CommandResults(readable_output="The operation executed is not supported on the given machine.")
    else:
        raise e


def init_filter_args_options():
    array = 'array'
    dropdown = 'dropdown'
    time_frame = 'time_frame'

    return {
        'alert_id': AlertFilterArg('internal_id', 'EQ', array),
        'severity': AlertFilterArg('severity', 'EQ', dropdown, {
            'low': 'SEV_020_LOW',
            'medium': 'SEV_030_MEDIUM',
            'high': 'SEV_040_HIGH'
        }),
        'starred': AlertFilterArg('starred', 'EQ', dropdown, {
            'true': True,
            'False': False,
        }),
        'Identity_type': AlertFilterArg('Identity_type', 'EQ', dropdown),
        'alert_action_status': AlertFilterArg('alert_action_status', 'EQ', dropdown, ALERT_STATUS_TYPES_REVERSE_DICT),
        'agent_id': AlertFilterArg('agent_id', 'EQ', array),
        'action_external_hostname': AlertFilterArg('action_external_hostname', 'CONTAINS', array),
        'rule_id': AlertFilterArg('matching_service_rule_id', 'EQ', array),
        'rule_name': AlertFilterArg('fw_rule', 'EQ', array),
        'alert_name': AlertFilterArg('alert_name', 'CONTAINS', array),
        'alert_source': AlertFilterArg('alert_source', 'CONTAINS', array),
        'time_frame': AlertFilterArg('source_insert_ts', None, time_frame),
        'user_name': AlertFilterArg('actor_effective_username', 'CONTAINS', array),
        'actor_process_image_name': AlertFilterArg('actor_process_image_name', 'CONTAINS', array),
        'causality_actor_process_image_command_line': AlertFilterArg('causality_actor_process_command_line', 'EQ',
                                                                     array),
        'actor_process_image_command_line': AlertFilterArg('actor_process_command_line', 'EQ', array),
        'action_process_image_command_line': AlertFilterArg('action_process_image_command_line', 'EQ', array),
        'actor_process_image_sha256': AlertFilterArg('actor_process_image_sha256', 'EQ', array),
        'causality_actor_process_image_sha256': AlertFilterArg('causality_actor_process_image_sha256', 'EQ', array),
        'action_process_image_sha256': AlertFilterArg('action_process_image_sha256', 'EQ', array),
        'action_file_image_sha256': AlertFilterArg('action_file_sha256', 'EQ', array),
        'action_registry_name': AlertFilterArg('action_registry_key_name', 'EQ', array),
        'action_registry_key_data': AlertFilterArg('action_registry_data', 'CONTAINS', array),
        'host_ip': AlertFilterArg('agent_ip_addresses', 'IPLIST_MATCH', array),
        'action_local_ip': AlertFilterArg('action_local_ip', 'IP_MATCH', array),
        'action_remote_ip': AlertFilterArg('action_remote_ip', 'IP_MATCH', array),
        'action_local_port': AlertFilterArg('action_local_port', 'EQ', array),
        'action_remote_port': AlertFilterArg('action_remote_port', 'EQ', array),
        'dst_action_external_hostname': AlertFilterArg('dst_action_external_hostname', 'CONTAINS', array),
        'mitre_technique_id_and_name': AlertFilterArg('mitre_technique_id_and_name', 'CONTAINS', array),
    }


def run_polling_command(client: CoreClient,
                        args: dict,
                        cmd: str,
                        command_function: Callable,
                        command_decision_field: str,
                        results_function: Callable,
                        polling_field: str,
                        polling_value: List,
                        stop_polling: bool = False,
                        values_raise_error: List = []) -> CommandResults:
    """
    Arguments:
    args: args
    cmd: the scheduled command's name (as appears in the yml file) to run in the following polling.
    command_function: the pythonic function that executes the command.
    command_decision_field: the field that is retrieved from the command_function's response that indicates
    the command_function status.
    results_function: the pythonic result function which we want to poll on.
    polling_field: the field that is retrieved from the results_function's response and indicates the polling status.
    polling_value: list of values of the polling_field we want to check. The list can contain values to stop or
    continue polling on, not both.
    stop_polling: True - polling_value stops the polling. False - polling_value does not stop the polling.
    values_raise_error: list of polling values that require raising an error.

    Return:
    command_results(CommandResults)
    """

    ScheduledCommand.raise_error_if_not_supported()
    interval_in_secs = int(args.get('interval_in_seconds', 60))
    timeout_in_seconds = int(args.get('timeout_in_seconds', 600))
    if command_decision_field not in args:
        # create new command run
        command_results = command_function(client, args)
        outputs = command_results.raw_response
        if outputs and not isinstance(outputs, list):
            outputs = [outputs]
        command_decision_values = [o.get(command_decision_field) for o in outputs] if outputs else []  # type: ignore
        if outputs and command_decision_values:
            polling_args = {
                command_decision_field: command_decision_values,
                'interval_in_seconds': interval_in_secs,
                **args
            }
            scheduled_command = ScheduledCommand(
                command=cmd,
                next_run_in_seconds=interval_in_secs,
                args=polling_args,
                timeout_in_seconds=timeout_in_seconds)
            if isinstance(command_results, list):
                command_results = command_results[0]
            command_results.scheduled_command = scheduled_command
            return command_results
        else:
            if command_results.readable_output:
                demisto.error(f"{command_results.readable_output}")
            else:
                demisto.error(f"Command {command_function} didn't succeeded, returned {outputs}")
            return command_results
    # get polling result
    command_results = results_function(client, args)
    outputs_result_func = command_results.raw_response
    if not outputs_result_func:
        return_error(f"Command {cmd} didn't succeeded, received empty response.")
    result = outputs_result_func.get(polling_field) if isinstance(outputs_result_func, dict) else \
        outputs_result_func[0].get(polling_field)
    cond = result not in polling_value if stop_polling else result in polling_value
    if values_raise_error and result in values_raise_error:
        return_results(command_results)
        raise DemistoException(f"The command {cmd} failed. Received status {result}")
    if cond:
        # schedule next poll
        polling_args = {
            'interval_in_seconds': interval_in_secs,
            **args
        }
        scheduled_command = ScheduledCommand(
            command=cmd,
            next_run_in_seconds=interval_in_secs,
            args=polling_args,
            timeout_in_seconds=timeout_in_seconds)

        # result with scheduled_command only - no update to the war room
        command_results = CommandResults(scheduled_command=scheduled_command, raw_response=outputs_result_func)
    return command_results


def convert_time_to_epoch(time_to_convert: str) -> int:
    """
    Converts time in epoch UNIX timestamp format or date in '%Y-%m-%dT%H:%M:%S' format to timestamp format.
    :param time_to_convert:
    :return: converted_timestamp
    """
    try:
        timestamp = int(time_to_convert)
        return timestamp
    except Exception:
        try:
            return date_to_timestamp(time_to_convert)
        except Exception:
            raise DemistoException('the time_frame format is invalid. Valid formats: %Y-%m-%dT%H:%M:%S or '
                                   'epoch UNIX timestamp (example: 1651505482)')


def create_filter_from_args(args: dict) -> dict:
    """
    Builds an XDR format filter dict for the xdr-get-alert command.
    :param args: The arguments provided by the user
    :return: The filter format built from args
    """
    valid_args = init_filter_args_options()
    and_operator_list = []
    start_time = args.pop('start_time', None)
    end_time = args.pop('end_time', None)

    if (start_time or end_time) and ('time_frame' not in args):
        raise DemistoException('Please choose "custom" under time_frame argument when using start_time and end_time '
                               'arguments')

    for arg_name, arg_value in args.items():
        if arg_name not in valid_args:
            raise DemistoException(f'Argument {arg_name} is not valid.')
        arg_properties = valid_args.get(arg_name)

        # handle time frame
        if arg_name == 'time_frame':
            # custom time frame
            if arg_value == 'custom':
                if not start_time or not end_time:
                    raise DemistoException(
                        'Please provide start_time and end_time arguments when using time_frame as custom.')
                start_time = convert_time_to_epoch(start_time)
                end_time = convert_time_to_epoch(end_time)
                search_type = 'RANGE'
                search_value: Union[dict, Optional[str]] = {
                    'from': start_time,
                    'to': end_time
                }

            # relative time frame
            else:
                search_value = None
                search_type = 'RELATIVE_TIMESTAMP'
                relative_date = dateparser.parse(arg_value)
                if relative_date:
                    delta_in_milliseconds = int((datetime.now() - relative_date).total_seconds() * 1000)
                    search_value = str(delta_in_milliseconds)

            and_operator_list.append({
                'SEARCH_FIELD': arg_properties.search_field,
                'SEARCH_TYPE': search_type,
                'SEARCH_VALUE': search_value
            })

        # handle array args, array elements should be seperated with 'or' op
        elif arg_properties.arg_type == 'array':
            or_operator_list = []
            arg_list = argToList(arg_value)
            for arg_item in arg_list:
                or_operator_list.append({
                    'SEARCH_FIELD': arg_properties.search_field,
                    'SEARCH_TYPE': arg_properties.search_type,
                    'SEARCH_VALUE': arg_item
                })
            and_operator_list.append({'OR': or_operator_list})
        else:
            and_operator_list.append({
                'SEARCH_FIELD': arg_properties.search_field,
                'SEARCH_TYPE': arg_properties.search_type,
                'SEARCH_VALUE': arg_properties.option_mapper.get(arg_value) if arg_properties.option_mapper else arg_value
            })

    return {'AND': and_operator_list}


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


def validate_args_scan_commands(args):
    endpoint_id_list = argToList(args.get('endpoint_id_list'))
    dist_name = argToList(args.get('dist_name'))
    gte_first_seen = args.get('gte_first_seen')
    gte_last_seen = args.get('gte_last_seen')
    lte_first_seen = args.get('lte_first_seen')
    lte_last_seen = args.get('lte_last_seen')
    ip_list = argToList(args.get('ip_list'))
    group_name = argToList(args.get('group_name'))
    platform = argToList(args.get('platform'))
    alias = argToList(args.get('alias'))
    hostname = argToList(args.get('hostname'))
    all_ = argToBoolean(args.get('all', 'false'))

    # to prevent the case where an empty filtered command will trigger by default a scan on all the endpoints.
    err_msg = 'To scan/abort scan all the endpoints run this command with the \'all\' argument as True ' \
              'and without any other filters. This may cause performance issues.\n' \
              'To scan/abort scan some of the endpoints, please use the filter arguments.'
    if all_:
        if (endpoint_id_list or dist_name or gte_first_seen or gte_last_seen or lte_first_seen or lte_last_seen
                or ip_list or group_name or platform or alias or hostname):
            raise Exception(err_msg)
    elif not endpoint_id_list and not dist_name and not gte_first_seen and not gte_last_seen \
            and not lte_first_seen and not lte_last_seen and not ip_list and not group_name and not platform \
            and not alias and not hostname:
        raise Exception(err_msg)


def endpoint_scan_command(client: CoreClient, args) -> CommandResults:
    endpoint_id_list = argToList(args.get('endpoint_id_list'))
    dist_name = argToList(args.get('dist_name'))
    gte_first_seen = args.get('gte_first_seen')
    gte_last_seen = args.get('gte_last_seen')
    lte_first_seen = args.get('lte_first_seen')
    lte_last_seen = args.get('lte_last_seen')
    ip_list = argToList(args.get('ip_list'))
    group_name = argToList(args.get('group_name'))
    platform = argToList(args.get('platform'))
    alias = argToList(args.get('alias'))
    isolate = args.get('isolate')
    hostname = argToList(args.get('hostname'))
    incident_id = arg_to_number(args.get('incident_id'))

    validate_args_scan_commands(args)

    reply = client.endpoint_scan(
        url_suffix='/endpoints/scan/',
        endpoint_id_list=argToList(endpoint_id_list),
        dist_name=dist_name,
        gte_first_seen=gte_first_seen,
        gte_last_seen=gte_last_seen,
        lte_first_seen=lte_first_seen,
        lte_last_seen=lte_last_seen,
        ip_list=ip_list,
        group_name=group_name,
        platform=platform,
        alias=alias,
        isolate=isolate,
        hostname=hostname,
        incident_id=incident_id
    )

    action_id = reply.get("action_id")

    context = {
        "actionId": action_id,
        "aborted": False
    }

    return CommandResults(
        readable_output=tableToMarkdown('Endpoint scan', {'Action Id': action_id}, ['Action Id']),
        outputs={f'{args.get("integration_context_brand", "CoreApiModule")}.endpointScan(val.actionId == obj.actionId)': context},
        raw_response=reply
    )


def action_status_get_command(client: CoreClient, args) -> CommandResults:
    action_id_list = argToList(args.get('action_id', ''))
    action_id_list = [arg_to_int(arg=item, arg_name=str(item)) for item in action_id_list]
    demisto.debug(f'action_status_get_command {action_id_list=}')
    result = []
    for action_id in action_id_list:
        reply = client.action_status_get(action_id)
        data = reply.get('data') or {}
        error_reasons = reply.get('errorReasons', {})

        for endpoint_id, status in data.items():
            action_result = {
                'action_id': action_id,
                'endpoint_id': endpoint_id,
                'status': status,
            }
            if error_reason := error_reasons.get(endpoint_id):
                action_result['ErrorReasons'] = error_reason
                action_result['error_description'] = (error_reason.get('errorDescription')
                                                      or get_missing_files_description(error_reason.get('missing_files'))
                                                      or 'An error occurred while processing the request.')
            result.append(action_result)

    return CommandResults(
        readable_output=tableToMarkdown(name='Get Action Status', t=result, removeNull=True,
                                        headers=['action_id', 'endpoint_id', 'status', 'error_description']),
        outputs_prefix=f'{args.get("integration_context_brand", "CoreApiModule")}.'
                       f'GetActionStatus(val.action_id == obj.action_id)',
        outputs=result,
        raw_response=result
    )


def get_missing_files_description(missing_files):
    if isinstance(missing_files, list) and len(missing_files) > 0 and isinstance(missing_files[0], dict):
        return missing_files[0].get('description')


def isolate_endpoint_command(client: CoreClient, args) -> CommandResults:
    endpoint_id = args.get('endpoint_id')
    disconnected_should_return_error = not argToBoolean(args.get('suppress_disconnected_endpoint_error', False))
    incident_id = arg_to_number(args.get('incident_id'))
    endpoint = client.get_endpoints(endpoint_id_list=[endpoint_id])
    if len(endpoint) == 0:
        raise ValueError(f'Error: Endpoint {endpoint_id} was not found')

    endpoint = endpoint[0]
    endpoint_status = endpoint.get('endpoint_status')
    is_isolated = endpoint.get('is_isolated')
    if is_isolated == 'AGENT_ISOLATED':
        return CommandResults(
            readable_output=f'Endpoint {endpoint_id} already isolated.'
        )
    if is_isolated == 'AGENT_PENDING_ISOLATION':
        return CommandResults(
            readable_output=f'Endpoint {endpoint_id} pending isolation.'
        )
    if endpoint_status == 'UNINSTALLED':
        raise ValueError(f'Error: Endpoint {endpoint_id}\'s Agent is uninstalled and therefore can not be isolated.')
    if endpoint_status == 'DISCONNECTED':
        if disconnected_should_return_error:
            raise ValueError(f'Error: Endpoint {endpoint_id} is disconnected and therefore can not be isolated.')
        else:
            return CommandResults(
                readable_output=f'Warning: isolation action is pending for the following disconnected endpoint: {endpoint_id}.',
                outputs={f'{args.get("integration_context_brand", "CoreApiModule")}.'
                         f'Isolation.endpoint_id(val.endpoint_id == obj.endpoint_id)': endpoint_id}
            )
    if is_isolated == 'AGENT_PENDING_ISOLATION_CANCELLATION':
        raise ValueError(
            f'Error: Endpoint {endpoint_id} is pending isolation cancellation and therefore can not be isolated.'
        )
    try:
        result = client.isolate_endpoint(endpoint_id=endpoint_id, incident_id=incident_id)

        return CommandResults(
            readable_output=f'The isolation request has been submitted successfully on Endpoint {endpoint_id}.\n',
            outputs={f'{args.get("integration_context_brand", "CoreApiModule")}.'
                     f'Isolation.endpoint_id(val.endpoint_id == obj.endpoint_id)': endpoint_id},
            raw_response=result
        )
    except Exception as e:
        return catch_and_exit_gracefully(e)


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
    return None


def create_account_context(endpoints):
    account_context = []
    for endpoint in endpoints:
        domain = endpoint.get('domain')
        if domain:
            users = endpoint.get('users', [])  # in case the value of 'users' is None
            if users and isinstance(users, list):
                for user in users:
                    account_context.append({
                        'Username': user,
                        'Domain': domain,
                    })

    return account_context


def get_endpoint_properties(single_endpoint):
    status = 'Online' if single_endpoint.get('endpoint_status', '').lower() == 'connected' else 'Offline'
    is_isolated = 'No' if 'unisolated' in single_endpoint.get('is_isolated', '').lower() else 'Yes'
    hostname = single_endpoint['host_name'] if single_endpoint.get('host_name') else single_endpoint.get(
        'endpoint_name')
    ip = single_endpoint.get('ip') or single_endpoint.get('public_ip') or ''
    return status, is_isolated, hostname, ip


def convert_os_to_standard(endpoint_os):
    os_type = ''
    endpoint_os = endpoint_os.lower()
    if 'windows' in endpoint_os:
        os_type = "Windows"
    elif 'linux' in endpoint_os:
        os_type = "Linux"
    elif 'mac' in endpoint_os:
        os_type = "Macos"
    elif 'android' in endpoint_os:
        os_type = "Android"
    return os_type


def generate_endpoint_by_contex_standard(endpoints, ip_as_string, integration_name="CoreApiModule"):
    standard_endpoints = []
    for single_endpoint in endpoints:
        status, is_isolated, hostname, ip = get_endpoint_properties(single_endpoint)
        # in the `-get-endpoints` command the ip is returned as list, in order not to break bc we will keep it
        # in the `endpoint` command we use the standard
        if ip_as_string and ip and isinstance(ip, list):
            ip = ip[0]
        os_type = convert_os_to_standard(single_endpoint.get('os_type', ''))
        endpoint = Common.Endpoint(
            id=single_endpoint.get('endpoint_id'),
            hostname=hostname,
            ip_address=ip,
            os=os_type,
            status=status,
            is_isolated=is_isolated,
            mac_address=single_endpoint.get('mac_address'),
            domain=single_endpoint.get('domain'),
            vendor=integration_name)

        standard_endpoints.append(endpoint)
    return standard_endpoints


def retrieve_all_endpoints(client, endpoints, endpoint_id_list, dist_name, ip_list, public_ip_list,
                           group_name, platform, alias_name, isolate, hostname, page_number,
                           limit, first_seen_gte, first_seen_lte, last_seen_gte, last_seen_lte,
                           sort_by_first_seen, sort_by_last_seen, status, username):
    endpoints_page = endpoints
    # Continue looping for as long as the latest page of endpoints retrieved is NOT empty
    while endpoints_page:
        page_number += 1
        endpoints_page = client.get_endpoints(
            endpoint_id_list=endpoint_id_list,
            dist_name=dist_name,
            ip_list=ip_list,
            public_ip_list=public_ip_list,
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
            sort_by_last_seen=sort_by_last_seen,
            status=status,
            username=username
        )
        endpoints += endpoints_page
    return endpoints


def convert_timestamps_to_datestring(endpoints):
    for endpoint in endpoints:
        if endpoint.get('content_release_timestamp'):
            endpoint['content_release_timestamp'] = timestamp_to_datestring(endpoint.get('content_release_timestamp'))
        if endpoint.get('first_seen'):
            endpoint['first_seen'] = timestamp_to_datestring(endpoint.get('first_seen'))
        if endpoint.get('install_date'):
            endpoint['install_date'] = timestamp_to_datestring(endpoint.get('install_date'))
        if endpoint.get('last_content_update_time'):
            endpoint['last_content_update_time'] = timestamp_to_datestring(endpoint.get('last_content_update_time'))
        if endpoint.get('last_seen'):
            endpoint['last_seen'] = timestamp_to_datestring(endpoint.get('last_seen'))
    return endpoints


def get_endpoints_command(client, args):
    integration_context_brand = args.pop('integration_context_brand', 'CoreApiModule')
    integration_name = args.pop("integration_name", "CoreApiModule")
    all_results = argToBoolean(args.get('all_results', False))
    # When we want to get all endpoints, start at page 0 and use the max limit supported by the API (100)
    if all_results:
        page_number = 0
        limit = 100
    else:
        page_number = arg_to_int(
            arg=args.get('page', '0'),
            arg_name='Failed to parse "page". Must be a number.',
            required=True
        )
        limit = arg_to_int(
            arg=args.get('limit', '30'),
            arg_name='Failed to parse "limit". Must be a number.',
            required=True
        )

    endpoint_id_list = argToList(args.get('endpoint_id_list'))
    dist_name = argToList(args.get('dist_name'))
    ip_list = argToList(args.get('ip_list'))
    public_ip_list = argToList(args.get('public_ip_list'))
    group_name = argToList(args.get('group_name'))
    platform = argToList(args.get('platform'))
    alias_name = argToList(args.get('alias_name'))
    isolate = args.get('isolate')
    hostname = argToList(args.get('hostname'))
    status = argToList(args.get('status'))
    convert_timestamp_to_datestring = argToBoolean(args.get('convert_timestamp_to_datestring', False))

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

    username = argToList(args.get('username'))

    endpoints = client.get_endpoints(
        endpoint_id_list=endpoint_id_list,
        dist_name=dist_name,
        ip_list=ip_list,
        public_ip_list=public_ip_list,
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
        sort_by_last_seen=sort_by_last_seen,
        status=status,
        username=username
    )

    if all_results:
        endpoints = retrieve_all_endpoints(client, endpoints, endpoint_id_list, dist_name,
                                           ip_list, public_ip_list, group_name, platform,
                                           alias_name, isolate, hostname, page_number,
                                           limit, first_seen_gte, first_seen_lte,
                                           last_seen_gte, last_seen_lte, sort_by_first_seen,
                                           sort_by_last_seen, status, username)

    if convert_timestamp_to_datestring:
        endpoints = convert_timestamps_to_datestring(endpoints)

    standard_endpoints = generate_endpoint_by_contex_standard(endpoints, False, integration_name)
    endpoint_context_list = []
    for endpoint in standard_endpoints:
        endpoint_context = endpoint.to_context().get(Common.Endpoint.CONTEXT_PATH)
        endpoint_context_list.append(endpoint_context)

    context = {
        f'{integration_context_brand}.Endpoint(val.endpoint_id == obj.endpoint_id)': endpoints,
        Common.Endpoint.CONTEXT_PATH: endpoint_context_list,
        f'{integration_context_brand}.Endpoint.count': len(standard_endpoints)
    }
    account_context = create_account_context(endpoints)
    if account_context:
        context[Common.Account.CONTEXT_PATH] = account_context

    return CommandResults(
        readable_output=tableToMarkdown('Endpoints', endpoints),
        outputs=context,
        raw_response=endpoints
    )


def endpoint_alias_change_command(client: CoreClient, **args) -> CommandResults:
    # get arguments
    endpoint_id_list = argToList(args.get('endpoint_id_list'))
    dist_name_list = argToList(args.get('dist_name'))
    ip_list = argToList(args.get('ip_list'))
    group_name_list = argToList(args.get('group_name'))
    platform_list = argToList(args.get('platform'))
    alias_name_list = argToList(args.get('alias_name'))
    isolate = args.get('isolate')
    hostname_list = argToList(args.get('hostname'))
    status = args.get('status')
    scan_status = args.get('scan_status')
    username_list = argToList(args.get('username'))
    new_alias_name = args.get('new_alias_name')

    # This is a workaround that is needed because of a specific behaviour of the system
    # that converts an empty string to a string with double quotes.
    if new_alias_name == '""':
        new_alias_name = ""

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

    # create filters
    filters: list[dict[str, str]] = create_request_filters(
        status=status, username=username_list, endpoint_id_list=endpoint_id_list, dist_name=dist_name_list,
        ip_list=ip_list, group_name=group_name_list, platform=platform_list, alias_name=alias_name_list, isolate=isolate,
        hostname=hostname_list, first_seen_gte=first_seen_gte, first_seen_lte=first_seen_lte,
        last_seen_gte=last_seen_gte, last_seen_lte=last_seen_lte, scan_status=scan_status
    )
    if not filters:
        raise DemistoException('Please provide at least one filter.')
    # importent: the API will return True even if the endpoint does not exist, so its a good idea to check
    # the results by a get_endpoints command
    client.set_endpoints_alias(filters=filters, new_alias_name=new_alias_name)

    return CommandResults(
        readable_output="The endpoint alias was changed successfully.")


def unisolate_endpoint_command(client, args):
    endpoint_id = args.get('endpoint_id')
    incident_id = arg_to_number(args.get('incident_id'))

    disconnected_should_return_error = not argToBoolean(args.get('suppress_disconnected_endpoint_error', False))
    endpoint = client.get_endpoints(endpoint_id_list=[endpoint_id])
    if len(endpoint) == 0:
        raise ValueError(f'Error: Endpoint {endpoint_id} was not found')

    endpoint = endpoint[0]
    endpoint_status = endpoint.get('endpoint_status')
    is_isolated = endpoint.get('is_isolated')
    if is_isolated == 'AGENT_UNISOLATED':
        return CommandResults(
            readable_output=f'Endpoint {endpoint_id} already unisolated.'
        )
    if is_isolated == 'AGENT_PENDING_ISOLATION_CANCELLATION':
        return CommandResults(
            readable_output=f'Endpoint {endpoint_id} pending isolation cancellation.'
        )
    if endpoint_status == 'UNINSTALLED':
        raise ValueError(f'Error: Endpoint {endpoint_id}\'s Agent is uninstalled and therefore can not be un-isolated.')
    if endpoint_status == 'DISCONNECTED':
        if disconnected_should_return_error:
            raise ValueError(f'Error: Endpoint {endpoint_id} is disconnected and therefore can not be un-isolated.')
        else:
            return CommandResults(
                readable_output=f'Warning: un-isolation action is pending for the following disconnected '
                                f'endpoint: {endpoint_id}.',
                outputs={
                    f'{args.get("integration_context_brand", "CoreApiModule")}.'
                    f'UnIsolation.endpoint_id(val.endpoint_id == obj.endpoint_id)'
                    f'': endpoint_id}
            )
    if is_isolated == 'AGENT_PENDING_ISOLATION':
        raise ValueError(
            f'Error: Endpoint {endpoint_id} is pending isolation and therefore can not be un-isolated.'
        )
    result = client.unisolate_endpoint(endpoint_id=endpoint_id, incident_id=incident_id)

    return CommandResults(
        readable_output=f'The un-isolation request has been submitted successfully on Endpoint {endpoint_id}.\n',
        outputs={f'{args.get("integration_context_brand", "CoreApiModule")}.'
                 f'UnIsolation.endpoint_id(val.endpoint_id == obj.endpoint_id)': endpoint_id},
        raw_response=result
    )


def retrieve_files_command(client: CoreClient, args: Dict[str, str]) -> CommandResults:
    endpoint_id_list: list = argToList(args.get('endpoint_ids'))
    windows: list = argToList(args.get('windows_file_paths'))
    linux: list = argToList(args.get('linux_file_paths'))
    macos: list = argToList(args.get('mac_file_paths'))
    file_path_list: list = argToList(args.get('generic_file_path'))
    incident_id: Optional[int] = arg_to_number(args.get('incident_id'))

    reply = client.retrieve_file(
        endpoint_id_list=endpoint_id_list,
        windows=windows,
        linux=linux,
        macos=macos,
        file_path_list=file_path_list,
        incident_id=incident_id
    )
    result = {'action_id': reply.get('action_id')}

    return CommandResults(
        readable_output=tableToMarkdown(name='Retrieve files', t=result, headerTransform=string_to_table_header),
        outputs_prefix=f'{args.get("integration_context_brand", "CoreApiModule")}'
                       f'.RetrievedFiles(val.action_id == obj.action_id)',
        outputs=result,
        raw_response=reply
    )


def run_snippet_code_script_command(client: CoreClient, args: Dict) -> CommandResults:
    snippet_code = args.get('snippet_code')
    endpoint_ids = argToList(args.get('endpoint_ids'))
    incident_id = arg_to_number(args.get('incident_id'))
    response = client.run_snippet_code_script(snippet_code=snippet_code, endpoint_ids=endpoint_ids, incident_id=incident_id)
    reply = response.get('reply')
    return CommandResults(
        readable_output=tableToMarkdown('Run Snippet Code Script', reply),
        outputs_prefix=f'{args.get("integration_context_brand", "CoreApiModule")}.ScriptRun',
        outputs_key_field='action_id',
        outputs=reply,
        raw_response=reply,
    )


def form_powershell_command(unescaped_string: str) -> str:
    """
    Builds a Powershell command using prefix and a shell-escaped string.

    Args:
        unescaped_string (str): An unescaped command string.

    Returns:
        str: Prefixed and escaped command.
    """
    escaped_string = ''

    for i, char in enumerate(unescaped_string):
        if char == "'":
            escaped_string += "''"

        elif char == '"':
            backslash_count = 0
            for j in range(i - 1, -1, -1):
                if unescaped_string[j] != '\\':
                    break
                backslash_count += 1

            escaped_string += ('\\' * backslash_count) + '\\"'

        else:
            escaped_string += char

    return f"powershell -Command \"{escaped_string}\""


def run_script_execute_commands_command(client: CoreClient, args: Dict) -> CommandResults:
    endpoint_ids = argToList(args.get('endpoint_ids'))
    incident_id = arg_to_number(args.get('incident_id'))
    timeout = arg_to_number(args.get('timeout', 600)) or 600

    commands = args.get('commands')
    is_raw_command = argToBoolean(args.get('is_raw_command', False))
    commands_list = remove_empty_elements([commands]) if is_raw_command else argToList(commands)

    if args.get('command_type') == 'powershell':
        commands_list = [form_powershell_command(command) for command in commands_list]
    parameters = {'commands_list': commands_list}

    response = client.run_script('a6f7683c8e217d85bd3c398f0d3fb6bf', endpoint_ids, parameters, timeout, incident_id)
    reply = response.get('reply')
    return CommandResults(
        readable_output=tableToMarkdown('Run Script Execute Commands', reply),
        outputs_prefix=f'{args.get("integration_context_brand", "CoreApiModule")}.ScriptRun',
        outputs_key_field='action_id',
        outputs=reply,
        raw_response=reply,
    )


def run_script_kill_process_command(client: CoreClient, args: Dict) -> CommandResults:
    endpoint_ids = argToList(args.get('endpoint_ids'))
    incident_id = arg_to_number(args.get('incident_id'))
    timeout = arg_to_number(args.get('timeout', 600)) or 600
    processes_names = argToList(args.get('process_name'))
    replies = []

    for process_name in processes_names:
        parameters = {'process_name': process_name}
        response = client.run_script('fd0a544a99a9421222b4f57a11839481', endpoint_ids, parameters, timeout, incident_id)
        reply = response.get('reply')
        replies.append(reply)

    command_result = CommandResults(
        readable_output=tableToMarkdown("Run Script Kill Process Results", replies),
        outputs_prefix=f'{args.get("integration_context_brand", "CoreApiModule")}.ScriptRun',
        outputs_key_field='action_id',
        outputs=replies,
        raw_response=replies,
    )

    return command_result


def run_script_file_exists_command(client: CoreClient, args: Dict) -> CommandResults:
    endpoint_ids = argToList(args.get('endpoint_ids'))
    incident_id = arg_to_number(args.get('incident_id'))
    timeout = arg_to_number(args.get('timeout', 600)) or 600
    file_paths = argToList(args.get('file_path'))
    replies = []
    for file_path in file_paths:
        parameters = {'path': file_path}
        response = client.run_script('414763381b5bfb7b05796c9fe690df46', endpoint_ids, parameters, timeout, incident_id)
        reply = response.get('reply')
        replies.append(reply)

    command_result = CommandResults(
        readable_output=tableToMarkdown(f'Run Script File Exists on {",".join(file_paths)}', replies),
        outputs_prefix=f'{args.get("integration_context_brand", "CoreApiModule")}.ScriptRun',
        outputs_key_field='action_id',
        outputs=replies,
        raw_response=replies,
    )
    return command_result


def run_script_delete_file_command(client: CoreClient, args: Dict) -> CommandResults:
    endpoint_ids = argToList(args.get('endpoint_ids'))
    incident_id = arg_to_number(args.get('incident_id'))
    timeout = arg_to_number(args.get('timeout', 600)) or 600
    file_paths = argToList(args.get('file_path'))
    replies = []
    for file_path in file_paths:
        parameters = {'file_path': file_path}
        response = client.run_script('548023b6e4a01ec51a495ba6e5d2a15d', endpoint_ids, parameters, timeout, incident_id)
        reply = response.get('reply')
        replies.append(reply)

    command_result = CommandResults(
        readable_output=tableToMarkdown(f'Run Script Delete File on {",".join(file_paths)}', replies),
        outputs_prefix=f'{args.get("integration_context_brand", "CoreApiModule")}.ScriptRun',
        outputs_key_field='action_id',
        outputs=replies,
        raw_response=replies,
    )
    return command_result


def quarantine_files_command(client, args):
    endpoint_id_list = argToList(args.get("endpoint_id_list"))
    file_path = args.get("file_path")
    file_hash = args.get("file_hash")
    incident_id = arg_to_number(args.get('incident_id'))

    try:
        reply = client.quarantine_files(
            endpoint_id_list=endpoint_id_list,
            file_path=file_path,
            file_hash=file_hash,
            incident_id=incident_id
        )
        output = {
            'endpointIdList': endpoint_id_list,
            'filePath': file_path,
            'fileHash': file_hash,
            'actionId': reply.get("action_id")
        }

        return CommandResults(
            readable_output=tableToMarkdown('Quarantine files', output, headers=[*output],
                                            headerTransform=pascalToSpace),
            outputs={f'{args.get("integration_context_brand", "CoreApiModule")}.'
                     f'quarantineFiles.actionIds(val.actionId === obj.actionId)': output},
            raw_response=reply
        )
    except Exception as e:
        return catch_and_exit_gracefully(e)


def restore_file_command(client, args):
    file_hash = args.get('file_hash')
    endpoint_id = args.get('endpoint_id')
    incident_id = arg_to_number(args.get('incident_id'))

    reply = client.restore_file(
        file_hash=file_hash,
        endpoint_id=endpoint_id,
        incident_id=incident_id
    )
    action_id = reply.get("action_id")

    return CommandResults(
        readable_output=tableToMarkdown('Restore files', {'Action Id': action_id}, ['Action Id']),
        outputs={f'{args.get("integration_context_brand", "CoreApiModule")}.'
                 f'restoredFiles.actionId(val.actionId == obj.actionId)': action_id},
        raw_response=reply
    )


def validate_sha256_hashes(hash_list):
    for hash_value in hash_list:
        if detect_file_indicator_type(hash_value) != 'sha256':
            raise DemistoException(f'The provided hash {hash_value} is not a valid sha256.')


def blocklist_files_command(client, args):
    hash_list = argToList(args.get('hash_list'))
    validate_sha256_hashes(hash_list)
    comment = args.get('comment')
    incident_id = arg_to_number(args.get('incident_id'))
    detailed_response = argToBoolean(args.get('detailed_response', False))
    try:
        res = client.blocklist_files(hash_list=hash_list,
                                     comment=comment,
                                     incident_id=incident_id,
                                     detailed_response=detailed_response)
    except Exception as e:
        if 'All hashes have already been added to the allow or block list' in str(e):
            return CommandResults(
                readable_output='All hashes have already been added to the block list.'
            )
        raise e

    if detailed_response:
        return CommandResults(
            readable_output=tableToMarkdown('Blocklist Files', res),
            outputs_prefix=f'{args.get("integration_context_brand", "CoreApiModule")}.blocklist',
            outputs=res,
            raw_response=res
        )

    markdown_data = [{'added_hashes': file_hash} for file_hash in hash_list]

    return CommandResults(
        readable_output=tableToMarkdown('Blocklist Files',
                                        markdown_data,
                                        headers=['added_hashes'],
                                        headerTransform=pascalToSpace),
        outputs={f'{args.get("integration_context_brand", "CoreApiModule")}.'
                 f'{args.get("prefix", "blocklist")}.added_hashes.fileHash(val.fileHash == obj.fileHash)': hash_list},
        raw_response=res
    )


def remove_blocklist_files_command(client: CoreClient, args: Dict) -> CommandResults:
    hash_list = argToList(args.get('hash_list'))
    validate_sha256_hashes(hash_list)
    comment = args.get('comment')
    incident_id = arg_to_number(args.get('incident_id'))

    res = client.remove_blocklist_files(hash_list=hash_list, comment=comment, incident_id=incident_id)
    markdown_data = [{'removed_hashes': file_hash} for file_hash in hash_list]

    return CommandResults(
        readable_output=tableToMarkdown('Blocklist Files Removed',
                                        markdown_data,
                                        headers=['removed_hashes'],
                                        headerTransform=pascalToSpace),
        outputs_prefix=f'{args.get("integration_context_brand", "CoreApiModule")}.blocklist',
        outputs=markdown_data,
        raw_response=res
    )


def allowlist_files_command(client, args):
    hash_list = argToList(args.get('hash_list'))
    comment = args.get('comment')
    incident_id = arg_to_number(args.get('incident_id'))
    detailed_response = argToBoolean(args.get('detailed_response', False))
    try:
        res = client.allowlist_files(hash_list=hash_list,
                                     comment=comment,
                                     incident_id=incident_id,
                                     detailed_response=detailed_response)
    except Exception as e:
        if 'All hashes have already been added to the allow or block list' in str(e):
            return CommandResults(
                readable_output='All hashes have already been added to the allow list.'
            )
        raise e

    if detailed_response:
        return CommandResults(
            readable_output=tableToMarkdown('Allowlist Files', res),
            outputs_prefix=f'{args.get("integration_context_brand", "CoreApiModule")}.allowlist',
            outputs=res,
            raw_response=res
        )

    markdown_data = [{'added_hashes': file_hash} for file_hash in hash_list]

    return CommandResults(
        readable_output=tableToMarkdown('Allowlist Files',
                                        markdown_data,
                                        headers=['added_hashes'],
                                        headerTransform=pascalToSpace),
        outputs={f'{args.get("integration_context_brand", "CoreApiModule")}.'
                 f'{args.get("prefix", "allowlist")}.added_hashes.fileHash(val.fileHash == obj.fileHash)': hash_list},
        raw_response=res
    )


def remove_allowlist_files_command(client, args):
    hash_list = argToList(args.get('hash_list'))
    comment = args.get('comment')
    incident_id = arg_to_number(args.get('incident_id'))
    res = client.remove_allowlist_files(hash_list=hash_list, comment=comment, incident_id=incident_id)
    markdown_data = [{'removed_hashes': file_hash} for file_hash in hash_list]
    return CommandResults(
        readable_output=tableToMarkdown('Allowlist Files Removed',
                                        markdown_data,
                                        headers=['removed_hashes'],
                                        headerTransform=pascalToSpace),
        outputs_prefix=f'{args.get("integration_context_brand", "CoreApiModule")}.allowlist',
        outputs=markdown_data,
        raw_response=res
    )


def create_endpoint_context(audit_logs):
    endpoints = []
    for log in audit_logs:
        endpoint_details = {
            'ID': log.get('ENDPOINTID'),
            'Hostname': log.get('ENDPOINTNAME'),
            'Domain': log.get('DOMAIN'),
        }
        remove_nulls_from_dictionary(endpoint_details)
        if endpoint_details:
            endpoints.append(endpoint_details)

    return endpoints


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
    integration_context = {
        f'{args.get("integration_context_brand", "CoreApiModule")}.AuditAgentReports': audit_logs}
    endpoint_context = create_endpoint_context(audit_logs)
    if endpoint_context:
        integration_context[Common.Endpoint.CONTEXT_PATH] = endpoint_context
    return (
        tableToMarkdown('Audit Agent Reports', audit_logs),
        integration_context,
        audit_logs
    )


def get_distribution_url_command(client, args):
    distribution_id = args.get('distribution_id')
    package_type = args.get('package_type')
    download_package = argToBoolean(args.get('download_package', False))

    url = client.get_distribution_url(distribution_id, package_type)

    if download_package and package_type not in ['x64', 'x86']:
        raise DemistoException("`download_package` argument can be used only for package_type 'x64' or 'x86'.")

    if not download_package:
        return CommandResults(
            outputs={
                'id': distribution_id,
                'url': url
            },
            outputs_prefix=f'{args.get("integration_context_brand", "CoreApiModule")}.Distribution',
            outputs_key_field='id',
            readable_output=f'[Distribution URL]({url})'
        )

    return download_installation_package(client,
                                         url,
                                         package_type,
                                         distribution_id,
                                         args.get("integration_context_brand", "CoreApiModule"))


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
            f'{args.get("integration_context_brand", "CoreApiModule")}.Distribution(val.id == obj.id)': distribution_list
        },
        distribution_list
    )


def download_installation_package(client, url: str, package_type: str, distribution_id: str, brand: str):
    dist_file_contents = client._http_request(
        method='GET',
        full_url=url,
        resp_type="content"
    )
    if package_type in ["x64", "x86"]:
        file_ext = "msi"
    else:
        file_ext = "zip"
    file_result = fileResult(
        filename=f"xdr-agent-install-package.{file_ext}",
        data=dist_file_contents
    )
    result = CommandResults(
        outputs={
            'id': distribution_id,
            'url': url
        },
        outputs_prefix=f'{brand}.Distribution',
        outputs_key_field='id',
        readable_output="Installation package downloaded successfully."
    )
    return [file_result, result]


def get_process_context(alert, process_type):
    process_context = {
        'Name': alert.get(f'{process_type}_process_image_name'),
        'MD5': alert.get(f'{process_type}_process_image_md5'),
        'SHA256': alert.get(f'{process_type}_process_image_sha256'),
        'PID': alert.get(f'{process_type}_process_os_pid'),
        'CommandLine': alert.get(f'{process_type}_process_command_line'),
        'Path': alert.get(f'{process_type}_process_image_path'),
        'Start Time': alert.get(f'{process_type}_process_execution_time'),
        'Hostname': alert.get('host_name'),
    }

    remove_nulls_from_dictionary(process_context)

    # If the process contains only 'HostName' , don't create an indicator
    if len(process_context.keys()) == 1 and 'Hostname' in process_context:
        return {}
    return process_context


def add_to_ip_context(alert, ip_context):
    action_local_ip = alert.get('action_local_ip')
    action_remote_ip = alert.get('action_remote_ip')
    if action_local_ip:
        ip_context.append({
            'Address': action_local_ip,
        })

    if action_remote_ip:
        ip_context.append({
            'Address': action_remote_ip,
        })


def create_context_from_network_artifacts(network_artifacts, ip_context):
    domain_context = []

    if network_artifacts:
        for artifact in network_artifacts:
            domain = artifact.get('network_domain')
            if domain:
                domain_context.append({
                    'Name': domain,
                })

            network_ip_details = {
                'Address': artifact.get('network_remote_ip'),
                'GEO': {
                    'Country': artifact.get('network_country')},
            }

            remove_nulls_from_dictionary(network_ip_details)

            if network_ip_details:
                ip_context.append(network_ip_details)

    return domain_context


def get_indicators_context(incident):
    file_context: List[Any] = []
    process_context: List[Any] = []
    ip_context: List[Any] = []
    for alert in incident.get('alerts', []):
        # file context
        file_details = {
            'Name': alert.get('action_file_name'),
            'Path': alert.get('action_file_path'),
            'SHA265': alert.get('action_file_sha256'),  # Here for backward compatibility
            'SHA256': alert.get('action_file_sha256'),
            'MD5': alert.get('action_file_md5'),
        }
        remove_nulls_from_dictionary(file_details)

        if file_details:
            file_context.append(file_details)

        # process context
        process_types = ['actor', 'os_actor', 'causality_actor', 'action']
        for process_type in process_types:
            single_process_context = get_process_context(alert, process_type)
            if single_process_context:
                process_context.append(single_process_context)

        # ip context
        add_to_ip_context(alert, ip_context)

    network_artifacts = incident.get('network_artifacts', [])

    domain_context = create_context_from_network_artifacts(network_artifacts, ip_context)

    file_artifacts = incident.get('file_artifacts', [])
    for file in file_artifacts:
        file_sha = file.get('file_sha256')
        file_details = {
            'Name': file.get('file_name'),
            'SHA256': file_sha,
        }
        remove_nulls_from_dictionary(file_details)
        is_malicious = file.get("is_malicious")

        if file_details:
            file_context.append(file_details)
            if file_sha:
                relevant_processes = filter(lambda p: p.get("SHA256") == file_sha, process_context)
                for process in relevant_processes:
                    process["is_malicious"] = is_malicious

    return file_context, process_context, domain_context, ip_context


def endpoint_command(client, args):
    endpoint_id_list = argToList(args.get('id'))
    endpoint_ip_list = argToList(args.get('ip'))
    endpoint_hostname_list = argToList(args.get('hostname'))

    if not any((endpoint_id_list, endpoint_ip_list, endpoint_hostname_list)):
        raise DemistoException(f'{args.get("integration_name", "CoreApiModule")} -'
                               f' In order to run this command, please provide a valid id, ip or hostname')

    endpoints = client.get_endpoints(
        endpoint_id_list=endpoint_id_list,
        ip_list=endpoint_ip_list,
        hostname=endpoint_hostname_list,
    )
    standard_endpoints = generate_endpoint_by_contex_standard(endpoints, True, args.get("integration_name", "CoreApiModule"))
    command_results = []
    if standard_endpoints:
        for endpoint in standard_endpoints:
            endpoint_context = endpoint.to_context().get(Common.Endpoint.CONTEXT_PATH)
            hr = tableToMarkdown('Cortex Endpoint', endpoint_context)

            command_results.append(CommandResults(
                readable_output=hr,
                raw_response=endpoints,
                indicator=endpoint
            ))

    else:
        command_results.append(CommandResults(
            readable_output="No endpoints were found",
            raw_response=endpoints,
        ))
    return command_results


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
            f'{args.get("integration_context_brand", "CoreApiModule")}.'
            f'AuditManagementLogs(val.AUDIT_ID == obj.AUDIT_ID)': audit_logs
        },
        audit_logs
    )


def get_quarantine_status_command(client, args):
    file_path = args.get('file_path')
    file_hash = args.get('file_hash')
    endpoint_id = args.get('endpoint_id')

    reply = client.get_quarantine_status(
        file_path=file_path,
        file_hash=file_hash,
        endpoint_id=endpoint_id
    )
    output = {
        'status': reply['status'],
        'endpointId': reply['endpoint_id'],
        'filePath': reply['file_path'],
        'fileHash': reply['file_hash']
    }

    return CommandResults(
        readable_output=tableToMarkdown('Quarantine files status', output, headers=[*output], headerTransform=pascalToSpace),
        outputs={f'{args.get("integration_context_brand", "CoreApiModule")}.'
                 f'quarantineFiles.status(val.fileHash === obj.fileHash &&'
                 f'val.endpointId === obj.endpointId && val.filePath === obj.filePath)': output},
        raw_response=reply
    )


def endpoint_scan_abort_command(client, args):
    endpoint_id_list = argToList(args.get('endpoint_id_list'))
    dist_name = argToList(args.get('dist_name'))
    gte_first_seen = args.get('gte_first_seen')
    gte_last_seen = args.get('gte_last_seen')
    lte_first_seen = args.get('lte_first_seen')
    lte_last_seen = args.get('lte_last_seen')
    ip_list = argToList(args.get('ip_list'))
    group_name = argToList(args.get('group_name'))
    platform = argToList(args.get('platform'))
    alias = argToList(args.get('alias'))
    isolate = args.get('isolate')
    hostname = argToList(args.get('hostname'))
    incident_id = arg_to_number(args.get('incident_id'))

    validate_args_scan_commands(args)

    reply = client.endpoint_scan(
        url_suffix='endpoints/abort_scan/',
        endpoint_id_list=argToList(endpoint_id_list),
        dist_name=dist_name,
        gte_first_seen=gte_first_seen,
        gte_last_seen=gte_last_seen,
        lte_first_seen=lte_first_seen,
        lte_last_seen=lte_last_seen,
        ip_list=ip_list,
        group_name=group_name,
        platform=platform,
        alias=alias,
        isolate=isolate,
        hostname=hostname,
        incident_id=incident_id
    )

    action_id = reply.get("action_id")

    context = {
        "actionId": action_id,
        "aborted": True
    }

    return CommandResults(
        readable_output=tableToMarkdown('Endpoint abort scan', {'Action Id': action_id}, ['Action Id']),
        outputs={f'{args.get("integration_context_brand", "CoreApiModule")}.'
                 f'endpointScan(val.actionId == obj.actionId)': context},
        raw_response=reply
    )


def sort_by_key(list_to_sort, main_key, fallback_key):
    """Sorts a given list elements by main_key for all elements with the key,
    uses sorting by fallback_key on all elements that dont have the main_key"""
    list_elements_with_main_key = [element for element in list_to_sort if element.get(main_key)]
    sorted_list = sorted(list_elements_with_main_key, key=itemgetter(main_key))
    if len(list_to_sort) == len(sorted_list):
        return sorted_list

    list_elements_with_fallback_without_main = [element for element in list_to_sort
                                                if element.get(fallback_key) and not element.get(main_key)]
    sorted_list.extend(sorted(list_elements_with_fallback_without_main, key=itemgetter(fallback_key)))

    if len(sorted_list) == len(list_to_sort):
        return sorted_list

    list_elements_without_fallback_and_main = [element for element in list_to_sort
                                               if not element.get(fallback_key) and not element.get(main_key)]

    sorted_list.extend(list_elements_without_fallback_and_main)
    return sorted_list


def drop_field_underscore(section):
    section_copy = section.copy()
    for field in section_copy:
        if '_' in field:
            section[field.replace('_', '')] = section.get(field)


def reformat_sublist_fields(sublist):
    for section in sublist:
        drop_field_underscore(section)


def handle_outgoing_incident_owner_sync(update_args):
    if 'owner' in update_args and demisto.params().get('sync_owners'):
        if update_args.get('owner'):
            user_info = demisto.findUser(username=update_args.get('owner'))
            if user_info:
                update_args['assigned_user_mail'] = user_info.get('email')
        else:
            # handle synced unassignment
            update_args['assigned_user_mail'] = None


def handle_user_unassignment(update_args):
    if ('assigned_user_mail' in update_args and update_args.get('assigned_user_mail') in ['None', 'null', '', None]) \
        or ('assigned_user_pretty_name' in update_args
            and update_args.get('assigned_user_pretty_name') in ['None', 'null', '', None]):
        update_args['unassign_user'] = 'true'
        update_args['assigned_user_mail'] = None
        update_args['assigned_user_pretty_name'] = None


def resolve_xdr_close_reason(xsoar_close_reason: str) -> str:
    """
    Resolving XDR close reason from possible custom XSOAR->XDR close-reason mapping or default mapping.
    :param xsoar_close_reason: XSOAR raw status/close reason e.g. 'False Positive'.
    :return: XDR close-reason in snake_case format e.g. 'resolved_false_positive'.
    """
    # Initially setting the close reason according to the default mapping.
    xdr_close_reason = XSOAR_RESOLVED_STATUS_TO_XDR.get(xsoar_close_reason, 'resolved_other')

    # Reading custom XSOAR->XDR close-reason mapping.
    custom_xsoar_to_xdr_close_reason_mapping = comma_separated_mapping_to_dict(
        demisto.params().get("custom_xsoar_to_xdr_close_reason_mapping")
    )

    # Overriding default close-reason mapping if there exists a custom one.
    if xsoar_close_reason in custom_xsoar_to_xdr_close_reason_mapping:
        xdr_close_reason_candidate = custom_xsoar_to_xdr_close_reason_mapping.get(xsoar_close_reason)
        # Transforming resolved close-reason into snake_case format with known prefix to match XDR status format.
        xdr_close_reason_candidate = "resolved_" + "_".join(xdr_close_reason_candidate.lower().split(" "))
        if xdr_close_reason_candidate not in XDR_RESOLVED_STATUS_TO_XSOAR:
            demisto.debug("Warning: Provided XDR close-reason does not exist. Using default XDR close-reason mapping. ")
        else:
            xdr_close_reason = xdr_close_reason_candidate
            demisto.debug(
                f"resolve_xdr_close_reason XSOAR->XDR custom close-reason exists, using {xsoar_close_reason}={xdr_close_reason}")
    else:
        demisto.debug(f"resolve_xdr_close_reason using default mapping {xsoar_close_reason}={xdr_close_reason}")

    return xdr_close_reason


def handle_outgoing_issue_closure(parsed_args: UpdateRemoteSystemArgs):
    """
    Handle closure of an outgoing issue by updating the delta field in the parsed_args object. The closed_reason will
    be determined based on whether it exists in XSOAR or XDR. If the XSOAR incident is closed and the remote incident isn't
    already closed, update the delta with resolve comment or xsoar close-reason.

    Args:
        parsed_args (object): An object of type UpdateRemoteSystemArgs, containing the parsed arguments.
    """

    close_reason_fields = ['close_reason', 'closeReason', 'closeNotes', 'resolve_comment', 'closingUserId']
    closed_reason = (next((parsed_args.delta.get(key) for key in close_reason_fields if parsed_args.delta.get(key)), None)
                     or next((parsed_args.data.get(key) for key in close_reason_fields if parsed_args.data.get(key)), None))
    demisto.debug(f"handle_outgoing_issue_closure: incident_id: {parsed_args.remote_incident_id} {closed_reason=}")
    remote_xdr_status = parsed_args.data.get('status') if parsed_args.data else None
    if parsed_args.inc_status == IncidentStatus.DONE and closed_reason and remote_xdr_status not in XDR_RESOLVED_STATUS_TO_XSOAR:
        demisto.debug("handle_outgoing_issue_closure: XSOAR is closed, xdr is open. updating delta")
        if close_notes := parsed_args.delta.get('closeNotes'):
            demisto.debug(f"handle_outgoing_issue_closure: adding resolve comment to the delta. {close_notes}")
            parsed_args.delta['resolve_comment'] = close_notes

        parsed_args.delta['status'] = resolve_xdr_close_reason(closed_reason)
        demisto.debug(
            f"handle_outgoing_issue_closure Closing Remote incident ID: {parsed_args.remote_incident_id}"
            f" with status {parsed_args.delta['status']}")


def get_update_args(parsed_args):
    """Change the updated field names to fit the update command"""
    handle_outgoing_issue_closure(parsed_args)
    handle_outgoing_incident_owner_sync(parsed_args.delta)
    handle_user_unassignment(parsed_args.delta)
    return parsed_args.delta


def get_distribution_versions_command(client, args):
    versions = client.get_distribution_versions()

    readable_output = []
    for operation_system in versions:
        os_versions = versions[operation_system]

        readable_output.append(
            tableToMarkdown(operation_system, os_versions or [], ['versions'])
        )

    return (
        '\n\n'.join(readable_output),
        {
            f'{args.get("integration_context_brand", "CoreApiModule")}.DistributionVersions': versions
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
            f'{args.get("integration_context_brand", "CoreApiModule")}.Distribution(val.id == obj.id)': distribution
        },
        distribution
    )


def delete_endpoints_command(client: CoreClient, args: Dict[str, str]) -> Tuple[str, Any, Any]:
    endpoint_id_list: list = argToList(args.get('endpoint_ids'))

    client.delete_endpoints(endpoint_id_list)

    return f'Successfully deleted the following endpoints: {args.get("endpoint_ids")}', None, None


def get_policy_command(client: CoreClient, args: Dict[str, str]) -> Tuple[str, dict, Any]:
    endpoint_id = args.get('endpoint_id')

    reply = client.get_policy(endpoint_id)
    context = {'endpoint_id': endpoint_id,
               'policy_name': reply.get('policy_name')}

    return (
        f'The policy name of endpoint: {endpoint_id} is: {reply.get("policy_name")}.',
        {
            f'{args.get("integration_context_brand", "CoreApiModule")}.Policy(val.endpoint_id == obj.endpoint_id)': context
        },
        reply
    )


def get_endpoint_device_control_violations_command(client: CoreClient, args: Dict[str, str]) -> Tuple[str, dict, Any]:
    endpoint_ids: list = argToList(args.get('endpoint_ids'))
    type_of_violation = args.get('type')
    timestamp_gte: int = arg_to_timestamp(
        arg=args.get('timestamp_gte'),
        arg_name='timestamp_gte'
    )
    timestamp_lte: int = arg_to_timestamp(
        arg=args.get('timestamp_lte'),
        arg_name='timestamp_lte'
    )
    ip_list: list = argToList(args.get('ip_list'))
    vendor: list = argToList(args.get('vendor'))
    vendor_id: list = argToList(args.get('vendor_id'))
    product: list = argToList(args.get('product'))
    product_id: list = argToList(args.get('product_id'))
    serial: list = argToList(args.get('serial'))
    hostname: list = argToList(args.get('hostname'))
    violation_id_list: list = argToList(args.get('violation_id_list', ''))
    username: list = argToList(args.get('username'))

    violation_ids = [arg_to_int(arg=item, arg_name=str(item)) for item in violation_id_list]

    reply = client.get_endpoint_device_control_violations(
        endpoint_ids=endpoint_ids,
        type_of_violation=[type_of_violation],
        timestamp_gte=timestamp_gte,
        timestamp_lte=timestamp_lte,
        ip_list=ip_list,
        vendor=vendor,
        vendor_id=vendor_id,
        product=product,
        product_id=product_id,
        serial=serial,
        hostname=hostname,
        violation_ids=violation_ids,
        username=username
    )

    headers = ['date', 'hostname', 'platform', 'username', 'ip', 'type', 'violation_id', 'vendor', 'product',
               'serial']
    violations: list = copy.deepcopy(reply.get('violations'))  # type: ignore
    for violation in violations:
        timestamp: str = violation.get('timestamp')
        violation['date'] = timestamp_to_datestring(timestamp, TIME_FORMAT)

    return (
        tableToMarkdown(name='Endpoint Device Control Violation', t=violations, headers=headers,
                        headerTransform=string_to_table_header, removeNull=True),
        {
            f'{args.get("integration_context_brand", "CoreApiModule")}.'
            f'EndpointViolations(val.violation_id==obj.violation_id)': violations
        },
        reply
    )


def retrieve_file_details_command(client: CoreClient, args, add_to_context):
    action_id_list = argToList(args.get('action_id', ''))
    action_id_list = [arg_to_int(arg=item, arg_name=str(item)) for item in action_id_list]

    result = []
    raw_result = []
    file_results = []
    endpoints_count = 0
    retrived_files_count = 0

    for action_id in action_id_list:
        data = client.retrieve_file_details(action_id)
        raw_result.append(data)

        for endpoint, link in data.items():
            endpoints_count += 1
            obj = {
                'action_id': action_id,
                'endpoint_id': endpoint
            }
            if link:
                retrived_files_count += 1
                obj['file_link'] = link
                file_link = "download" + link.split("download")[1]
                file = client.get_file_by_url_suffix(url_suffix=file_link)
                file_results.append(fileResult(filename=f'{endpoint}_{retrived_files_count}.zip', data=file))
            result.append(obj)

    hr = f'### Action id : {args.get("action_id", "")} \n Retrieved {retrived_files_count} files from ' \
         f'{endpoints_count} endpoints. \n To get the exact action status run the core-action-status-get command'
    context = {f'{args.get("integration_context_brand", "CoreApiModule")}'
               f'.RetrievedFiles(val.action_id == obj.action_id)': result}
    return_entry = {'Type': entryTypes['note'],
                    'ContentsFormat': formats['json'],
                    'Contents': raw_result,
                    'HumanReadable': hr,
                    'ReadableContentsFormat': formats['markdown'],
                    'EntryContext': context if add_to_context else {}
                    }
    return return_entry, file_results


def get_scripts_command(client: CoreClient, args: Dict[str, str]) -> Tuple[str, dict, Any]:
    script_name: list = argToList(args.get('script_name'))
    description: list = argToList(args.get('description'))
    created_by: list = argToList(args.get('created_by'))
    windows_supported = args.get('windows_supported')
    linux_supported = args.get('linux_supported')
    macos_supported = args.get('macos_supported')
    is_high_risk = args.get('is_high_risk')
    offset = arg_to_int(arg=args.get('offset', 0), arg_name='offset')
    limit = arg_to_int(arg=args.get('limit', 50), arg_name='limit')

    result = client.get_scripts(
        name=script_name,
        description=description,
        created_by=created_by,
        windows_supported=[windows_supported],
        linux_supported=[linux_supported],
        macos_supported=[macos_supported],
        is_high_risk=[is_high_risk]
    )
    scripts = copy.deepcopy(result.get('scripts')[offset:(offset + limit)])  # type: ignore
    for script in scripts:
        timestamp = script.get('modification_date')
        script['modification_date_timestamp'] = timestamp
        script['modification_date'] = timestamp_to_datestring(timestamp, TIME_FORMAT)
    headers: list = ['name', 'description', 'script_uid', 'modification_date', 'created_by',
                     'windows_supported', 'linux_supported', 'macos_supported', 'is_high_risk']

    return (
        tableToMarkdown(name='Scripts', t=scripts, headers=headers, removeNull=True,
                        headerTransform=string_to_table_header),
        {
            f'{args.get("integration_context_brand", "CoreApiModule")}.Scripts(val.script_uid == obj.script_uid)': scripts
        },
        result
    )


def get_script_metadata_command(client: CoreClient, args: Dict[str, str]) -> Tuple[str, dict, Any]:
    script_uid = args.get('script_uid')

    reply = client.get_script_metadata(script_uid)
    script_metadata = copy.deepcopy(reply)

    timestamp = script_metadata.get('modification_date')
    script_metadata['modification_date_timestamp'] = timestamp
    script_metadata['modification_date'] = timestamp_to_datestring(timestamp, TIME_FORMAT)

    return (
        tableToMarkdown(name='Script Metadata', t=script_metadata, removeNull=True,
                        headerTransform=string_to_table_header),
        {
            f'{args.get("integration_context_brand", "CoreApiModule")}.ScriptMetadata(val.script_uid == obj.script_uid)': reply
        },
        reply
    )


def get_script_code_command(client: CoreClient, args: Dict[str, str]) -> Tuple[str, dict, Any]:
    script_uid = args.get('script_uid')

    reply = client.get_script_code(script_uid)
    context = {
        'script_uid': script_uid,
        'code': reply
    }

    return (
        f'### Script code: \n ``` {str(reply)} ```',
        {
            f'{args.get("integration_context_brand", "CoreApiModule")}.ScriptCode(val.script_uid == obj.script_uid)': context
        },
        reply
    )


@polling_function(
    name=demisto.command(),
    interval=arg_to_number(demisto.args().get('polling_interval_in_seconds', 10)),
    # Check for both 'polling_timeout_in_seconds' and 'polling_timeout' to avoid breaking BC:
    timeout=arg_to_number(demisto.args().get('polling_timeout_in_seconds', demisto.args().get('polling_timeout', 600))),
    requires_polling_arg=False  # means it will always be default to poll, poll=true
)
def script_run_polling_command(args: dict, client: CoreClient) -> PollResult:
    if action_id := args.get('action_id'):
        response = client.get_script_execution_status(action_id)
        general_status = response.get('reply', {}).get('general_status') or ''

        return PollResult(
            response=get_script_execution_results_command(
                client, {'action_id': action_id,
                         'integration_context_brand': 'Core'
                         if argToBoolean(args.get('is_core', False))
                         else 'PaloAltoNetworksXDR'}
            ),
            continue_to_poll=general_status.upper() in ('PENDING', 'IN_PROGRESS')
        )

    else:
        endpoint_ids = argToList(args.get('endpoint_ids'))
        response = get_run_script_execution_response(client, args)
        reply = response.get('reply')
        action_id = reply.get('action_id')

        args['action_id'] = action_id

        return PollResult(
            response=None,  # since polling defaults to true, no need to deliver response here
            continue_to_poll=True,  # if an error is raised from the api, an exception will be raised
            partial_result=CommandResults(
                outputs_prefix=f'{args.get("integration_context_brand", "CoreApiModule")}.ScriptRun',
                outputs_key_field='action_id',
                outputs=reply,
                raw_response=response,
                readable_output=f'Waiting for the script to finish running '
                                f'on the following endpoints: {endpoint_ids}...'
            ),
            args_for_next_run=args
        )


def get_run_script_execution_response(client: CoreClient, args: Dict):
    script_uid = args.get('script_uid')
    endpoint_ids = argToList(args.get('endpoint_ids'))
    timeout = arg_to_number(args.get('timeout', 600)) or 600
    incident_id = arg_to_number(args.get('incident_id'))
    if parameters := args.get('parameters'):
        try:
            parameters = json.loads(parameters)
        except json.decoder.JSONDecodeError as e:
            raise ValueError(f'The parameters argument is not in a valid JSON structure:\n{e}')
    else:
        parameters = {}
    return client.run_script(script_uid, endpoint_ids, parameters, timeout, incident_id=incident_id)


def run_script_command(client: CoreClient, args: Dict) -> CommandResults:
    response = get_run_script_execution_response(client, args)
    reply = response.get('reply')
    return CommandResults(
        readable_output=tableToMarkdown('Run Script', reply),
        outputs_prefix=f'{args.get("integration_context_brand", "CoreApiModule")}.ScriptRun',
        outputs_key_field='action_id',
        outputs=reply,
        raw_response=response,
    )


def get_script_execution_status_command(client: CoreClient, args: Dict) -> CommandResults:
    action_ids = argToList(args.get('action_id', ''))
    replies = []
    raw_responses = []
    for action_id in action_ids:
        response = client.get_script_execution_status(action_id)
        reply = response.get('reply')
        reply['action_id'] = int(action_id)
        replies.append(reply)
        raw_responses.append(response)

    command_result = CommandResults(
        readable_output=tableToMarkdown(f'Script Execution Status - {",".join(str(i) for i in action_ids)}', replies),
        outputs_prefix=f'{args.get("integration_context_brand", "CoreApiModule")}.ScriptStatus',
        outputs_key_field='action_id',
        outputs=replies,
        raw_response=raw_responses,
    )
    return command_result


def parse_get_script_execution_results(results: List[Dict]) -> List[Dict]:
    parsed_results = []
    api_keys = ['endpoint_name',
                'endpoint_ip_address',
                'endpoint_status',
                'domain',
                'endpoint_id',
                'execution_status',
                'return_value',
                'standard_output',
                'retrieved_files',
                'failed_files',
                'retention_date']
    for result in results:
        result_keys = result.keys()
        difference_keys = list(set(result_keys) - set(api_keys))
        if difference_keys:
            for key in difference_keys:
                parsed_res = result.copy()
                parsed_res['command'] = key
                parsed_res['command_output'] = result[key]
                parsed_results.append(parsed_res)
        else:
            parsed_results.append(result.copy())
    return parsed_results


def get_script_execution_results_command(client: CoreClient, args: Dict) -> List[CommandResults]:
    action_ids = argToList(args.get('action_id', ''))
    command_results = []
    for action_id in action_ids:
        response = client.get_script_execution_results(action_id)
        results = response.get('reply', {}).get('results')
        context = {
            'action_id': int(action_id),
            'results': parse_get_script_execution_results(results),
        }
        command_results.append(CommandResults(
            readable_output=tableToMarkdown(f'Script Execution Results - {action_id}', results),
            outputs_prefix=f'{args.get("integration_context_brand", "CoreApiModule")}.ScriptResult',
            outputs_key_field='action_id',
            outputs=context,
            raw_response=response,
        ))
    return command_results


def get_script_execution_result_files_command(client: CoreClient, args: Dict) -> Dict:
    action_id = args.get('action_id', '')
    endpoint_id = args.get('endpoint_id')
    file_response = client.get_script_execution_result_files(action_id, endpoint_id)
    try:
        filename = file_response.headers.get('Content-Disposition').split('attachment; filename=')[1]
    except Exception as e:
        demisto.debug(f'Failed extracting filename from response headers - [{str(e)}]')
        filename = action_id + '.zip'
    return fileResult(filename, file_response.content)


def add_exclusion_command(client: CoreClient, args: Dict) -> CommandResults:
    name = args.get('name')
    indicator = args.get('filterObject')
    if not indicator:
        raise DemistoException("Didn't get filterObject arg. This arg is required.")
    status = args.get('status', "ENABLED")
    comment = args.get('comment')

    res = client.add_exclusion(name=name,
                               status=status,
                               indicator=json.loads(indicator),
                               comment=comment)

    return CommandResults(
        readable_output=tableToMarkdown('Add Exclusion', res),
        outputs={
            f'{args.get("integration_context_brand", "CoreApiModule")}.exclusion.rule_id(val.rule_id == obj.rule_id)': res.get(
                "rule_id")},
        raw_response=res
    )


def delete_exclusion_command(client: CoreClient, args: Dict) -> CommandResults:
    alert_exclusion_id = arg_to_number(args.get('alert_exclusion_id'))
    if not alert_exclusion_id:
        raise DemistoException("Didn't get alert_exclusion_id arg. This arg is required.")
    res = client.delete_exclusion(alert_exclusion_id=alert_exclusion_id)
    return CommandResults(
        readable_output=f"Successfully deleted the following exclusion: {alert_exclusion_id}",
        outputs={
            f'{args.get("integration_context_brand", "CoreApiModule")}.'
            f'deletedExclusion.rule_id(val.rule_id == obj.rule_id)': res.get(
                "rule_id")},
        raw_response=res
    )


def get_exclusion_command(client: CoreClient, args: Dict) -> CommandResults:
    res = client.get_exclusion(tenant_id=args.get('tenant_ID'),
                               filter=args.get('filterObject'),
                               limit=arg_to_number(args.get('limit', 20)))

    return CommandResults(
        outputs_prefix=f'{args.get("integration_context_brand", "CoreApiModule")}.exclusion',
        outputs=res,
        readable_output=tableToMarkdown('Exclusion', res),
        raw_response=res
    )


def decode_dict_values(dict_to_decode: dict):
    """Decode JSON str values of a given dict.

    Args:
      dict_to_decode (dict): The dict to decode.

    """
    for key, value in dict_to_decode.items():
        # if value is a dictionary, we want to recursively decode it's values
        if isinstance(value, dict):
            decode_dict_values(value)
        # if value is a string, we want to try to decode it, if it cannot be decoded, we will move on.
        elif isinstance(value, str):
            try:
                dict_to_decode[key] = json.loads(value)
            except ValueError:
                continue


def filter_general_fields(alert: dict, filter_fields: bool = True, events_from_decider_as_list: bool = False) -> dict:
    """filter only relevant general fields from a given alert.

    Args:
      alert (dict): The alert to filter
      filter_fields (bool): Whether to return a subset of the fields.
      events_from_decider_as_list (bool): Whether to return events_from_decider context endpoint as a dictionary or as a list.

    Returns:
      dict: The filtered alert
    """

    if filter_fields:
        result = {k: v for k, v in alert.items() if k in ALERT_GENERAL_FIELDS}
    else:
        result = alert

    if (events_from_decider := alert.get("stateful_raw_data", {}).get("events_from_decider", {})) and events_from_decider_as_list:
        alert["stateful_raw_data"]["events_from_decider"] = list(events_from_decider.values())

    if not (event := alert.get('raw_abioc', {}).get('event', {})):
        return_warning('No XDR cloud analytics event.')
        return result

    if filter_fields:
        updated_event = {k: v for k, v in event.items() if k in ALERT_EVENT_GENERAL_FIELDS}
    else:
        updated_event = event

    result['event'] = updated_event
    return result


def filter_vendor_fields(alert: dict):
    """Remove non relevant fields from the alert event (filter by vendor: Amazon/google/Microsoft)

    Args:
      alert (dict): The alert to filter

    Returns:
      dict: The filtered alert
    """
    vendor_mapper = {
        'Amazon': ALERT_EVENT_AWS_FIELDS,
        'Google': ALERT_EVENT_GCP_FIELDS,
        'MSFT': ALERT_EVENT_AZURE_FIELDS,
    }
    event = alert.get('event', {})
    vendor = event.get('vendor')
    if vendor and vendor in vendor_mapper:
        raw_log = event.get('raw_log', {})
        if raw_log and isinstance(raw_log, dict):
            for key in list(raw_log):
                if key not in vendor_mapper[vendor]:
                    raw_log.pop(key)


def get_original_alerts_command(client: CoreClient, args: Dict) -> CommandResults:
    alert_id_list = argToList(args.get('alert_ids', []))
    for alert_id in alert_id_list:
        if alert_id and re.match(r'^[a-fA-F0-9-]{32,36}\$&\$.+$', alert_id):
            raise DemistoException(f"Error: Alert ID {alert_id} is invalid. This issue arises because the playbook is running in"
                                   f" debug mode, which replaces the original alert ID with a debug alert ID, causing the task to"
                                   f" fail. To run this playbook in debug mode, please update the 'alert_ids' value to the real "
                                   f"alert ID in the relevant task. Alternatively, run the playbook on the actual alert "
                                   f"(not in debug mode) to ensure task success.")
    events_from_decider_as_list = bool(args.get('events_from_decider_format', '') == 'list')
    raw_response = client.get_original_alerts(alert_id_list)
    reply = copy.deepcopy(raw_response)
    alerts = reply.get('alerts', [])
    processed_alerts = []
    filtered_alerts = []

    filter_fields_argument = argToBoolean(args.get('filter_alert_fields', True))  # default, for BC, is True.

    for alert in alerts:
        # decode raw_response
        try:
            alert['original_alert_json'] = safe_load_json(alert.get('original_alert_json', ''))
            # some of the returned JSON fields are double encoded, so it needs to be double-decoded.
            # example: {"x": "someValue", "y": "{\"z\":\"anotherValue\"}"}
            decode_dict_values(alert)
        except Exception as e:
            demisto.debug("encountered the following while decoding dictionary values, skipping")
            demisto.debug(f'{e}')
            continue

        # Remove original_alert_json field and add its content to the alert body.
        alert.update(alert.pop('original_alert_json', {}))

        # Process the alert (with without filetring fields)
        processed_alerts.append(filter_general_fields(alert, filter_fields=False,
                                                      events_from_decider_as_list=events_from_decider_as_list))

        # Create a filtered version (used either for output when filter_fields is False, or for readable output)
        filtered_alert = filter_general_fields(alert, filter_fields=True, events_from_decider_as_list=False)
        filter_vendor_fields(filtered_alert)  # changes in-place

        filtered_alerts.append(filtered_alert)

    return CommandResults(
        outputs_prefix=f'{args.get("integration_context_brand", "CoreApiModule")}.OriginalAlert',
        outputs_key_field='internal_id',
        outputs=filtered_alerts if filter_fields_argument else processed_alerts,
        readable_output=tableToMarkdown("Alerts", t=filtered_alerts),  # Filtered are always used for readable output
        raw_response=raw_response,
    )


ALERT_STATUS_TYPES = {
    'DETECTED': 'detected',
    'DETECTED_0': 'detected (allowed the session)',
    'DOWNLOAD': 'detected (download)',
    'DETECTED_19': 'detected (forward)',
    'POST_DETECTED': 'detected (post detected)',
    'PROMPT_ALLOW': 'detected (prompt allow)',
    'DETECTED_4': 'detected (raised an alert)',
    'REPORTED': 'detected (reported)',
    'REPORTED_TRIGGER_4': 'detected (on write)',
    'SCANNED': 'detected (scanned)',
    'DETECTED_23': 'detected (sinkhole)',
    'DETECTED_18': 'detected (syncookie sent)',
    'DETECTED_21': 'detected (wildfire upload failure)',
    'DETECTED_20': 'detected (wildfire upload success)',
    'DETECTED_22': 'detected (wildfire upload skip)',
    'DETECTED_MTH': 'detected (xdr managed threat hunting)',
    'BLOCKED_25': 'prevented (block)',
    'BLOCKED': 'prevented (blocked)',
    'BLOCKED_14': 'prevented (block-override)',
    'BLOCKED_5': 'prevented (blocked the url)',
    'BLOCKED_6': 'prevented (blocked the ip)',
    'BLOCKED_13': 'prevented (continue)',
    'BLOCKED_1': 'prevented (denied the session)',
    'BLOCKED_8': 'prevented (dropped all packets)',
    'BLOCKED_2': 'prevented (dropped the session)',
    'BLOCKED_3': 'prevented (dropped the session and sent a tcp reset)',
    'BLOCKED_7': 'prevented (dropped the packet)',
    'BLOCKED_16': 'prevented (override)',
    'BLOCKED_15': 'prevented (override-lockout)',
    'BLOCKED_26': 'prevented (post detected)',
    'PROMPT_BLOCK': 'prevented (prompt block)',
    'BLOCKED_17': 'prevented (random-drop)',
    'BLOCKED_24': 'prevented (silently dropped the session with an icmp unreachable message to the host or application)',
    'BLOCKED_9': 'prevented (terminated the session and sent a tcp reset to both sides of the connection)',
    'BLOCKED_10': 'prevented (terminated the session and sent a tcp reset to the client)',
    'BLOCKED_11': 'prevented (terminated the session and sent a tcp reset to the server)',
    'BLOCKED_TRIGGER_4': 'prevented (on write)',
}

ALERT_STATUS_TYPES_REVERSE_DICT = {v: k for k, v in ALERT_STATUS_TYPES.items()}


def get_alerts_by_filter_command(client: CoreClient, args: Dict) -> CommandResults:
    # get arguments
    request_data: dict = {'filter_data': {}}
    filter_data = request_data['filter_data']
    sort_field = args.pop('sort_field', 'source_insert_ts')
    sort_order = args.pop('sort_order', 'DESC')
    prefix = args.pop("integration_context_brand", "CoreApiModule")
    args.pop("integration_name", None)
    custom_filter = {}
    filter_data['sort'] = [{
        'FIELD': sort_field,
        'ORDER': sort_order
    }]
    offset = args.pop('offset', 0)
    limit = args.pop('limit', 50)
    filter_data['paging'] = {
        'from': int(offset),
        'to': int(limit)
    }
    if not args:
        raise DemistoException('Please provide at least one filter argument.')

    # handle custom filter
    custom_filter_str = args.pop('custom_filter', None)

    if custom_filter_str:
        for arg in args:
            if arg not in ['time_frame', 'start_time', 'end_time']:
                raise DemistoException(
                    'Please provide either "custom_filter" argument or other filter arguments but not both.')
        try:
            custom_filter = json.loads(custom_filter_str)
        except Exception as e:
            raise DemistoException('custom_filter format is not valid.') from e

    filter_res = create_filter_from_args(args)
    if custom_filter:  # if exists, add custom filter to the built filter
        if 'AND' in custom_filter:
            filter_obj = custom_filter['AND']
            filter_res['AND'].extend(filter_obj)
        else:
            filter_res['AND'].append(custom_filter)

    filter_data['filter'] = filter_res
    demisto.debug(f'sending the following request data: {request_data}')
    raw_response = client.get_alerts_by_filter_data(request_data)

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


def get_dynamic_analysis_command(client: CoreClient, args: Dict) -> CommandResults:
    alert_id_list = argToList(args.get('alert_ids', []))
    raw_response = client.get_original_alerts(alert_id_list)
    reply = copy.deepcopy(raw_response)
    alerts = reply.get('alerts', [])
    filtered_alerts = []
    for alert in alerts:
        # decode raw_response
        try:
            alert['original_alert_json'] = safe_load_json(alert.get('original_alert_json', ''))
            # some of the returned JSON fields are double encoded, so it needs to be double-decoded.
            # example: {"x": "someValue", "y": "{\"z\":\"anotherValue\"}"}
            decode_dict_values(alert)
        except Exception as e:
            demisto.debug("encountered the following while decoding dictionary values, skipping")
            demisto.debug(e)
        # remove original_alert_json field and add its content to alert.
        alert.update(alert.pop('original_alert_json', {}))
        if demisto.get(alert, 'messageData.dynamicAnalysis'):
            filtered_alerts.append(demisto.get(alert, 'messageData.dynamicAnalysis'))
    if not filtered_alerts:
        return CommandResults(
            readable_output="There is no dynamicAnalysis for these alert ids.",
            raw_response=raw_response
        )
    return CommandResults(
        outputs_prefix=f'{args.get("integration_context_brand", "CoreApiModule")}.DynamicAnalysis',
        outputs=filtered_alerts,
        raw_response=raw_response,
    )


def create_request_filters(
    status: Optional[str] = None,
    username: Optional[List] = None,
    endpoint_id_list: Optional[List] = None,
    dist_name: Optional[List] = None,
    ip_list: Optional[List] = None,
    public_ip_list: Optional[List] = None,
    group_name: Optional[List] = None,
    platform: Optional[List] = None,
    alias_name: Optional[List] = None,
    isolate: Optional[str] = None,
    hostname: Optional[List] = None,
    first_seen_gte=None,
    first_seen_lte=None,
    last_seen_gte=None,
    last_seen_lte=None,
    scan_status=None,
):
    filters = []

    if status:
        filters.append({
            'field': 'endpoint_status',
            'operator': 'IN',
            'value': status if isinstance(status, list) else [status]
        })

    if username:
        filters.append({
            'field': 'username',
            'operator': 'IN',
            'value': username
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

    if public_ip_list:
        filters.append({
            'field': 'public_ip_list',
            'operator': 'in',
            'value': public_ip_list
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

    if scan_status:
        filters.append({
            'field': 'scan_status',
            'operator': 'IN',
            'value': [scan_status]
        })

    return filters


def args_to_request_filters(args):
    if set(args.keys()) & {  # check if any filter argument was provided
        'endpoint_id_list', 'dist_name', 'ip_list', 'group_name', 'platform', 'alias_name',
        'isolate', 'hostname', 'status', 'first_seen_gte', 'first_seen_lte', 'last_seen_gte', 'last_seen_lte'
    }:
        endpoint_id_list = argToList(args.get('endpoint_id_list'))
        dist_name = argToList(args.get('dist_name'))
        ip_list = argToList(args.get('ip_list'))
        group_name = argToList(args.get('group_name'))
        platform = argToList(args.get('platform'))
        alias_name = argToList(args.get('alias_name'))
        isolate = args.get('isolate')
        hostname = argToList(args.get('hostname'))
        status = args.get('status')

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

        return create_request_filters(
            endpoint_id_list=endpoint_id_list, dist_name=dist_name, ip_list=ip_list,
            group_name=group_name, platform=platform, alias_name=alias_name, isolate=isolate, hostname=hostname,
            first_seen_lte=first_seen_lte, first_seen_gte=first_seen_gte,
            last_seen_lte=last_seen_lte, last_seen_gte=last_seen_gte, status=status
        )
    # a request must be sent with at least one filter parameter, so by default we will send the endpoint_id_list filter
    return create_request_filters(endpoint_id_list=argToList(args.get('endpoint_ids')))


def add_tag_to_endpoints_command(client: CoreClient, args: Dict):
    endpoint_ids = argToList(args.get('endpoint_ids', []))
    tag = args.get('tag')
    raw_response = {}
    for b in batch(endpoint_ids, 1000):
        raw_response.update(client.add_tag_endpoint(endpoint_ids=b, tag=tag, args=args))

    return CommandResults(
        readable_output=f'Successfully added tag {tag} to endpoint(s) {endpoint_ids}', raw_response=raw_response
    )


def remove_tag_from_endpoints_command(client: CoreClient, args: Dict):
    endpoint_ids = argToList(args.get('endpoint_ids', []))
    tag = args.get('tag')
    raw_response = {}
    for b in batch(endpoint_ids, 1000):
        raw_response.update(client.remove_tag_endpoint(endpoint_ids=b, tag=tag, args=args))

    return CommandResults(
        readable_output=f'Successfully removed tag {tag} from endpoint(s) {endpoint_ids}', raw_response=raw_response
    )


def parse_risky_users_or_hosts(user_or_host_data: dict[str, Any],
                               id_header: str,
                               score_header: str,
                               description_header: str
                               ) -> dict[str, Any]:
    reasons = user_or_host_data.get('reasons', [])
    return {
        id_header: user_or_host_data.get('id'),
        score_header: user_or_host_data.get('score'),
        description_header: reasons[0].get('description') if reasons else None,
    }


def parse_user_groups(group: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            'User email': user,
            'Group Name': group.get('group_name'),
            'Group Description': group.get('description'),
        }
        for user in group.get("user_email", [])
    ]


def parse_role_names(role_data: dict[str, Any]) -> dict[str, Any]:
    return {
        "Role Name": role_data.get("pretty_name"),
        "Description": role_data.get("description"),
        "Permissions": role_data.get("permissions", []),
        "Users": role_data.get("users", []),
        "Groups": role_data.get("groups", []),
    }


def enrich_error_message_id_group_role(e: DemistoException, type_: str | None, custom_message: str | None) -> str | None:
    """
    Attempts to parse additional info from an exception and return it as string. Returns `None` if it can't do that.

    Args:
        e (Exception): The error that occurred.
        type (str | None): The type of resource associated with the error(Role id or Group), if applicable.
        custom_message (str | None): A custom error message to be included in the raised ValueError, if desired.

    Raises:
        ValueError: If the error message indicates that the resource was not found, a more detailed error message
            is constructed using the `find_the_cause_error` function and raised with the original error as the cause.
    """
    if (
        e.res is not None
        and e.res.status_code == 500
        and 'was not found' in str(e)
    ):
        error_message: str = ''
        pattern = r"(id|Group|Role) \\?'([/A-Za-z 0-9_]+)\\?'"
        if match := re.search(pattern, str(e)):
            error_message = f'Error: {match[1]} {match[2]} was not found. '

        return (f'{error_message}{custom_message if custom_message and type_ in ("Group", "Role") else ""}'
                f'Full error message: {e}')
    return None


def list_users_command(client: CoreClient, args: dict[str, str]) -> CommandResults:
    """
    Returns a list of all users using the Core API client.

    Args:
        client: A CoreClient instance used for connecting to the Core API.
        args: A dictionary containing additional arguments. Possible keys include:
            - integration_context_brand (str): The name of the integration context brand.

    Returns:
        A CommandResults object containing the readable_output and outputs fields.

    Raises:
        ValueError: If the API connection failed.
    """

    def parse_user(user: dict[str, Any]) -> dict[str, Any]:
        return {
            'User email': user.get('user_email'),
            'First Name': user.get('user_first_name'),
            'Last Name': user.get('user_last_name'),
            'Role': user.get('role_name'),
            'Type': user.get('user_type'),
            'Groups': user.get('groups'),
        }

    listed_users: list[dict[str, Any]] = client.list_users().get('reply', [])
    table_for_markdown = [parse_user(user) for user in listed_users]
    readable_output = tableToMarkdown(name='Users', t=table_for_markdown)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{args.get("integration_context_brand", "CoreApiModule")}.User',
        outputs_key_field='user_email',
        outputs=listed_users,
    )


def list_user_groups_command(client: CoreClient, args: dict[str, str]) -> CommandResults:
    """
     Retrieves a list of user groups from the Core API module based on the specified group names.

    Args:
        client: A CoreClient object used to communicate with the Core API module.
        args: A dictionary of arguments passed to the function. The following keys may be present:
            - group_names (required): A list of group names to retrieve details for.

    Returns:
        A CommandResults object containing the table of user groups.

    Raises:
        ValueError: If the API connection fails or the specified group name(s) is not found.
    """

    group_names = argToList(args['group_names'])
    try:
        outputs = client.list_user_groups(group_names).get("reply", [])
    except DemistoException as e:
        custom_message = None
        if len(group_names) > 1:
            custom_message = "Note: If you sent more than one group name, they may not exist either. "

        if error_message := enrich_error_message_id_group_role(e=e, type_="Group", custom_message=custom_message):
            raise DemistoException(error_message)
        raise

    table_for_markdown: list[dict[str, str | None]] = []
    for group in outputs:
        table_for_markdown.extend(parse_user_groups(group))

    headers = ["Group Name", "Group Description", "User email"]
    readable_output = tableToMarkdown(name='Groups', t=table_for_markdown, headers=headers)
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{args.get("integration_context_brand", "CoreApiModule")}.UserGroup',
        outputs_key_field='group_name',
        outputs=outputs,
    )


def list_roles_command(client: CoreClient, args: dict[str, str]) -> CommandResults:
    """
    Retrieves a list of roles with the provided role names from the Core API.

    Args:
        client: A CoreClient object used to communicate with the Core API module.
        args: A dictionary of arguments. The 'role_names' key should be present and contain a
              comma-separated string of role names to retrieve.

    Returns:
         A CommandResults object containing the table of roles.

    Raises:
        DemistoException: If an error occurs while retrieving the data from the Core API.
        ValueError: If the input argument is not valid.

    """
    role_names = argToList(args["role_names"])
    try:
        outputs = client.list_roles(role_names).get("reply", [])
    except DemistoException as e:
        custom_message = None
        if len(role_names) > 1:
            custom_message = "Note: If you sent more than one Role name, they may not exist either. "

        if error_message := enrich_error_message_id_group_role(e=e, type_="Role", custom_message=custom_message):
            raise DemistoException(error_message)
        raise

    headers = ["Role Name", "Description", "Permissions", "Users", "Groups"]
    table_for_markdown = [parse_role_names(role[0]) for role in outputs if len(role) == 1]
    readable_output = tableToMarkdown(
        name='Roles',
        t=table_for_markdown,
        headers=headers
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{args.get("integration_context_brand", "CoreApiModule")}.Role',
        outputs_key_field='pretty_name',
        outputs=outputs,
    )


def change_user_role_command(client: CoreClient, args: dict[str, str]) -> CommandResults:
    """
     Changes or removes the role of user(s) in the system.

    Args:
        client (CoreClient): An instance of the CoreClient class used to interact with the system.
        args (dict[str, str]): A dictionary containing the command arguments.
            - 'user_emails' (str): A comma-separated string of user emails.
            - 'role_name' (str, optional): The name of the role to assign to the user(s).
              If not provided, the role for the user(s) will be removed.

    Returns:
        CommandResults: An object containing the result of the command execution.
    """
    user_emails = argToList(args['user_emails'])

    if role_name := args.get('role_name'):
        res = client.set_user_role(user_emails, role_name)["reply"]
        action_message = "updated"
    else:
        res = client.remove_user_role(user_emails)["reply"]
        action_message = "removed"

    if not (count := int(res["update_count"])):
        raise DemistoException(f"No user role has been {action_message}.")

    plural_suffix = 's' if count > 1 else ''

    return CommandResults(
        readable_output=f"Role was {action_message} successfully for {count} user{plural_suffix}."
    )


def list_risky_users_or_host_command(client: CoreClient, command: str, args: dict[str, str]) -> CommandResults:
    """
    Retrieves a list of risky users or details about a specific user's risk score.

    Args:
        client: A CoreClient object used to communicate with the API.
        args: A dictionary containing the following headers (optional):
            - user_id [str]: ID of the user to retrieve risk score details for.
            - limit [str]: Specifying the maximum number of risky users to return.

    Returns:
        A CommandResults object, in case the user was not found, an appropriate message will be returend.

    Raises:
        ValueError: If the API connection fails.

    """

    def _warn_if_module_is_disabled(e: DemistoException) -> None:
        if (
            e is not None
            and e.res is not None
            and e.res.status_code == 500
            and 'No identity threat' in str(e)
            and "An error occurred while processing XDR public API" in e.message
        ):
            return_warning(f'Please confirm the XDR Identity Threat Module is enabled.\nFull error message: {e}', exit=True)

    match command:
        case "user":
            id_key = "user_id"
            table_title = "Risky Users"
            outputs_prefix = "RiskyUser"
            get_func = client.list_risky_users
            table_headers = ["User ID", "Score", "Description"]
        case 'host':
            id_key = "host_id"
            table_title = "Risky Hosts"
            outputs_prefix = "RiskyHost"
            get_func = client.list_risky_hosts
            table_headers = ["Host ID", "Score", "Description"]

    outputs: list[dict] | dict
    if id_ := args.get(id_key):
        try:
            outputs = client.risk_score_user_or_host(id_).get('reply', {})
        except DemistoException as e:
            _warn_if_module_is_disabled(e)
            if error_message := enrich_error_message_id_group_role(e=e, type_="id", custom_message=""):
                not_found_message = 'was not found'
                if not_found_message in error_message:
                    return CommandResults(readable_output=f'The {command} {id_} {not_found_message}')
                else:
                    raise DemistoException(error_message)
            else:
                raise

        table_for_markdown = [parse_risky_users_or_hosts(outputs, *table_headers)]  # type: ignore[arg-type]

    else:
        list_limit = int(args.get('limit', 10))

        try:
            outputs = get_func().get('reply', [])[:list_limit]
        except DemistoException as e:
            _warn_if_module_is_disabled(e)
            raise
        table_for_markdown = [parse_risky_users_or_hosts(user, *table_headers) for user in outputs]

    readable_output = tableToMarkdown(name=table_title, t=table_for_markdown, headers=table_headers)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{args.get("integration_context_brand", "CoreApiModule")}.{outputs_prefix}',
        outputs_key_field='id',
        outputs=outputs,
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
        if isinstance(id_, int | float):
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

    starred = argToBoolean(args.get('starred')) if args.get('starred', None) not in ('', None) else None
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
                         " since_creation_time=\"1 year\" sort_by_creation_time=\"desc\" limit=10")

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
            f'{args.get("integration_context_brand", "CoreApiModule")}.Incident(val.incident_id==obj.incident_id)': raw_incidents
        },
        raw_incidents
    )


def terminate_process_command(client, args) -> CommandResults:
    """
    AVAILABLE ONLY TO XDR3.12 / XSIAM2.4
    Terminate the process command for a specific agent and instance IDs.

    :type client: ``Client``
    :param client: The client to use for making API calls.

    :type args: ``Dict[str, Any]``
    :param args: The arguments for the command.

    :return: The results of the command.
    :rtype: ``CommandResults``
    """
    agent_id = args.get('agent_id')
    instance_ids = argToList(args.get('instance_id'))
    process_name = args.get('process_name')
    incident_id = args.get('incident_id')
    replies: List[Dict[str, Any]] = []
    for instance_id in instance_ids:
        reply_per_instance_id = client.terminate_on_agent(
            url_suffix_endpoint='terminate_process',
            id_key='instance_id',
            id_value=instance_id,
            agent_id=agent_id,
            process_name=process_name,
            incident_id=incident_id
        )
        action_id = reply_per_instance_id.get("group_action_id")
        demisto.debug(f'Action terminate process succeeded with action_id={action_id}')
        replies.append({"action_id": action_id})

    return CommandResults(
        readable_output=tableToMarkdown(f'Action terminate process created on instance ids: {", ".join(instance_ids)}', replies),
        outputs={
            f'{args.get("integration_context_brand", "CoreApiModule")}'
            f'.TerminateProcess(val.actionId && val.actionId == obj.actionId)': replies},
        raw_response=replies
    )


def terminate_causality_command(client, args) -> CommandResults:
    """
    AVAILABLE ONLY TO XDR3.12 / XSIAM2.4
    Terminate the causality command for a specific agent and causality IDs.

    :type client: ``Client``
    :param client: The client to use for making API calls.

    :type args: ``Dict[str, Any]``
    :param args: The arguments for the command.

    :return: The results of the command.
    :rtype: ``CommandResults``
    """
    agent_id = args.get('agent_id')
    causality_ids = argToList(args.get('causality_id'))
    process_name = args.get('process_name')
    incident_id = args.get('incident_id')
    replies: List[Dict[str, Any]] = []
    for causality_id in causality_ids:
        reply_per_instance_id = client.terminate_on_agent(
            url_suffix_endpoint='terminate_causality',
            id_key='causality_id',
            id_value=causality_id,
            agent_id=agent_id,
            process_name=process_name,
            incident_id=incident_id
        )
        action_id = reply_per_instance_id.get("group_action_id")
        demisto.debug(f'Action terminate process succeeded with action_id={action_id}')
        replies.append({"action_id": action_id})

    return CommandResults(
        readable_output=tableToMarkdown(f'Action terminate causality created on {",".join(causality_ids)}', replies),
        outputs={f'{args.get("integration_context_brand", "CoreApiModule")}.TerminateProcess(val.actionId == obj.actionId)':
                 replies},
        raw_response=replies
    )
