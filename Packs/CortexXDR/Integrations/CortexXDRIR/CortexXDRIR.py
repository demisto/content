import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from datetime import timezone
import secrets
import string
import hashlib
from typing import Any, Dict, Tuple
import dateparser
import urllib3
import traceback
from operator import itemgetter
import copy

# Disable insecure warnings
urllib3.disable_warnings()

TIME_FORMAT = "%Y-%m-%dT%H:%M:%S"
NONCE_LENGTH = 64
API_KEY_LENGTH = 128

INTEGRATION_CONTEXT_BRAND = 'PaloAltoNetworksXDR'
XDR_INCIDENT_TYPE_NAME = 'Cortex XDR Incident'

XDR_INCIDENT_FIELDS = {
    "status": {"description": "Current status of the incident: \"new\",\"under_"
                              "investigation\",\"resolved_threat_handled\","
                              "\"resolved_known_issue\",\"resolved_duplicate\","
                              "\"resolved_false_positive\",\"resolved_other\"",
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

XDR_RESOLVED_STATUS_TO_XSOAR = {
    'resolved_threat_handled': 'Resolved',
    'resolved_known_issue': 'Other',
    'resolved_duplicate': 'Duplicate',
    'resolved_false_positive': 'False Positive',
    'resolved_other': 'Other'
}

XSOAR_RESOLVED_STATUS_TO_XDR = {
    'Resolved': 'resolved_threat_handled',
    'Other': 'resolved_other',
    'Duplicate': 'resolved_duplicate',
    'False Positive': 'resolved_false_positive'
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


class Client(BaseClient):

    def __init__(self, base_url: str, headers: dict, timeout: int = 120, proxy: bool = False, verify: bool = False):
        self.timeout = timeout
        super().__init__(base_url=base_url, headers=headers, proxy=proxy, verify=verify)

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
            'alerts_limit': alerts_limit
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
            'update_data': update_data
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
                json_data={},
                timeout=self.timeout
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
                json_data={'request_data': request_data},
                timeout=self.timeout
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
            },
            timeout=self.timeout
        )

    def unisolate_endpoint(self, endpoint_id):
        self._http_request(
            method='POST',
            url_suffix='/endpoints/unisolate',
            json_data={
                'request_data': {
                    'endpoint_id': endpoint_id
                }
            },
            timeout=self.timeout
        )

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

    def blacklist_files(self, hash_list, comment=None):
        request_data: Dict[str, Any] = {"hash_list": hash_list}
        if comment:
            request_data["comment"] = comment

        self._headers['content-type'] = 'application/json'
        reply = self._http_request(
            method='POST',
            url_suffix='/hash_exceptions/blacklist/',
            json_data={'request_data': request_data},
            ok_codes=(200, 201),
            timeout=self.timeout
        )
        return reply.get('reply')

    def whitelist_files(self, hash_list, comment=None):
        request_data: Dict[str, Any] = {"hash_list": hash_list}
        if comment:
            request_data["comment"] = comment

        self._headers['content-type'] = 'application/json'
        reply = self._http_request(
            method='POST',
            url_suffix='/hash_exceptions/whitelist/',
            json_data={'request_data': request_data},
            ok_codes=(201, 200),
            timeout=self.timeout
        )
        return reply.get('reply')

    def quarantine_files(self, endpoint_id_list, file_path, file_hash):
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

        self._headers['content-type'] = 'application/json'
        reply = self._http_request(
            method='POST',
            url_suffix='/endpoints/quarantine/',
            json_data={'request_data': request_data},
            ok_codes=(200, 201),
            timeout=self.timeout
        )

        return reply.get('reply')

    def restore_file(self, file_hash, endpoint_id=None):
        request_data: Dict[str, Any] = {'file_hash': file_hash}
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

    def endpoint_scan(self, endpoint_id_list=None, dist_name=None, gte_first_seen=None, gte_last_seen=None,
                      lte_first_seen=None,
                      lte_last_seen=None, ip_list=None, group_name=None, platform=None, alias=None, isolate=None,
                      hostname: list = None):
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
                'field': 'alias_name',
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

        self._headers['content-type'] = 'application/json'
        reply = self._http_request(
            method='POST',
            url_suffix='/endpoints/scan/',
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

    def retrieve_file(self, endpoint_id_list: list, windows: list, linux: list, macos: list) -> Dict[str, Any]:
        files = {}
        if windows:
            files['windows'] = windows
        if linux:
            files['linux'] = linux
        if macos:
            files['linux'] = macos

        if not windows and not linux and not macos:
            raise ValueError('You should enter at least one path.')

        request_data: Dict[str, Any] = {
            'filters': [
                {
                    'field': 'endpoint_id_list',
                    'operator': 'in',
                    'value': endpoint_id_list
                }
            ],
            'files': files
        }

        reply = self._http_request(
            method='POST',
            url_suffix='/endpoints/file_retrieval/',
            json_data={'request_data': request_data},
            timeout=self.timeout
        )
        return reply.get('reply')

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

    def run_script(self, script_uid, endpoint_ids: list, timeout: int, parameters: Dict[str, Any]) -> Dict[str, Any]:
        filters: list = [{
            'field': 'endpoint_id_list',
            'operator': 'in',
            'value': endpoint_ids
        }]
        request_data: Dict[str, Any] = {'script_uid': script_uid, 'timeout': timeout, 'filters': filters,
                                        'parameters_values': parameters}

        reply = self._http_request(
            method='POST',
            url_suffix='/scripts/run_script/',
            json_data={'request_data': request_data},
            timeout=self.timeout
        )

        return reply.get('reply')

    def get_script_execution_status(self, action_id) -> Dict[str, Any]:
        request_data: Dict[str, Any] = {
            'action_id': action_id
        }

        reply = self._http_request(
            method='POST',
            url_suffix='/scripts/get_script_execution_status/',
            json_data={'request_data': request_data},
            timeout=self.timeout
        )

        return reply.get('reply')

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
            method='POST',
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


def check_if_incident_was_modified_in_xdr(incident_id, last_mirrored_in_time_timestamp, last_modified_incidents_dict):
    if incident_id in last_modified_incidents_dict:  # search the incident in the dict of modified incidents
        incident_modification_time_in_xdr = int(str(last_modified_incidents_dict[incident_id]))

        demisto.debug(f"XDR incident {incident_id}\n"
                      f"modified time:         {incident_modification_time_in_xdr}\n"
                      f"last mirrored in time: {last_mirrored_in_time_timestamp}")

        if incident_modification_time_in_xdr > last_mirrored_in_time_timestamp:  # need to update this incident
            demisto.info(f"Incident '{incident_id}' was modified. performing extra-data request.")
            return True
    else:  # the incident was not modified
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
        last_mirrored_in_timestamp = (last_mirrored_in_time - 120)

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
    raw_incident = client.get_incident_extra_data(incident_id, alerts_limit)

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
    endpoint_context_output = assign_params(**{
        'Hostname': incident.get('hosts', '')
    })

    context_output = {f'{INTEGRATION_CONTEXT_BRAND}.Incident(val.incident_id==obj.incident_id)': incident}
    if account_context_output:
        context_output['Account(val.Username==obj.Username)'] = account_context_output
    if endpoint_context_output:
        context_output['Endpoint(val.Hostname==obj.Hostname)'] = endpoint_context_output

    return (
        '\n'.join(readable_output),
        context_output,
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
        {f'{INTEGRATION_CONTEXT_BRAND}.Endpoint(val.endpoint_id == obj.endpoint_id)': endpoints,
         'Endpoint(val.ID == obj.ID)': return_endpoint_standard_context(endpoints)},
        endpoints
    )


def return_endpoint_standard_context(endpoints):
    endpoints_context_list = []
    for endpoint in endpoints:
        endpoints_context_list.append(assign_params(**{
            "Hostname": (endpoint['host_name'] if endpoint.get('host_name', '') else endpoint.get('endpoint_name')),
            "ID": endpoint.get('endpoint_id'),
            "IPAddress": endpoint.get('ip'),
            "Domain": endpoint.get('domain'),
            "OS": endpoint.get('os_type'),
        }))
    return endpoints_context_list


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


def blacklist_files_command(client, args):
    hash_list = argToList(args.get('hash_list'))
    comment = args.get('comment')

    client.blacklist_files(hash_list=hash_list, comment=comment)
    markdown_data = [{'fileHash': file_hash} for file_hash in hash_list]

    return (
        tableToMarkdown('Blacklist Files', markdown_data, headers=['fileHash'], headerTransform=pascalToSpace),
        {
            f'{INTEGRATION_CONTEXT_BRAND}.blackList.fileHash(val.fileHash == obj.fileHash)': hash_list
        },
        argToList(hash_list)
    )


def whitelist_files_command(client, args):
    hash_list = argToList(args.get('hash_list'))
    comment = args.get('comment')

    client.whitelist_files(hash_list=hash_list, comment=comment)
    markdown_data = [{'fileHash': file_hash} for file_hash in hash_list]
    return (
        tableToMarkdown('Whitelist Files', markdown_data, ['fileHash'], headerTransform=pascalToSpace),
        {
            f'{INTEGRATION_CONTEXT_BRAND}.whiteList.fileHash(val.fileHash == obj.fileHash)': hash_list
        },
        argToList(hash_list)
    )


def quarantine_files_command(client, args):
    endpoint_id_list = argToList(args.get("endpoint_id_list"))
    file_path = args.get("file_path")
    file_hash = args.get("file_hash")

    reply = client.quarantine_files(
        endpoint_id_list=endpoint_id_list,
        file_path=file_path,
        file_hash=file_hash
    )
    output = {
        'endpointIdList': endpoint_id_list,
        'filePath': file_path,
        'fileHash': file_hash,
        'actionId': reply.get("action_id")
    }

    return (
        tableToMarkdown('Quarantine files', output, headers=[*output],
                        headerTransform=pascalToSpace),
        {
            f'{INTEGRATION_CONTEXT_BRAND}.quarantineFiles.actionIds(val.actionId === obj.actionId)': output
        },
        reply
    )


def restore_file_command(client, args):
    file_hash = args.get('file_hash')
    endpoint_id = args.get('endpoint_id')

    reply = client.restore_file(
        file_hash=file_hash,
        endpoint_id=endpoint_id
    )
    action_id = reply.get("action_id")

    return (
        tableToMarkdown('Restore files', {'Action Id': action_id}, ['Action Id']),
        {
            f'{INTEGRATION_CONTEXT_BRAND}.restoredFiles.actionId(val.actionId == obj.actionId)': action_id
        },
        action_id
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

    return (
        tableToMarkdown('Quarantine files', output, headers=[*output], headerTransform=pascalToSpace),
        {
            f'{INTEGRATION_CONTEXT_BRAND}.quarantineFiles.status(val.fileHash === obj.fileHash &&'
            f'val.endpointId === obj.endpointId && val.filePath === obj.filePath)': output
        },
        reply
    )


def endpoint_scan_command(client, args):
    endpoint_id_list = args.get('endpoint_id_list')
    dist_name = args.get('dist_name')
    gte_first_seen = args.get('gte_first_seen')
    gte_last_seen = args.get('gte_last_seen')
    lte_first_seen = args.get('lte_first_seen')
    lte_last_seen = args.get('lte_last_seen')
    ip_list = args.get('ip_list')
    group_name = args.get('group_name')
    platform = args.get('platform')
    alias = args.get('alias')
    isolate = args.get('isolate')
    hostname = argToList(args.get('hostname'))

    reply = client.endpoint_scan(
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
        hostname=hostname
    )

    action_id = reply.get("action_id")

    return (
        tableToMarkdown('Endpoint scan', {'Action Id': action_id}, ['Action Id']),
        {
            f'{INTEGRATION_CONTEXT_BRAND}.endpointScan.actionId(val.actionId == obj.actionId)': action_id
        },
        reply
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


def drop_field_underscore(section):
    section_copy = section.copy()
    for field in section_copy.keys():
        if '_' in field:
            section[field.replace('_', '')] = section.get(field)


def reformat_sublist_fields(sublist):
    for section in sublist:
        drop_field_underscore(section)


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
                'closeNotes': incident_data.get('resolve_comment')
            },
            'ContentsFormat': EntryFormat.JSON
        }
        incident_data['closeReason'] = XDR_RESOLVED_STATUS_TO_XSOAR.get(incident_data.get("status"))
        incident_data['closeNotes'] = incident_data.get('resolve_comment')

        if incident_data.get('status') == 'resolved_known_issue':
            closing_entry['Contents']['closeNotes'] = 'Known Issue.\n' + incident_data['closeNotes']
            incident_data['closeNotes'] = 'Known Issue.\n' + incident_data['closeNotes']

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
        incident_data = get_incident_extra_data_command(client, {"incident_id": remote_args.remote_incident_id,
                                                                 "alerts_limit": 1000,
                                                                 "return_only_updated_incident": True,
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


def handle_outgoing_issue_closure(update_args, inc_status):
    if inc_status == 2:
        update_args['status'] = XSOAR_RESOLVED_STATUS_TO_XDR.get(update_args.get('closeReason'))
        demisto.debug(f"Closing Remote XDR incident with status {update_args['status']}")
        update_args['resolve_comment'] = update_args.get('closeNotes')


def get_update_args(delta, inc_status):
    """Change the updated field names to fit the update command"""
    update_args = delta
    handle_outgoing_incident_owner_sync(update_args)
    handle_user_unassignment(update_args)
    handle_outgoing_issue_closure(update_args, inc_status)
    return update_args


def update_remote_system_command(client, args):
    remote_args = UpdateRemoteSystemArgs(args)
    try:
        if remote_args.delta and remote_args.incident_changed:
            demisto.debug(f'Got the following delta keys {str(list(remote_args.delta.keys()))} to update XDR '
                          f'incident {remote_args.remote_incident_id}')
            update_args = get_update_args(remote_args.delta, remote_args.inc_status)

            update_args['incident_id'] = remote_args.remote_incident_id
            demisto.debug(f'Sending incident with remote ID [{remote_args.remote_incident_id}] to XDR\n')
            update_incident_command(client, update_args)

        else:
            demisto.debug(f'Skipping updating remote incident fields [{remote_args.remote_incident_id}] '
                          f'as it is not new nor changed')

        return remote_args.remote_incident_id

    except Exception as e:
        demisto.debug(f"Error in XDR outgoing mirror for incident {remote_args.remote_incident_id} \n"
                      f"Error message: {str(e)}")

        return remote_args.remote_incident_id


def fetch_incidents(client, first_fetch_time, integration_instance, last_run: dict = None, max_fetch: int = 10):
    # Get the last fetch time, if exists
    last_fetch = last_run.get('time') if isinstance(last_run, dict) else None
    incidents_from_previous_run = last_run.get('incidents_from_previous_run', []) if isinstance(last_run,
                                                                                                dict) else []
    # Handle first time fetch, fetch incidents retroactively
    if last_fetch is None:
        last_fetch, _ = parse_date_range(first_fetch_time, to_timestamp=True)

    incidents = []
    if incidents_from_previous_run:
        raw_incidents = incidents_from_previous_run
    else:
        raw_incidents = client.get_incidents(gte_creation_time_milliseconds=last_fetch,
                                             limit=max_fetch, sort_by_creation_time='asc')

    # save the last 100 modified incidents to the integration context - for mirroring purposes
    client.save_modified_incidents_to_integration_context()

    # maintain a list of non created incidents in a case of a rate limit exception
    non_created_incidents: list = raw_incidents.copy()
    next_run = dict()
    try:
        for raw_incident in raw_incidents:
            incident_id = raw_incident.get('incident_id')

            incident_data = get_incident_extra_data_command(client, {"incident_id": incident_id,
                                                                     "alerts_limit": 1000})[2].get('incident')

            sort_all_list_incident_fields(incident_data)

            incident_data['mirror_direction'] = MIRROR_DIRECTION.get(demisto.params().get('mirror_direction', 'None'),
                                                                     None)
            incident_data['mirror_instance'] = integration_instance
            incident_data['last_mirrored_in'] = int(datetime.now().timestamp() * 1000)

            description = raw_incident.get('description')
            occurred = timestamp_to_datestring(raw_incident['creation_time'], TIME_FORMAT + 'Z')
            incident = {
                'name': f'#{incident_id} - {description}',
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


def delete_endpoints_command(client: Client, args: Dict[str, str]) -> Tuple[str, Any, Any]:
    endpoint_id_list: list = argToList(args.get('endpoint_ids'))

    client.delete_endpoints(endpoint_id_list)

    return f'Successfully deleted the following endpoints: {args.get("endpoint_ids")}', None, None


def get_policy_command(client: Client, args: Dict[str, str]) -> Tuple[str, dict, Any]:
    endpoint_id = args.get('endpoint_id')

    reply = client.get_policy(endpoint_id)
    context = {'endpoint_id': endpoint_id,
               'policy_name': reply.get('policy_name')}

    return (
        f'The policy name of endpoint: {endpoint_id} is: {reply.get("policy_name")}.',
        {
            f'{INTEGRATION_CONTEXT_BRAND}.Policy(val.endpoint_id == obj.endpoint_id)': context
        },
        reply
    )


def get_endpoint_device_control_violations_command(client: Client, args: Dict[str, str]) -> Tuple[str, dict, Any]:
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
            f'{INTEGRATION_CONTEXT_BRAND}.EndpointViolations(val.violation_id==obj.violation_id)': violations
        },
        reply
    )


def retrieve_files_command(client: Client, args: Dict[str, str]) -> Tuple[str, dict, Any]:
    endpoint_id_list: list = argToList(args.get('endpoint_ids'))
    windows: list = argToList(args.get('windows_file_paths'))
    linux: list = argToList(args.get('linux_file_paths'))
    macos: list = argToList(args.get('mac_file_paths'))

    reply = client.retrieve_file(
        endpoint_id_list=endpoint_id_list,
        windows=windows,
        linux=linux,
        macos=macos
    )
    result = {'action_id': reply.get('action_id')}
    return (
        tableToMarkdown(name='Retrieve files', t=result, headerTransform=string_to_table_header),
        {
            f'{INTEGRATION_CONTEXT_BRAND}.RetrievedFiles(val.action_id == obj.action_id)': result
        },
        reply
    )


def retrieve_file_details_command(client: Client, args):
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
                file = client.get_file(file_link=link)
                file_results.append(fileResult(filename=f'{endpoint}_{retrived_files_count}.zip', data=file))
            result.append(obj)

    hr = f'### Action id : {args.get("action_id", "")} \n Retrieved {retrived_files_count} files from ' \
         f'{endpoints_count} endpoints. \n To get the exact action status run the xdr-action-status-get command'

    return_entry = {'Type': entryTypes['note'],
                    'ContentsFormat': formats['json'],
                    'Contents': raw_result,
                    'HumanReadable': hr,
                    'ReadableContentsFormat': formats['markdown'],
                    'EntryContext': {}
                    }
    return return_entry, file_results


def get_scripts_command(client: Client, args: Dict[str, str]) -> Tuple[str, dict, Any]:
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
            f'{INTEGRATION_CONTEXT_BRAND}.Scripts(val.script_uid == obj.script_uid)': scripts
        },
        result
    )


def get_script_metadata_command(client: Client, args: Dict[str, str]) -> Tuple[str, dict, Any]:
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
            f'{INTEGRATION_CONTEXT_BRAND}.ScriptMetadata(val.script_uid == obj.script_uid)': reply
        },
        reply
    )


def get_script_code_command(client: Client, args: Dict[str, str]) -> Tuple[str, dict, Any]:
    script_uid = args.get('script_uid')

    reply = client.get_script_code(script_uid)
    context = {
        'script_uid': script_uid,
        'code': reply
    }

    return (
        f'### Script code: \n ``` {str(reply)} ```',
        {
            f'{INTEGRATION_CONTEXT_BRAND}.ScriptCode(val.script_uid == obj.script_uid)': context
        },
        reply
    )


def action_status_get_command(client: Client, args) -> Tuple[str, Any, Any]:
    action_id_list = argToList(args.get('action_id', ''))
    action_id_list = [arg_to_int(arg=item, arg_name=str(item)) for item in action_id_list]

    result = []
    for action_id in action_id_list:
        data = client.action_status_get(action_id)

        for endpoint_id, status in data.items():
            result.append({
                'action_id': action_id,
                'endpoint_id': endpoint_id,
                'status': status
            })

    return (
        tableToMarkdown(name='Get Action Status', t=result, removeNull=True),
        {
            f'{INTEGRATION_CONTEXT_BRAND}.GetActionStatus(val.action_id == obj.action_id)': result
        },
        result
    )


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
    try:
        timeout = int(demisto.params().get('timeout', 120))
    except ValueError as e:
        demisto.debug(f'Failed casting timeout parameter to int, falling back to 120 - {e}')
        timeout = 120
    try:
        max_fetch = int(demisto.params().get('max_fetch', 10))
    except ValueError as e:
        demisto.debug(f'Failed casting max fetch parameter to int, falling back to 10 - {e}')
        max_fetch = 10

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
        headers=headers,
        timeout=timeout
    )

    args = demisto.args()

    try:
        if demisto.command() == 'test-module':
            client.test_module(first_fetch_time)
            demisto.results('ok')

        elif demisto.command() == 'fetch-incidents':
            integration_instance = demisto.integrationInstance()
            next_run, incidents = fetch_incidents(client, first_fetch_time, integration_instance, demisto.getLastRun(),
                                                  max_fetch)
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif demisto.command() == 'xdr-get-incidents':
            return_outputs(*get_incidents_command(client, args))

        elif demisto.command() == 'xdr-get-incident-extra-data':
            return_outputs(*get_incident_extra_data_command(client, args))

        elif demisto.command() == 'xdr-update-incident':
            return_outputs(*update_incident_command(client, args))

        elif demisto.command() == 'xdr-get-endpoints':
            return_outputs(*get_endpoints_command(client, args))

        elif demisto.command() == 'xdr-insert-parsed-alert':
            return_outputs(*insert_parsed_alert_command(client, args))

        elif demisto.command() == 'xdr-insert-cef-alerts':
            return_outputs(*insert_cef_alerts_command(client, args))

        elif demisto.command() == 'xdr-isolate-endpoint':
            return_outputs(*isolate_endpoint_command(client, args))

        elif demisto.command() == 'xdr-unisolate-endpoint':
            return_outputs(*unisolate_endpoint_command(client, args))

        elif demisto.command() == 'xdr-get-distribution-url':
            return_outputs(*get_distribution_url_command(client, args))

        elif demisto.command() == 'xdr-get-create-distribution-status':
            return_outputs(*get_distribution_status_command(client, args))

        elif demisto.command() == 'xdr-get-distribution-versions':
            return_outputs(*get_distribution_versions_command(client))

        elif demisto.command() == 'xdr-create-distribution':
            return_outputs(*create_distribution_command(client, args))

        elif demisto.command() == 'xdr-get-audit-management-logs':
            return_outputs(*get_audit_management_logs_command(client, args))

        elif demisto.command() == 'xdr-get-audit-agent-reports':
            return_outputs(*get_audit_agent_reports_command(client, args))

        elif demisto.command() == 'xdr-blacklist-files':
            return_outputs(*blacklist_files_command(client, args))

        elif demisto.command() == 'xdr-whitelist-files':
            return_outputs(*whitelist_files_command(client, args))

        elif demisto.command() == 'xdr-quarantine-files':
            return_outputs(*quarantine_files_command(client, args))

        elif demisto.command() == 'xdr-get-quarantine-status':
            return_outputs(*get_quarantine_status_command(client, args))

        elif demisto.command() == 'xdr-restore-file':
            return_outputs(*restore_file_command(client, args))

        elif demisto.command() == 'xdr-endpoint-scan':
            return_outputs(*endpoint_scan_command(client, args))

        elif demisto.command() == 'get-mapping-fields':
            return_results(get_mapping_fields_command())

        elif demisto.command() == 'get-remote-data':
            return_results(get_remote_data_command(client, args))

        elif demisto.command() == 'update-remote-system':
            return_results(update_remote_system_command(client, args))

        elif demisto.command() == 'xdr-delete-endpoints':
            return_outputs(*delete_endpoints_command(client, args))

        elif demisto.command() == 'xdr-get-policy':
            return_outputs(*get_policy_command(client, args))

        elif demisto.command() == 'xdr-get-endpoint-device-control-violations':
            return_outputs(*get_endpoint_device_control_violations_command(client, args))

        elif demisto.command() == 'xdr-retrieve-files':
            return_outputs(*retrieve_files_command(client, args))

        elif demisto.command() == 'xdr-retrieve-file-details':
            return_entry, file_results = retrieve_file_details_command(client, args)
            demisto.results(return_entry)
            if file_results:
                demisto.results(file_results)

        elif demisto.command() == 'xdr-get-scripts':
            return_outputs(*get_scripts_command(client, args))

        elif demisto.command() == 'xdr-get-script-metadata':
            return_outputs(*get_script_metadata_command(client, args))

        elif demisto.command() == 'xdr-get-script-code':
            return_outputs(*get_script_code_command(client, args))

        elif demisto.command() == 'xdr-action-status-get':
            return_outputs(*action_status_get_command(client, args))

        elif demisto.command() == 'get-modified-remote-data':
            return_results(get_modified_remote_data_command(client, demisto.args()))

    except Exception as err:
        if demisto.command() == 'fetch-incidents':
            LOG(str(err))
            raise

        demisto.error(traceback.format_exc())
        return_error(str(err))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
