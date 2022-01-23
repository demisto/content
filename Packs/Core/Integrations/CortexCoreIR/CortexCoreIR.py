import copy
import hashlib
import secrets
import string
from operator import itemgetter
from typing import Tuple, Callable

import demistomock as demisto  # noqa: F401
import urllib3
from CommonServerPython import *  # noqa: F401

# Disable insecure warnings
urllib3.disable_warnings()

TIME_FORMAT = "%Y-%m-%dT%H:%M:%S"
NONCE_LENGTH = 64
API_KEY_LENGTH = 128

INTEGRATION_CONTEXT_BRAND = 'PaloAltoNetworksCore'
INTEGRATION_NAME = 'Cortex Core - IR'


XSOAR_RESOLVED_STATUS_TO_Core = {
    'Other': 'resolved_other',
    'Duplicate': 'resolved_duplicate',
    'False Positive': 'resolved_false_positive',
    'Resolved': 'resolved_true_positive',
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


class Client(BaseClient):

    def __init__(self, base_url: str, headers: dict, timeout: int = 120, proxy: bool = False, verify: bool = False):
        self.timeout = timeout
        super().__init__(base_url=base_url, headers=headers, proxy=proxy, verify=verify)

    def test_module(self, first_fetch_time):
        """
            Performs basic get request to get item samples
        """
        last_one_day, _ = parse_date_range(first_fetch_time, TIME_FORMAT)
        try:
            self.get_incidents(lte_creation_time=last_one_day, limit=1)
        except Exception as err:
            if 'API request Unauthorized' in str(err):
                # this error is received from the Core server when the client clock is not in sync to the server
                raise DemistoException(f'{str(err)} please validate that your both '
                                       f'XSOAR and Core server clocks are in sync')
            else:
                raise

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

    def blocklist_files(self, hash_list, comment=None, incident_id=None):
        request_data: Dict[str, Any] = {"hash_list": hash_list}
        if comment:
            request_data["comment"] = comment
        if incident_id:
            request_data['incident_id'] = incident_id

        self._headers['content-type'] = 'application/json'
        reply = self._http_request(
            method='POST',
            url_suffix='/hash_exceptions/blocklist/',
            json_data={'request_data': request_data},
            ok_codes=(200, 201, 500,),
            timeout=self.timeout
        )
        return reply.get('reply')

    def allowlist_files(self, hash_list, comment=None, incident_id=None):
        request_data: Dict[str, Any] = {"hash_list": hash_list}
        if comment:
            request_data["comment"] = comment
        if incident_id:
            request_data['incident_id'] = incident_id

        self._headers['content-type'] = 'application/json'
        reply = self._http_request(
            method='POST',
            url_suffix='/hash_exceptions/allowlist/',
            json_data={'request_data': request_data},
            ok_codes=(201, 200),
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

    def report_incorrect_wildfire(self, file_hash: str, new_verdict: int, reason: str, email: str):
        request_data: Dict[str, Any] = {
            "hash": file_hash,
            "new_verdict": new_verdict,
            "reason": reason,
            "email": email,
        }
        reply = self._http_request(
            method='POST',
            url_suffix='/wildfire/report_as_incorrect/',
            json_data={'request_data': request_data},
            timeout=self.timeout
        )
        return reply


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
    if len(process_context.keys()) == 1 and 'Hostname' in process_context.keys():
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
        arg=args.get('page', '0'),
        arg_name='Failed to parse "page". Must be a number.',
        required=True
    )

    limit = arg_to_int(
        arg=args.get('limit', '30'),
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
            sort_by_last_seen=sort_by_last_seen,
            status=status
        )

    standard_endpoints = generate_endpoint_by_contex_standard(endpoints, False)
    endpoint_context_list = []
    for endpoint in standard_endpoints:
        endpoint_context = endpoint.to_context().get(Common.Endpoint.CONTEXT_PATH)
        endpoint_context_list.append(endpoint_context)

    context = {
        f'{INTEGRATION_CONTEXT_BRAND}.Endpoint(val.endpoint_id == obj.endpoint_id)': endpoints,
        Common.Endpoint.CONTEXT_PATH: endpoint_context_list
    }
    account_context = create_account_context(endpoints)
    if account_context:
        context[Common.Account.CONTEXT_PATH] = account_context

    return CommandResults(
        readable_output=tableToMarkdown('Endpoints', endpoints),
        outputs=context,
        raw_response=endpoints
    )


def convert_os_to_standard(endpoint_os):
    os_type = ''
    endpoint_os = endpoint_os.lower()
    if 'windows' in endpoint_os:
        os_type = "Windows"
    elif 'linux' in endpoint_os:
        os_type = "Linux"
    elif 'macos' in endpoint_os:
        os_type = "Macos"
    elif 'android' in endpoint_os:
        os_type = "Android"
    return os_type


def get_endpoint_properties(single_endpoint):
    status = 'Online' if single_endpoint.get('endpoint_status', '').lower() == 'connected' else 'Offline'
    is_isolated = 'No' if 'unisolated' in single_endpoint.get('is_isolated', '').lower() else 'Yes'
    hostname = single_endpoint['host_name'] if single_endpoint.get('host_name') else single_endpoint.get(
        'endpoint_name')
    ip = single_endpoint.get('ip')
    return status, is_isolated, hostname, ip


def generate_endpoint_by_contex_standard(endpoints, ip_as_string):
    standard_endpoints = []
    for single_endpoint in endpoints:
        status, is_isolated, hostname, ip = get_endpoint_properties(single_endpoint)
        # in the `core-get-endpoints` command the ip is returned as list, in order not to break bc we will keep it
        # in the `endpoint` command we use the standard
        if ip_as_string and isinstance(ip, list):
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
            vendor=INTEGRATION_NAME)

        standard_endpoints.append(endpoint)
    return standard_endpoints


def endpoint_command(client, args):
    endpoint_id_list = argToList(args.get('id'))
    endpoint_ip_list = argToList(args.get('ip'))
    endpoint_hostname_list = argToList(args.get('hostname'))

    endpoints = client.get_endpoints(
        endpoint_id_list=endpoint_id_list,
        ip_list=endpoint_ip_list,
        hostname=endpoint_hostname_list,
    )
    standard_endpoints = generate_endpoint_by_contex_standard(endpoints, True)
    command_results = []
    if standard_endpoints:
        for endpoint in standard_endpoints:
            endpoint_context = endpoint.to_context().get(Common.Endpoint.CONTEXT_PATH)
            hr = tableToMarkdown('Cortex Core Endpoint', endpoint_context)

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


def isolate_endpoint_command(client, args):
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
                outputs={f'{INTEGRATION_CONTEXT_BRAND}.Isolation.endpoint_id(val.endpoint_id == obj.endpoint_id)': endpoint_id}
            )
    if is_isolated == 'AGENT_PENDING_ISOLATION_CANCELLATION':
        raise ValueError(
            f'Error: Endpoint {endpoint_id} is pending isolation cancellation and therefore can not be isolated.'
        )
    result = client.isolate_endpoint(endpoint_id=endpoint_id, incident_id=incident_id)

    return CommandResults(
        readable_output=f'The isolation request has been submitted successfully on Endpoint {endpoint_id}.\n',
        outputs={f'{INTEGRATION_CONTEXT_BRAND}.Isolation.endpoint_id(val.endpoint_id == obj.endpoint_id)': endpoint_id},
        raw_response=result
    )


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
                    f'{INTEGRATION_CONTEXT_BRAND}.UnIsolation.endpoint_id(val.endpoint_id == obj.endpoint_id)'
                    f'': endpoint_id}
            )
    if is_isolated == 'AGENT_PENDING_ISOLATION':
        raise ValueError(
            f'Error: Endpoint {endpoint_id} is pending isolation and therefore can not be un-isolated.'
        )
    result = client.unisolate_endpoint(endpoint_id=endpoint_id, incident_id=incident_id)

    return CommandResults(
        readable_output=f'The un-isolation request has been submitted successfully on Endpoint {endpoint_id}.\n',
        outputs={f'{INTEGRATION_CONTEXT_BRAND}.UnIsolation.endpoint_id(val.endpoint_id == obj.endpoint_id)': endpoint_id},
        raw_response=result
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
    integration_context = {f'{INTEGRATION_CONTEXT_BRAND}.AuditAgentReports': audit_logs}
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

    url = client.get_distribution_url(distribution_id, package_type)

    return (
        f'[Distribution URL]({url})',
        {
            'PaloAltoNetworksCore.Distribution(val.id == obj.id)': {
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


def blocklist_files_command(client, args):
    hash_list = argToList(args.get('hash_list'))
    comment = args.get('comment')
    incident_id = arg_to_number(args.get('incident_id'))

    res = client.blocklist_files(hash_list=hash_list, comment=comment, incident_id=incident_id)
    if isinstance(res, dict) and res.get('err_extra') != "All hashes have already been added to the allow or block list":
        raise ValueError(res)
    markdown_data = [{'fileHash': file_hash} for file_hash in hash_list]

    return (
        tableToMarkdown('Blacklist Files', markdown_data, headers=['fileHash'], headerTransform=pascalToSpace),
        {
            f'{INTEGRATION_CONTEXT_BRAND}.blackList.fileHash(val.fileHash == obj.fileHash)': hash_list
        },
        argToList(hash_list)
    )


def allowlist_files_command(client, args):
    hash_list = argToList(args.get('hash_list'))
    comment = args.get('comment')
    incident_id = arg_to_number(args.get('incident_id'))

    client.allowlist_files(hash_list=hash_list, comment=comment, incident_id=incident_id)
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
    incident_id = arg_to_number(args.get('incident_id'))

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
        readable_output=tableToMarkdown('Quarantine files', output, headers=[*output], headerTransform=pascalToSpace),
        outputs={f'{INTEGRATION_CONTEXT_BRAND}.quarantineFiles.actionIds(val.actionId === obj.actionId)': output},
        raw_response=reply
    )


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
        outputs={f'{INTEGRATION_CONTEXT_BRAND}.restoredFiles.actionId(val.actionId == obj.actionId)': action_id},
        raw_response=reply
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
        outputs={f'{INTEGRATION_CONTEXT_BRAND}.quarantineFiles.status(val.fileHash === obj.fileHash &&'
                 f'val.endpointId === obj.endpointId && val.filePath === obj.filePath)': output},
        raw_response=reply
    )


def endpoint_scan_command(client, args):
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
        outputs={f'{INTEGRATION_CONTEXT_BRAND}.endpointScan(val.actionId == obj.actionId)': context},
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
        outputs={f'{INTEGRATION_CONTEXT_BRAND}.endpointScan(val.actionId == obj.actionId)': context},
        raw_response=reply
    )


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
        if endpoint_id_list or dist_name or gte_first_seen or gte_last_seen or lte_first_seen or lte_last_seen \
                or ip_list or group_name or platform or alias or hostname:
            raise Exception(err_msg)
    else:
        if not endpoint_id_list and not dist_name and not gte_first_seen and not gte_last_seen \
                and not lte_first_seen and not lte_last_seen and not ip_list and not group_name and not platform \
                and not alias and not hostname:
            raise Exception(err_msg)


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
    for field in section_copy.keys():
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


def handle_outgoing_issue_closure(update_args, inc_status):
    if inc_status == 2:
        update_args['status'] = XSOAR_RESOLVED_STATUS_TO_Core.get(update_args.get('closeReason', 'Other'))
        demisto.debug(f"Closing Remote Core incident with status {update_args['status']}")
        update_args['resolve_comment'] = update_args.get('closeNotes', '')


def get_update_args(delta, inc_status):
    """Change the updated field names to fit the update command"""
    update_args = delta
    handle_outgoing_incident_owner_sync(update_args)
    handle_user_unassignment(update_args)
    if update_args.get('closingUserId'):
        handle_outgoing_issue_closure(update_args, inc_status)
    return update_args


def update_remote_system_command(client, args):
    remote_args = UpdateRemoteSystemArgs(args)

    if remote_args.delta:
        demisto.debug(f'Got the following delta keys {str(list(remote_args.delta.keys()))} to update Core '
                      f'incident {remote_args.remote_incident_id}')
    try:
        if remote_args.incident_changed:
            update_args = get_update_args(remote_args.delta, remote_args.inc_status)

            update_args['incident_id'] = remote_args.remote_incident_id
            demisto.debug(f'Sending incident with remote ID [{remote_args.remote_incident_id}] to Core\n')
            update_incident_command(client, update_args)

        else:
            demisto.debug(f'Skipping updating remote incident fields [{remote_args.remote_incident_id}] '
                          f'as it is not new nor changed')

        return remote_args.remote_incident_id

    except Exception as e:
        demisto.debug(f"Error in Core outgoing mirror for incident {remote_args.remote_incident_id} \n"
                      f"Error message: {str(e)}")

        return remote_args.remote_incident_id


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


def retrieve_files_command(client: Client, args: Dict[str, str]) -> CommandResults:
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
        outputs={f'{INTEGRATION_CONTEXT_BRAND}.RetrievedFiles(val.action_id == obj.action_id)': result},
        raw_response=reply
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
         f'{endpoints_count} endpoints. \n To get the exact action status run the core-action-status-get command'

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


def action_status_get_command(client: Client, args) -> CommandResults:
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

    return CommandResults(
        readable_output=tableToMarkdown(name='Get Action Status', t=result, removeNull=True),
        outputs={f'{INTEGRATION_CONTEXT_BRAND}.GetActionStatus(val.action_id == obj.action_id)': result},
        raw_response=result
    )


def run_script_command(client: Client, args: Dict) -> CommandResults:
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
    response = client.run_script(script_uid, endpoint_ids, parameters, timeout, incident_id=incident_id)
    reply = response.get('reply')
    return CommandResults(
        readable_output=tableToMarkdown('Run Script', reply),
        outputs_prefix=f'{INTEGRATION_CONTEXT_BRAND}.ScriptRun',
        outputs_key_field='action_id',
        outputs=reply,
        raw_response=response,
    )


def run_snippet_code_script_command(client: Client, args: Dict) -> CommandResults:
    snippet_code = args.get('snippet_code')
    endpoint_ids = argToList(args.get('endpoint_ids'))
    incident_id = arg_to_number(args.get('incident_id'))
    response = client.run_snippet_code_script(snippet_code=snippet_code, endpoint_ids=endpoint_ids, incident_id=incident_id)
    reply = response.get('reply')
    return CommandResults(
        readable_output=tableToMarkdown('Run Snippet Code Script', reply),
        outputs_prefix=f'{INTEGRATION_CONTEXT_BRAND}.ScriptRun',
        outputs_key_field='action_id',
        outputs=reply,
        raw_response=reply,
    )


def get_script_execution_status_command(client: Client, args: Dict) -> List[CommandResults]:
    action_ids = argToList(args.get('action_id', ''))
    command_results = []
    for action_id in action_ids:
        response = client.get_script_execution_status(action_id)
        reply = response.get('reply')
        reply['action_id'] = int(action_id)
        command_results.append(CommandResults(
            readable_output=tableToMarkdown(f'Script Execution Status - {action_id}', reply),
            outputs_prefix=f'{INTEGRATION_CONTEXT_BRAND}.ScriptStatus',
            outputs_key_field='action_id',
            outputs=reply,
            raw_response=response,
        ))
    return command_results


def get_script_execution_results_command(client: Client, args: Dict) -> List[CommandResults]:
    action_ids = argToList(args.get('action_id', ''))
    command_results = []
    for action_id in action_ids:
        response = client.get_script_execution_results(action_id)
        results = response.get('reply', {}).get('results')
        context = {
            'action_id': int(action_id),
            'results': results,
        }
        command_results.append(CommandResults(
            readable_output=tableToMarkdown(f'Script Execution Results - {action_id}', results),
            outputs_prefix=f'{INTEGRATION_CONTEXT_BRAND}.ScriptResult',
            outputs_key_field='action_id',
            outputs=context,
            raw_response=response,
        ))
    return command_results


def get_script_execution_result_files_command(client: Client, args: Dict) -> Dict:
    action_id = args.get('action_id', '')
    endpoint_id = args.get('endpoint_id')
    file_response = client.get_script_execution_result_files(action_id, endpoint_id)
    try:
        filename = file_response.headers.get('Content-Disposition').split('attachment; filename=')[1]
    except Exception as e:
        demisto.debug(f'Failed extracting filename from response headers - [{str(e)}]')
        filename = action_id + '.zip'
    return fileResult(filename, file_response.content)


def run_script_execute_commands_command(client: Client, args: Dict) -> CommandResults:
    endpoint_ids = argToList(args.get('endpoint_ids'))
    incident_id = arg_to_number(args.get('incident_id'))
    timeout = arg_to_number(args.get('timeout', 600)) or 600
    parameters = {'commands_list': argToList(args.get('commands'))}
    response = client.run_script('a6f7683c8e217d85bd3c398f0d3fb6bf', endpoint_ids, parameters, timeout, incident_id)
    reply = response.get('reply')
    return CommandResults(
        readable_output=tableToMarkdown('Run Script Execute Commands', reply),
        outputs_prefix=f'{INTEGRATION_CONTEXT_BRAND}.ScriptRun',
        outputs_key_field='action_id',
        outputs=reply,
        raw_response=reply,
    )


def run_script_delete_file_command(client: Client, args: Dict) -> List[CommandResults]:
    endpoint_ids = argToList(args.get('endpoint_ids'))
    incident_id = arg_to_number(args.get('incident_id'))
    timeout = arg_to_number(args.get('timeout', 600)) or 600
    file_paths = argToList(args.get('file_path'))
    all_files_response = []
    for file_path in file_paths:
        parameters = {'file_path': file_path}
        response = client.run_script('548023b6e4a01ec51a495ba6e5d2a15d', endpoint_ids, parameters, timeout, incident_id)
        reply = response.get('reply')
        all_files_response.append(CommandResults(
            readable_output=tableToMarkdown(f'Run Script Delete File on {file_path}', reply),
            outputs_prefix=f'{INTEGRATION_CONTEXT_BRAND}.ScriptRun',
            outputs_key_field='action_id',
            outputs=reply,
            raw_response=reply,
        ))
    return all_files_response


def run_script_file_exists_command(client: Client, args: Dict) -> List[CommandResults]:
    endpoint_ids = argToList(args.get('endpoint_ids'))
    incident_id = arg_to_number(args.get('incident_id'))
    timeout = arg_to_number(args.get('timeout', 600)) or 600
    file_paths = argToList(args.get('file_path'))
    all_files_response = []
    for file_path in file_paths:
        parameters = {'path': file_path}
        response = client.run_script('414763381b5bfb7b05796c9fe690df46', endpoint_ids, parameters, timeout, incident_id)
        reply = response.get('reply')
        all_files_response.append(CommandResults(
            readable_output=tableToMarkdown(f'Run Script File Exists on {file_path}', reply),
            outputs_prefix=f'{INTEGRATION_CONTEXT_BRAND}.ScriptRun',
            outputs_key_field='action_id',
            outputs=reply,
            raw_response=reply,
        ))
    return all_files_response


def run_script_kill_process_command(client: Client, args: Dict) -> List[CommandResults]:
    endpoint_ids = argToList(args.get('endpoint_ids'))
    incident_id = arg_to_number(args.get('incident_id'))
    timeout = arg_to_number(args.get('timeout', 600)) or 600
    processes_names = argToList(args.get('process_name'))
    all_processes_response = []
    for process_name in processes_names:
        parameters = {'process_name': process_name}
        response = client.run_script('fd0a544a99a9421222b4f57a11839481', endpoint_ids, parameters, timeout, incident_id)
        reply = response.get('reply')
        all_processes_response.append(CommandResults(
            readable_output=tableToMarkdown(f'Run Script Kill Process on {process_name}', reply),
            outputs_prefix=f'{INTEGRATION_CONTEXT_BRAND}.ScriptRun',
            outputs_key_field='action_id',
            outputs=reply,
            raw_response=reply,
        ))

    return all_processes_response


def report_incorrect_wildfire_command(client: Client, args: Dict) -> CommandResults:
    file_hash = args.get('file_hash')
    reason = args.get('reason')
    email = args.get('email')
    new_verdict = arg_to_int(
        arg=args.get('new_verdict'),
        arg_name='Failed to parse "new_verdict". Must be a number.',
        required=True
    )

    response = client.report_incorrect_wildfire(file_hash, new_verdict, reason, email)
    reply = response.get('reply')
    return CommandResults(
        readable_output=tableToMarkdown(f'Reported incorrect WildFire on {hash}', reply),
        outputs_prefix=f'{INTEGRATION_CONTEXT_BRAND}.WildFire',
        outputs=reply,
        raw_response=response,
    )


def run_polling_command(client: Client,
                        args: dict,
                        cmd: str,
                        command_function: Callable,
                        command_decision_field: str,
                        results_function: Callable,
                        polling_field: str,
                        polling_value: List,
                        stop_polling: bool = False) -> CommandResults:
    """
    args: demito args
    cmd: the command to schedule by after the current command
    command_function: the function which is runs the actual command
    command_decision_field: the field in the response based on it what the command status and if the command occurred
    results_function: the function which we are polling on and retrieves the status of the command_function
    polling_field: the field which from the result of the results_function which we are interested in its value
    polling_value: list of values of the polling_field we want to check
    stop_polling: yes - polling_value is stopping, not - polling_value not stopping
    """

    ScheduledCommand.raise_error_if_not_supported()
    interval_in_secs = int(args.get('interval_in_seconds', 60))
    if command_decision_field not in args:
        # create new command run
        command_results = command_function(client, args)
        if isinstance(command_results, CommandResults):
            outputs = [command_results.raw_response] if command_results.raw_response else []
        else:
            outputs = [c.raw_response for c in command_results]
        command_decision_values = [o.get(command_decision_field) for o in outputs] if outputs else []
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
                timeout_in_seconds=600)
            if isinstance(command_results, list):
                command_results = command_results[0]
            command_results.scheduled_command = scheduled_command
            return command_results
        else:
            if command_results.readable_output:
                demisto.error(f"{command_results.readable_output}")
            else:
                demisto.error(f"Command {command_function} didn't succeeded, returned "
                              f"{command_decision_field} = {outputs.get(command_decision_field)}")
            return command_results
    # get polling result
    command_results = results_function(client, args)
    outputs = command_results.raw_response
    result = outputs.get(polling_field) if isinstance(outputs, dict) else outputs[0].get(polling_field)
    cond = result not in polling_value if stop_polling else result in polling_value
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
            timeout_in_seconds=600)

        # result with scheduled_command only - no update to the war room
        command_results = CommandResults(scheduled_command=scheduled_command,
                                         readable_output=f"Polling again because {polling_field} = {result}")
    return command_results


def main():
    """
    Executes an integration command
    """
    command = demisto.command()
    LOG(f'Command being called is {command}')

    args = demisto.args()

    api_key = demisto.params().get('apikey') if command != "core-report-incorrect-wildfire" else demisto.args().get('master_key')
    api_key_id = demisto.params().get('apikey_id')
    base_url = urljoin(demisto.params().get('url'), '/public_api/v1')
    proxy = demisto.params().get('proxy')
    verify_cert = not demisto.params().get('insecure', False)

    try:
        timeout = int(demisto.params().get('timeout', 120))
    except ValueError as e:
        demisto.debug(f'Failed casting timeout parameter to int, falling back to 120 - {e}')
        timeout = 120

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

    try:
        if command == 'test-module':
            client.test_module('3 days')
            demisto.results('ok')

        elif command == 'core-get-endpoints':
            return_results(get_endpoints_command(client, args))

        elif command == 'core-isolate-endpoint':
            polling_args = {
                **args,
                "endpoint_id_list": args.get('endpoint_id')
            }
            return_results(run_polling_command(client=client,
                                               args=polling_args,
                                               cmd="core-isolate-endpoint",
                                               command_function=isolate_endpoint_command,
                                               command_decision_field="action_id",
                                               results_function=get_endpoints_command,
                                               polling_field="is_isolated",
                                               polling_value=["AGENT_ISOLATED"],
                                               stop_polling=True))

        elif command == 'core-unisolate-endpoint':
            polling_args = {
                **args,
                "endpoint_id_list": args.get('endpoint_id')
            }
            return_results(run_polling_command(client=client,
                                               args=polling_args,
                                               cmd="core-unisolate-endpoint",
                                               command_function=unisolate_endpoint_command,
                                               command_decision_field="action_id",
                                               results_function=get_endpoints_command,
                                               polling_field="is_isolated",
                                               polling_value=["AGENT_UNISOLATED"],
                                               stop_polling=True))

        elif command == 'core-get-distribution-url':
            return_outputs(*get_distribution_url_command(client, args))

        elif command == 'core-get-create-distribution-status':
            return_outputs(*get_distribution_status_command(client, args))

        elif command == 'core-get-distribution-versions':
            return_outputs(*get_distribution_versions_command(client))

        elif command == 'core-create-distribution':
            return_outputs(*create_distribution_command(client, args))

        elif command == 'core-get-audit-management-logs':
            return_outputs(*get_audit_management_logs_command(client, args))

        elif command == 'core-get-audit-agent-reports':
            return_outputs(*get_audit_agent_reports_command(client, args))

        elif command == 'core-blocklist-files':
            return_outputs(*blocklist_files_command(client, args))

        elif command == 'core-allowlist-files':
            return_outputs(*allowlist_files_command(client, args))

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
                                               results_function=get_quarantine_status_command,
                                               polling_field="status",
                                               polling_value=[False]))

        elif command == 'core-get-quarantine-status':
            return_results(get_quarantine_status_command(client, args))

        elif command == 'core-restore-file':
            return_results(run_polling_command(client=client,
                                               args=args,
                                               cmd="core-retrieve-files",
                                               command_function=restore_file_command,
                                               command_decision_field="action_id",
                                               results_function=action_status_get_command,
                                               polling_field="status",
                                               polling_value=["PENDING",
                                                              "IN_PROGRESS",
                                                              "PENDING_ABORT"]))

        elif command == 'core-endpoint-scan':
            return_results(run_polling_command(client=client,
                                               args=args,
                                               cmd="core-retrieve-files",
                                               command_function=endpoint_scan_command,
                                               command_decision_field="action_id",
                                               results_function=action_status_get_command,
                                               polling_field="status",
                                               polling_value=["PENDING",
                                                              "IN_PROGRESS",
                                                              "PENDING_ABORT"]))

        elif command == 'core-endpoint-scan-abort':
            return_results(endpoint_scan_abort_command(client, args))

        elif command == 'update-remote-system':
            return_results(update_remote_system_command(client, args))

        elif command == 'core-delete-endpoints':
            return_outputs(*delete_endpoints_command(client, args))

        elif command == 'core-get-policy':
            return_outputs(*get_policy_command(client, args))

        elif command == 'core-get-endpoint-device-control-violations':
            return_outputs(*get_endpoint_device_control_violations_command(client, args))

        elif command == 'core-retrieve-files':
            return_results(run_polling_command(client=client,
                                               args=args,
                                               cmd="core-retrieve-files",
                                               command_function=retrieve_files_command,
                                               command_decision_field="action_id",
                                               results_function=action_status_get_command,
                                               polling_field="status",
                                               polling_value=["PENDING",
                                                              "IN_PROGRESS",
                                                              "PENDING_ABORT"]))

        elif command == 'core-retrieve-file-details':
            return_entry, file_results = retrieve_file_details_command(client, args)
            demisto.results(return_entry)
            if file_results:
                demisto.results(file_results)

        elif command == 'core-get-scripts':
            return_outputs(*get_scripts_command(client, args))

        elif command == 'core-get-script-metadata':
            return_outputs(*get_script_metadata_command(client, args))

        elif command == 'core-get-script-code':
            return_outputs(*get_script_code_command(client, args))

        elif command == 'core-action-status-get':
            return_results(action_status_get_command(client, args))

        elif command == 'core-run-script':
            return_results(run_script_command(client, args))

        elif command == 'core-run-snippet-code-script':
            return_results(run_polling_command(client=client,
                                               args=args,
                                               cmd="core-run-snippet-code-script",
                                               command_function=run_snippet_code_script_command,
                                               command_decision_field="action_id",
                                               results_function=action_status_get_command,
                                               polling_field="status",
                                               polling_value=["PENDING",
                                                              "IN_PROGRESS",
                                                              "PENDING_ABORT"]))

        elif command == 'core-get-script-execution-status':
            return_results(get_script_execution_status_command(client, args))

        elif command == 'core-get-script-execution-results':
            return_results(get_script_execution_results_command(client, args))

        elif command == 'core-get-script-execution-result-files':
            return_results(get_script_execution_result_files_command(client, args))

        elif command == 'core-run-script-execute-commands':
            return_results(run_polling_command(client=client,
                                               args=args,
                                               cmd="core-run-script-execute-commands",
                                               command_function=run_script_execute_commands_command,
                                               command_decision_field="action_id",
                                               results_function=action_status_get_command,
                                               polling_field="status",
                                               polling_value=["PENDING",
                                                              "IN_PROGRESS",
                                                              "PENDING_ABORT"]))

        elif command == 'core-run-script-delete-file':
            return_results(run_polling_command(client=client,
                                               args=args,
                                               cmd="core-run-script-delete-file",
                                               command_function=run_script_delete_file_command,
                                               command_decision_field="action_id",
                                               results_function=action_status_get_command,
                                               polling_field="status",
                                               polling_value=["PENDING",
                                                              "IN_PROGRESS",
                                                              "PENDING_ABORT"]))

        elif command == 'core-run-script-file-exists':
            return_results(run_polling_command(client=client,
                                               args=args,
                                               cmd="core-run-script-file-exists",
                                               command_function=run_script_file_exists_command,
                                               command_decision_field="action_id",
                                               results_function=action_status_get_command,
                                               polling_field="status",
                                               polling_value=["PENDING",
                                                              "IN_PROGRESS",
                                                              "PENDING_ABORT"]))

        elif command == 'core-run-script-kill-process':
            return_results(run_polling_command(client=client,
                                               args=args,
                                               cmd="core-run-script-kill-process",
                                               command_function=run_script_kill_process_command,
                                               command_decision_field="action_id",
                                               results_function=action_status_get_command,
                                               polling_field="status",
                                               polling_value=["PENDING",
                                                              "IN_PROGRESS",
                                                              "PENDING_ABORT"]))

        elif command == 'endpoint':
            return_results(endpoint_command(client, args))

        elif command == 'core-report-incorrect-wildfire':
            return_results(report_incorrect_wildfire_command(client, args))
    except Exception as err:
        demisto.error(traceback.format_exc())
        return_error(str(err))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
