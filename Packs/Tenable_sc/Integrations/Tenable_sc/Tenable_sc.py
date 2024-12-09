import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


import re
from requests import Session
import urllib3
import functools
import json
from datetime import datetime
from requests import cookies
import pytz
from typing import Any

# disable insecure warnings
urllib3.disable_warnings()


''' GLOBAL VARIABLES'''
ACTION_TYPE_TO_VALUE = {
    'notification': 'users.username',
    'email': 'users.username',
    'syslog': 'host',
    'scan': 'scan.name',
    'report': 'report.name',
    'ticket': 'assignee.username'
}

FIELDS_TO_INCLUDE = 'id,name,description,type,ownerGroup,owner,tags,modifiedTime,restrictedIPs'
API_KEY = "API_KEY"
USERNAME_AND_PASSWORD = "USERNAME_AND_PASSWORD"
ROLE_ID_DICT = {
    "Administrator": "1",
    "Security Manager": "2",
    "Security Analyst": "3",
    "Vulnerability Analyst": "4",
    "Executive": "5",
    "Credential Manager": "6",
    "Auditor": "7"
}


class Client(BaseClient):
    def __init__(self, verify_ssl: bool = True, proxy: bool = False, user_name: str = "",
                 password: str = "", access_key: str = "", secret_key: str = "", url: str = ""):

        if not proxy:
            try:
                del os.environ['HTTP_PROXY']
                del os.environ['HTTPS_PROXY']
                del os.environ['http_proxy']
                del os.environ['https_proxy']
            except Exception as e:
                demisto.debug(f"encountered the following issue: {e}")

        self.url = f"{get_server_url(url)}/rest"
        self.verify_ssl = verify_ssl
        self.max_retries = 3
        self.headers: dict[str, Any] = {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
        self.auth_method = API_KEY
        if not (user_name and password) and not (secret_key and access_key):
            raise DemistoException("Please provide either user_name and password or secret_key and access_key")
        if secret_key and access_key:
            self.headers['x-apikey'] = f"accesskey={access_key}; secretkey={secret_key}"
            BaseClient.__init__(self, base_url=self.url, headers=self.headers, verify=verify_ssl, proxy=proxy)
            self.send_request = self.send_request_api_key_auth
        else:
            self.session = Session()
            integration_context = demisto.getIntegrationContext()
            self.token = integration_context.get('token')
            self.cookie = integration_context.get('cookie')
            self.user_name = user_name
            self.password = password
            self.send_request = self.send_request_username_and_password_auth
            self.auth_method = USERNAME_AND_PASSWORD
            if not self.token or not self.cookie:
                self.login()

    def __enter__(self):
        return self

    def send_request_api_key_auth(self, path, method='GET', body={}, params={}, headers=None):
        """
        Send the requests for access & secret keys authentication method.
        Args:
            path (str): The url suffix.
            method (str): The request method.
            body (dict): The request body.
            params (dict): The request params.
            headers (dict): The request headers.
        Returns:
            Dict: The response.
        """
        headers = headers or self.headers
        return self._http_request(method, url_suffix=path, params=params, data=json.dumps(body), headers=headers)

    def send_request_username_and_password_auth(self, path, method='GET', body=None, params=None, headers=None, try_number=1):
        """
        Send the requests for username & password authentication method.
        Args:
            path (str): The url suffix.
            method (str): The request method.
            body (dict): The request body.
            params (dict): The request params.
            headers (dict): The request headers.
            try_number (int): The request retries counter.
        Returns:
            Dict: The response.
        """
        body = body if body is not None else {}
        params = params if params is not None else {}
        headers = headers if headers is not None else self.headers

        headers['X-SecurityCenter'] = self.token
        url = f'{self.url}/{path}'

        session_cookie = cookies.create_cookie('TNS_SESSIONID', self.cookie)
        self.session.cookies.set_cookie(session_cookie)  # type: ignore

        res = self.session.request(method, url, data=json.dumps(body), params=params, headers=headers, verify=self.verify_ssl)

        if res.status_code == 403 and try_number <= self.max_retries:
            self.login()
            headers['X-SecurityCenter'] = self.token  # The Token is being updated in the login
            return self.send_request_username_and_password_auth(path, method, body, params, headers, try_number + 1)

        elif res.status_code < 200 or res.status_code >= 300:
            try:
                error = res.json()
            except Exception:
                # type: ignore
                raise DemistoException(
                    f'Error: Got status code {str(res.status_code)} with {url=} \
                    with body {res.content} with headers {str(res.headers)}')   # type: ignore

            raise DemistoException(f"Error: Got an error from TenableSC, code: {error['error_code']}, \
                        details: {error['error_msg']}")  # type: ignore
        return res.json()

    def login(self):
        """
        Set the token for username & password authentication method.
        """
        login_body = {
            'username': self.user_name,
            'password': self.password
        }
        login_response = self.send_login_request(login_body)

        if 'response' not in login_response:
            raise DemistoException('Error: Could not retrieve login token')

        token = login_response['response'].get('token')
        # There might be a case where the API does not return a token because there are too many sessions with the same user
        # In that case we need to add 'releaseSession = true'
        if not token:
            login_body['releaseSession'] = 'true'
            login_response = self.send_login_request(login_body)
            if 'response' not in login_response or 'token' not in login_response['response']:
                raise DemistoException('Error: Could not retrieve login token')
            token = login_response['response']['token']

        self.token = str(token)
        demisto.setIntegrationContext({'token': self.token})

    def send_login_request(self, login_body):
        """
        Send the request to login for username & password authentication method.
        Args:
            login_body (dict): The request body.
        Returns:
            Dict: The response.
        """
        url = f'{self.url}/token'

        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
        res = self.session.request('post', url, headers=headers, data=json.dumps(login_body), verify=self.verify_ssl)

        if res.status_code < 200 or res.status_code >= 300:
            raise DemistoException(f'Error: Got status code {str(res.status_code)} with {url=} \
                        with body {res.content} with headers {str(res.headers)}')  # type: ignore

        self.cookie = res.cookies.get('TNS_SESSIONID', self.cookie)
        demisto.setIntegrationContext({'cookie': self.cookie})

        return res.json()

    def __exit__(self, *args):
        """
        Send the request to logout for username & password authentication method.
        """
        if self.auth_method == USERNAME_AND_PASSWORD:
            self.send_request(path='token', method='DELETE')

    def create_scan(self, args: dict[str, Any]):
        """
        Send the request for create_scan_command and create_remediation_scan_command.
        Args:
            args (dict): The demisto.args() object.
        Returns:
            Dict: The response.
        """
        body = self.create_scan_body(args)

        return self.send_request(path='scan', method='POST', body=body)

    def create_scan_body(self, args):
        """
        Construct the body for the create_scan request.
        Args:
            args (dict): The demisto.args() object.
        Returns:
            Dict: The request body.
        """
        create_scan_mapping_dict = {
            'description': 'description',
            'dhcpTracking': 'dhcp_tracking',
            'timeoutAction': 'timeout_action',
            'scanningVirtualHosts': 'scan_virtual_hosts',
            'rolloverType': 'rollover_type',
            'ipList': 'ip_list'
        }
        body = {key: args.get(value) for key, value in create_scan_mapping_dict.items() if args.get(value)}

        scan_type = args.get("scan_type")
        body["type"] = scan_type if scan_type else ('policy' if args.get("policy_id") else 'plugin')

        body['name'] = args.get('name') or args.get('scan_name')

        body["pluginID"] = args.get('plugin_id') or args.get('plugins_id')

        if repo_id := args.get("repository_id"):
            body["repository"] = {'id': repo_id}

        if policy_id := args.get("policy_id"):
            body["policy"] = {'id': policy_id}

        if zone_id := args.get("zone_id"):
            body["zone"] = {'id': zone_id}

        if report_ids := args.get("report_ids"):
            body['reports'] = [{'id': r_id, 'reportSource': 'individual'} for r_id in argToList(report_ids)]

        if asset_ids := args.get("asset_ids"):
            if str(asset_ids).startswith('All'):
                manageable = asset_ids == 'AllManageable'
                res = self.get_assets(None)
                assets = get_elements(res['response'], manageable)
                asset_ids = [a['id'] for a in assets]
            body['assets'] = [{'id': a_id} for a_id in argToList(asset_ids)]

        if credentials := args.get("credentials"):
            body['credentials'] = [{'id': c_id} for c_id in argToList(credentials)]

        if max_scan_time := int(args.get('max_scan_time', '1')):
            body['maxScanTime'] = max_scan_time * 3600

        if schedule := args.get('schedule'):
            schedule_body = {
                'type': schedule
            }

            if dependent := args.get('dependent_id'):
                schedule_body['dependentID'] = dependent

            if schedule == 'ical':
                start_time = args.get("start_time")
                repeat_rule_freq = args.get("repeat_rule_freq", "")
                repeat_rule_interval = int(args.get("repeat_rule_interval", 0))
                repeat_rule_by_day = argToList(args.get("repeat_rule_by_day", ""))
                timestamp_format = "%Y%m%dT%H%M%S"
                expected_format = "%Y-%m-%d:%H:%M:%S"
                try:
                    start_time = datetime.strptime(start_time, expected_format)
                    start_time = datetime.strftime(start_time, timestamp_format)
                except Exception:
                    start_time = parse_date_range(start_time, date_format=timestamp_format)[0]
                if time_zone := args.get("time_zone") and start_time:
                    schedule_body['start'] = f"TZID={time_zone}:{start_time}"
                else:
                    raise DemistoException("Please make sure to provide both time_zone and start_time.")
                if all([repeat_rule_freq, repeat_rule_interval, repeat_rule_by_day]):
                    schedule_body['repeatRule'] = f"FREQ={repeat_rule_freq};INTERVAL={repeat_rule_interval};"
                    f"BYDAY={repeat_rule_by_day}"
                elif repeat_rule_freq and repeat_rule_interval:
                    schedule_body['repeatRule'] = f"FREQ={repeat_rule_freq};INTERVAL={repeat_rule_interval}"
                elif any([repeat_rule_freq, repeat_rule_interval, repeat_rule_by_day]):
                    raise DemistoException("Please make sure to provide repeat_rule_freq, repeat_rule_interval with or without "
                                           "repeat_rule_by_day, or don't provide any of them.")
                schedule_body['enabled'] = argToBoolean(args.get("enabled", True))
            body['schedule'] = schedule_body

        remove_nulls_from_dictionary(body)
        return body

    def get_scan_results(self, scan_results_id):
        """
        Send the request for get_scan_status.
        Args:
            scan_results_id (str): The ID of the scan results to search.
        Returns:
            Dict: The response.
        """
        path = 'scanResult/' + scan_results_id

        return self.send_request(path)

    def launch_scan(self, scan_id, scan_target):
        """
        Send the request for launch_scan_command and launch_scan_report_command.
        Args:
            scan_id (str): The ID of the scan to launch.
            scan_target (str): Optional body parameters.
        Returns:
            Dict: The response.
        """
        path = 'scan/' + scan_id + '/launch'
        body = None
        if scan_target:
            body = {
                'diagnosticTarget': scan_target['address'],
                'diagnosticPassword': scan_target['password']
            }

        return self.send_request(path, 'post', body=body)

    def get_query(self, query_id):
        """
        Send the request for get_alert_command and list_query_command.
        Args:
            query_id (str): The ID of the query to retrieve.
        Returns:
            Dict: The response.
        """
        path = f'query/{query_id}'

        return self.send_request(path)

    def list_queries(self, type):
        """
        Send the request for list_query_command and list_queries.
        Args:
            type (str): The query type to retrieve.
        Returns:
            Dict: The response.
        """
        path = 'query'
        params = {}
        if type:
            params["type"] = type

        return self.send_request(path=path, method="GET", params=params)

    def get_all_scan_results(self):
        """
        Send the request for get_all_scan_results_command.
        Returns:
            Dict: The response.
        """
        params = {
            'fields': 'name,description,details,status,scannedIPs,startTime,scanDuration,importStart,'
            'finishTime,completedChecks,owner,ownerGroup,repository,importStatus'
        }
        return self.send_request(path='scanResult', params=params)

    def get_alerts(self, fields=None, alert_id=None):
        """
        Send the request for list_alerts_command and get_alert_command.
        Args:
            fields (str): The fields to include in the response.
            alert_id (str): The ID of the alert to search.
        Returns:
            Dict: The response.
        """
        path = 'alert'
        params = {}  # type: Dict[str, Any]

        if alert_id:
            path += '/' + alert_id

        if fields:
            params = {
                'fields': fields
            }

        return self.send_request(path, params=params)

    def get_organization(self, fields=None):
        """
        Send the request for get_organization_command.
        Args:
            fields (str): The fields to include in the response.
        Returns:
            Dict: The response.
        """
        params = {}  # type: Dict[str, Any]

        if fields:
            params = {
                'fields': ",".join(fields)
            }

        return self.send_request(path='organization', params=params)

    def get_system_licensing(self):
        """
        Send the request for get_system_licensing_command.
        Returns:
            Dict: The response.
        """
        return self.send_request(path='status')

    def get_scans(self, fields):
        """
        Send the request for list_scans_command.
        Args:
            fields (str): The fields to include in the response.
        Returns:
            Dict: The response.
        """
        params = None

        if fields:
            params = {
                'fields': fields
            }

        return self.send_request(path='scan', params=params)

    def get_policies(self, fields):
        """
        Send the request for list_policies_command.
        Args:
            fields (str): The fields to include in the response.
        Returns:
            Dict: The response.
        """
        params = None

        if fields:
            params = {
                'fields': fields
            }

        return self.send_request(path='policy', params=params)

    def get_repositories(self):
        """
        Send the request for list_repositories_command.
        Returns:
            Dict: The response.
        """
        return self.send_request(path='repository')

    def get_assets(self, fields):
        """
        Send the request for list_assets_command and create_scan.
        Args:
            fields (str): The fields to include in the response.
        Returns:
            Dict: The response.
        """
        params = None

        if fields:
            params = {
                'fields': fields
            }

        return self.send_request(path='asset', params=params)

    def get_credentials(self):
        """
        Send the request for list_credentials_command.
        Returns:
            Dict: The response.
        """
        params = {
            'fields': FIELDS_TO_INCLUDE
        }

        return self.send_request(path='credential', params=params)

    def get_asset(self, asset_id):
        """
        Send the request for list_assets_command.
        Args:
            asset_id (str): The ID of the asset to search.
        Returns:
            Dict: The response.
        """
        params = {
            'fields': 'id,name,description,status,createdTime,modifiedTime,viewableIPs,ownerGroup,tags,owner'
        }

        return self.send_request(path=f'asset/{asset_id}', params=params)

    def create_asset(self, name, description, owner_id, tags, ips):
        """
        Send the request for create_asset_command.
        Args:
            name (str): The name for the asset.
            description (str): The description for the asset.
            owner_id (str): The ID of the owner of the asset.
            tags (str): The tags for the asset.
            ips (str): The IP list for the asset.
        Returns:
            Dict: The response.
        """
        body = {
            'name': name,
            'definedIPs': ips,
            'type': 'static'
        }

        if description:
            body['description'] = description

        if owner_id:
            body['ownerID'] = owner_id

        if tags:
            body['tags'] = tags

        return self.send_request(path='asset', method='POST', body=body)

    def delete_asset(self, asset_id):
        """
        Send the request for delete_asset_command.
        Args:
            asset_id (str): The ID of the asset to delete.
        Returns:
            Dict: The response.
        """
        return self.send_request(path=f'asset/{asset_id}', method='DELETE')

    def get_report_definitions(self, fields):
        """
        Send the request for list_report_definitions_command.
        Args:
            fields (str): The fields to include in the response.
        Returns:
            Dict: The response.
        """
        params = None

        if fields:
            params = {
                'fields': fields
            }

        return self.send_request(path='reportDefinition', params=params)

    def get_zones(self):
        """
        Send the request for list_zones_command.
        Returns:
            Dict: The response.
        """
        return self.send_request(path='zone')

    def get_scan_report(self, scan_results_id):
        """
        Send the request for get_scan_report_command and launch_scan_report_command.
        Args:
            scan_results_id (str): The ID of the scan_results to search for.
        Returns:
            Dict: The response.
        """
        path = 'scanResult/' + scan_results_id

        params = {
            'fields': 'name,description,details,status,scannedIPs,progress,startTime,scanDuration,importStart,'
                      'finishTime,completedChecks,owner,ownerGroup,repository,policy,importStatus,running'
        }

        return self.send_request(path, params=params)

    def create_query(self, scan_id, tool):
        """
        Send the request for get_vulnerabilities.
        Args:
            scan_id (str): The ID of the scan_results to create the query for.
            tool (str): the tool to use.
        Returns:
            Dict: The response.
        """
        path = 'query'

        body = {
            'name': f'scan {scan_id} query',
            'type': 'vuln',
            'tool': tool,
            'scanID': scan_id
        }

        return self.send_request(path, method='POST', body=body)

    def delete_query(self, query_id):
        """
        Send the request for get_vulnerabilities.
        Args:
            query_id (str): The ID of the query to delete.
        Returns:
            Dict: The response.
        """
        if not query_id:
            raise DemistoException('query id returned None')
        path = 'query/' + str(query_id)
        self.send_request(path, method='DELETE')

    def get_analysis(self, body=None, args={}):
        """
        Send the request for get_vulnerability_command and get_vulnerabilities.
        Args:
            args (dict): Either an empty dict if passed from get_vulnerabilities, otherwise, the demisto.results() object.
            body (str): The request body (if function is called from get_vulnerabilities).
        Returns:
            Dict: The response.
        """
        body = body or self.create_get_vulnerability_request_body(args)

        return self.send_request(path='analysis', method='POST', body=body)

    def create_get_vulnerability_request_body(self, args={}):
        """
        Create the body for the request made in get_analysis.
        Args:
            args (dict): Either an empty dict if passed from get_vulnerabilities, otherwise, the demisto.results() object.
        Returns:
            Dict: The prepared request body.
        """
        vuln_id = args.get('vulnerability_id')
        scan_results_id = args.get('scan_results_id')
        sort_field = args.get('sort_field', 'severity')
        query_id = args.get('query_id')
        query = {'id': query_id}
        sort_direction = args.get('sort_direction', "ASC")
        source_type = args.get('source_type', "individual")
        page = int(args.get('page', '0'))
        limit = int(args.get('limit', '50'))
        if limit > 200:
            limit = 200
        body = {
            'type': 'vuln',
            'view': 'all',
            'sourceType': source_type,
            'startOffset': page,  # Lower bound for the results list (must be specified)
            'endOffset': page + limit,  # Upper bound for the results list (must be specified)
            'sortField': sort_field,
            'sortDir': sort_direction,
            'tool': 'vulndetails',
        }
        if source_type == 'individual':
            if scan_results_id:
                body['scanID'] = scan_results_id
            else:
                raise DemistoException("When choosing source_type = individual - scan_results_id must be provided.")
            vuln_filter = [{
                'filterName': 'pluginID',
                'operator': '=',
                'value': vuln_id
            }]
            query["filters"] = vuln_filter
            query["tool"] = 'vulndetails'
            query["type"] = 'vuln'
        else:
            body['sourceType'] = source_type
            if not query_id:
                raise DemistoException(f"When choosing source_type = {source_type} - query_id must be provided.")
        body["query"] = query

        return body

    def get_system_diagnostics(self):
        """
        Send the request for get_system_information_command.
        Returns:
            Dict: The response.
        """
        return self.send_request(path='system/diagnostics')

    def get_system(self):
        """
        Send the request for get_system_information_command.
        Returns:
            Dict: The response.
        """
        return self.send_request(path='system')

    def list_groups(self, show_users):
        """
        Send the request for list_groups_command.
        Args:
            show_users (str): Optional filtering argument.
        Returns:
            Dict: The response.
        """
        params = {}
        if show_users:
            params['fields'] = 'users'

        return self.send_request(path='group', method='GET', params=params)

    def get_vulnerability(self, vuln_id):
        """
        Send the request for get_vulnerability_command.
        Args:
            vuln_id (str): The ID of the vulnerability to search.
        Returns:
            Dict: The response.
        """
        path = f'plugin/{vuln_id}'

        params = {
            'fields': 'name,description,family,type,cpe,riskFactor,solution,synopsis,exploitEase,exploitAvailable,'
                      'cvssVector,baseScore,pluginPubDate,pluginModDate,vulnPubDate,temporalScore,xrefs,checkType'
        }

        return self.send_request(path, params=params)

    def delete_scan(self, scan_id):
        """
        Send the request for delete_scan_command.
        Args:
            scan_id (str): The ID of the scan to delete.
        Returns:
            Dict: The response.
        """
        return self.send_request(path=f'scan/{scan_id}', method='DELETE')

    def get_device(self, uuid, ip, dns_name, repo):
        """
        Send the request for get_device_command.
        Args:
            uuid (str): The UUID of the device to search.
            ip (str): Optional filtering argument.
            dns_name (str): Optional filtering argument.
            repo (str): Optional filtering argument.
        Returns:
            Dict: The response.
        """
        path, params = create_get_device_request_params_and_path(uuid, ip, dns_name, repo)

        return self.send_request(path, params=params)

    def get_users(self, fields='id,username,firstname,lastname,title,email,createdTime,modifiedTime,lastLogin,role',
                  user_id=None):
        """
        Send the request for list_users_command.
        Args:
            fields (str): The fields to include in the response.
            user_id (str): The ID of the user to search.
        Returns:
            Dict: The response.
        """
        path = 'user'

        if user_id:
            path += '/' + user_id

        params = None

        if fields:
            params = {
                'fields': fields
            }

        return self.send_request(path, params=params)

    def create_user(self, args):
        """
        Send the request for create_user_command.
        Args:
            args (Dict): The demisto.args() object.
        Returns:
            Dict: The response.
        """
        body = create_user_request_body(args)

        return self.send_request(path='user', body=body, method='POST')

    def update_user(self, args, user_id):
        """
        Send the request for update_user_command.
        Args:
            args (Dict): The demisto.args() object.
            user_id (str): The ID of the user to update.
        Returns:
            Dict: The response.
        """
        body = create_user_request_body(args)

        return self.send_request(path=f'user/{user_id}', body=body, method='PATCH')

    def update_asset(self, args, asset_id):
        """
        Send the request for update_asset_command.
        Args:
            args (Dict): The demisto.args() object.
            asset_id (str): The ID of the asset to update.
        Returns:
            Dict: The response.
        """
        body = {
            "name": args.get("name"),
            "description": args.get("description"),
            "tags": args.get("tags"),
            "ownerID": args.get("owner_id"),
            "definedIPs": args.get("ip_list")
        }
        remove_nulls_from_dictionary(body)
        return self.send_request(path=f'asset/{asset_id}', body=body, method='PATCH')

    def delete_user(self, user_id):
        """
        Send the request for delete_user_command.
        Args:
            user_id (str): The ID of the user to delete.
        Returns:
            Dict: The response.
        """
        return self.send_request(path=f'user/{user_id}', method='DELETE')

    def list_plugin_family(self, plugin_id, is_active):
        """
        Send the request for list_plugin_family_command.
        Args:
            plugin_id (str): The id of the plugin to get.
            is_active (str): Wether to filter by active / passive plugins.
        Returns:
            Dict: The response.
        """
        path = "pluginFamily"
        if plugin_id:
            path += f"/{plugin_id}"
        else:
            if is_active == 'true':
                path += "?fields=active"
            elif is_active == 'false':
                path += "?fields=passive"
        return self.send_request(path=path, method='GET')

    def create_policy(self, args):
        """
        Send the request for create_policy_command.
        Args:
            args (Dict): the demisto.args() object.
        Returns:
            Dict: The response.
        """
        body = create_policy_request_body(args)

        return self.send_request(path="policy", method='POST', body=body)


''' HELPER FUNCTIONS '''


def create_get_device_request_params_and_path(uuid: str, ip: str, dns_name: str, repo: str):
    """
    Construct the url suffix and params dict for get_device request.
    Args:
        uuid (str): UUID extracted from args.
        ip (str): IP extracted from args.
        dns_name (str): Dns extracted from args.
        repo (str): Repo name extracted from args.
    Returns:
        str: The url suffix for the request.
        Dict: The params for the request.
    """
    path = f'repository/{repo}/' if repo else ''
    path += 'deviceInfo'
    params = {
        'fields': 'ip,uuid,macAddress,netbiosName,dnsName,os,osCPE,lastScan,repository,total,severityLow,'
                  'severityMedium,severityHigh,severityCritical'
    }
    if uuid:
        params['uuid'] = uuid
    else:
        params['ip'] = ip
        if dns_name:
            params['dnsName'] = dns_name
    return path, params


def create_policy_request_body(args: dict[str, Any]):
    """
    Construct the body for create_policy request.
    Args:
        args (Dict): The demisto.args() object.
    Returns:
        Dict: The body for the request.
    """
    body = {
        "name": args.get("policy_name"),
        "description": args.get("policy_description"),
        "context": "scan",
        "preferences": {
            "portscan_range": args.get("port_scan_range", 'default'),
            "tcp_scanner": args.get("tcp_scanner", "no"),
            "syn_scanner": args.get("syn_scanner", "yes"),
            "udp_scanner": args.get("udp_scanner", "no"),
            "syn_firewall_detection": args.get("syn_firewall_detection", 'Automatic (normal)')
        },
        "policyTemplate": {
            "id": args.get("policy_template_id", '1')
        },
    }
    family = {"id": args.get("family_id", "")}
    if plugins_id := args.get("plugins_id"):
        family["plugins"] = [{"id": id for id in plugins_id.split(',')}]
    body["families"] = [family]
    remove_nulls_from_dictionary(body)
    return body


def create_user_request_body(args: dict[str, Any]):
    """
    Create user request body for update or create user commands.
    Args:
        args (Dict): the demisto.args() object.
    Returns:
        Dict: The request body.
    """
    user_query_mapping_dict: dict[str, str] = {
        "firstname": "first_name",
        "lastname": "last_name",
        "username": "user_name",
        "email": "email",
        "city": "city",
        "state": "state",
        "address": "address",
        "country": "country",
        "authType": "auth_type",
        "emailNotice": "email_notice",
        "phone": "phone",
        "locked": "locked",
        "mustChangePassword": "must_change_password",
        "currentPassword": "current_password",
        "password": "password",
        "groupID": "group_id",
        "responsibleAssetID": "responsible_asset_id"
    }
    body = {key: args.get(value) for key, value in user_query_mapping_dict.items() if args.get(value)}

    if role_id := args.get("role_id", ""):
        body["roleID"] = ROLE_ID_DICT.get(role_id, "")

    if args.get('managed_users_groups'):
        body["managedUsersGroups"] = [{"id": managed_users_group} for
                                      managed_users_group in args.get('managed_users_groups', "").split(',')]
    if args.get('managed_objects_groups'):
        body["managedObjectsGroups"] = [{"id": int(managed_objects_group)} for
                                        managed_objects_group in args.get('managed_objects_groups', "").split(',')]
    if time_zone := args.get('time_zone'):
        body["preferences"] = [{"name": "timezone", "value": time_zone, "tag": ""}]

    return body


def get_server_url(url):
    """
    Remove redundant '/' from the url the server url.
    For example: www.example.com/ - > www.example.com.
    Args:
        url (str): The server url.
    Returns:
        str: The server url.
    """
    url = re.sub('/[\/]+$/', '', url)
    url = re.sub('\/$', '', url)
    return url


def validate_user_body_params(args: dict[str, Any], command_type: str):
    """
    Validate all given arguments are valid according to the command type (update or create).
    Args:
        args (Dict): the demisto.args() object.
        command_type (Dict): the command type the function is called from (update or create)
    Returns:
        None: return error if arguments are invalid.
    """
    numbers_args_ls = ["group_id", "user_id", "responsible_asset_id"]

    time_zone = args.get("time_zone")
    password = args.get("password")
    email_notice = args.get("email_notice")
    email = args.get("email")
    auth_type = args.get("auth_type")

    for number_arg in numbers_args_ls:
        try:
            int(args.get(number_arg, '0'))
        except Exception:
            raise DemistoException(f"{number_arg} must be a valid number.")

    if time_zone and time_zone not in pytz.all_timezones:
        raise DemistoException("Invalid time zone ID. Please choose one of the following: "
                               "https://docs.oracle.com/middleware/1221/wcs/tag-ref/MISC/TimeZones.html")

    if command_type == "create" and (auth_type == 'Ldap' or auth_type == 'saml'):
        args["must_change_password"] = "false"

    if password:
        if command_type == 'update' and not args.get("current_password"):
            raise DemistoException("current_password must be provided when attempting to update password.")
        if len(password) < 3:
            raise DemistoException("Password length must be at least 3 characters.")

    if email and not re.compile(emailRegex).match(email):
        raise DemistoException(f"Error: The given email address: {email} is not in the correct format.")

    if command_type == 'create' and not email_notice == 'none' and not email:
        raise DemistoException("When email_notice is different from none, an email must be given as well.")


def timestamp_to_utc(timestamp_str, default_returned_value=''):
    """
    Convert timestamp string to UTC date time.
    Args:
        timestamp_str (str): timestamp string.
        default_returned_value (str): the default return value
    Returns:
        str: UTC date time string.
    """
    if timestamp_str and (int(timestamp_str) > 0):  # no value is when timestamp_str == '-1'
        return datetime.utcfromtimestamp(int(timestamp_str)).strftime(
            '%Y-%m-%dT%H:%M:%SZ')
    return default_returned_value


def scan_duration_to_demisto_format(duration, default_returned_value=''):
    """
    Convert duration to demisto format time.
    Args:
        duration (str): Scan duration in tenable sc format.
        default_returned_value (str): the default return value
    Returns:
        Int / str: the scan duration in demisto format.
    """
    if duration:
        return float(duration) / 60
    return default_returned_value


''' FUNCTIONS '''


def list_scans_command(client: Client, args: dict[str, Any]):
    """
    List scans.
    Args:
        client (Client): The tenable.sc client object.
        args (Dict): demisto.args() object.
    Returns:
        CommandResults: command results object with the response, human readable section, and the context entries to add.
    """
    res = client.get_scans('id,name,description,policy,ownerGroup,owner')
    manageable = args.get('manageable', 'false').lower()

    if not (res and res.get('response')):
        raise DemistoException('No scans found')

    scans_dicts = get_elements(res['response'], manageable)

    if len(scans_dicts) == 0:
        raise DemistoException('No scans found')

    headers = ['ID', 'Name', 'Description', 'Policy', 'Group', 'Owner']

    mapped_scans = [{
        'Name': s['name'],
        'ID': s['id'],
        'Description': s['description'],
        'Policy': s['policy'].get('name'),
        'Group': s['ownerGroup'].get('name'),
        'Owner': s['owner'].get('username')
    } for s in scans_dicts]

    return CommandResults(
        outputs=createContext(mapped_scans, removeNull=True),
        outputs_prefix='TenableSC.Scan',
        raw_response=res,
        outputs_key_field='ID',
        readable_output=tableToMarkdown('Tenable.sc Scans', mapped_scans, headers, removeNull=True)
    )


def list_policies_command(client: Client, args: dict[str, Any]):
    """
    List policies.
    Args:
        client (Client): The tenable.sc client object.
        args (Dict): demisto.args() object.
    Returns:
        CommandResults: command results object with the response, human readable section, and the context entries to add.
    """
    res = client.get_policies('id,name,description,tags,modifiedTime,owner,ownerGroup,policyTemplate')

    manageable = args.get('manageable', 'false').lower()

    if not (res and res.get('response')):
        raise DemistoException('No policies found')

    policies = get_elements(res['response'], manageable)

    if len(policies) == 0:
        raise DemistoException('No policies found')

    headers = ['ID', 'Name', 'Description', 'Tag', 'Type', 'Group', 'Owner', 'LastModified']

    mapped_policies = [{
        'ID': p['id'],
        'Name': p['name'],
        'Description': p['description'],
        'Tag': p['tags'],
        'Type': p.get('policyTemplate', {}).get('name'),
        'Group': p.get('ownerGroup', {}).get('name'),
        'Owner': p.get('owner', {}).get('username'),
        'LastModified': timestamp_to_utc(p['modifiedTime'])
    } for p in policies]

    return CommandResults(
        outputs=createContext(mapped_policies, removeNull=True),
        outputs_prefix='TenableSC.ScanPolicy',
        raw_response=res,
        outputs_key_field='ID',
        readable_output=tableToMarkdown('Tenable.sc Scan Policies', mapped_policies, headers, removeNull=True)
    )


def list_repositories_command(client: Client, args: dict[str, Any]):
    """
    List repositories.
    Args:
        client (Client): The tenable.sc client object.
        args (Dict): demisto.args() object.
    Returns:
        CommandResults: command results object with the response, human readable section, and the context entries to add.
    """
    res = client.get_repositories()

    if not (res and res.get('response')):
        raise DemistoException('No repositories found')

    repositories = res['response']

    if len(repositories) == 0:
        raise DemistoException('No repositories found')

    headers = [
        'ID',
        'Name',
        'Description'
    ]

    mapped_repositories = [{'ID': r['id'], 'Name': r['name'], 'Description': r['description']} for r in repositories]

    return CommandResults(
        outputs=createContext(mapped_repositories, removeNull=True),
        outputs_prefix='TenableSC.ScanRepository',
        raw_response=res,
        outputs_key_field='ID',
        readable_output=tableToMarkdown('Tenable.sc Scan Repositories', mapped_repositories, headers, removeNull=True)
    )


def list_credentials_command(client: Client, args: dict[str, Any]):
    """
    List credentials.
    Args:
        client (Client): The tenable.sc client object.
        args (Dict): demisto.args() object.
    Returns:
        CommandResults: command results object with the response, human readable section, and the context entries to add.
    """
    res = client.get_credentials()

    manageable = args.get('manageable', 'false').lower()

    if not (res and res.get('response')):
        raise DemistoException('No credentials found')

    credentials = get_elements(res['response'], manageable)

    if len(credentials) == 0:
        raise DemistoException('No credentials found')

    headers = ['ID', 'Name', 'Description', 'Type', 'Tag', 'Group', 'Owner', 'LastModified']

    mapped_credentials = [{
        'ID': c['id'],
        'Name': c['name'],
        'Description': c['description'],
        'Type': c['type'],
        'Tag': c['tags'],
        'Group': c.get('ownerGroup', {}).get('name'),
        'Owner': c.get('owner', {}).get('name'),
        'LastModified': timestamp_to_utc(c['modifiedTime'])
    } for c in credentials]

    return CommandResults(
        outputs=createContext(mapped_credentials, removeNull=True),
        outputs_prefix='TenableSC.Credential',
        raw_response=res,
        outputs_key_field='ID',
        readable_output=tableToMarkdown('Tenable.sc Credentials', mapped_credentials, headers, removeNull=True)
    )


def list_assets_command(client: Client, args: dict[str, Any]):
    """
    List assets.
    Args:
        client (Client): The tenable.sc client object.
        args (Dict): demisto.args() object.
    Returns:
        CommandResults: command results object with the response, human readable section, and the context entries to add.
    """
    res = client.get_assets('id,name,description,ipCount,type,tags,modifiedTime,groups,owner')

    manageable = args.get('manageable', 'false').lower()

    if not (res and res.get('response')):
        raise DemistoException('No assets found')

    assets = get_elements(res['response'], manageable)

    if len(assets) == 0:
        raise DemistoException('No assets found')

    headers = ['ID', 'Name', 'Tag', 'Owner', 'Group', 'Type', 'HostCount', 'LastModified']

    mapped_assets = [{
        'ID': a['id'],
        'Name': a['name'],
        'Tag': a['tags'],
        'Owner': a.get('owner', {}).get('username'),
        'Type': a['type'],
        'Group': a.get('ownerGroup', {}).get('name'),
        'HostCount': a['ipCount'],
        'LastModified': timestamp_to_utc(a['modifiedTime'])
    } for a in assets]

    return CommandResults(
        outputs=createContext(mapped_assets, removeNull=True),
        outputs_prefix='TenableSC.Asset',
        raw_response=res,
        outputs_key_field='ID',
        readable_output=tableToMarkdown('Tenable.sc Assets', mapped_assets, headers, removeNull=True)
    )


def get_asset_command(client: Client, args: dict[str, Any]):
    """
    Retrieve an asset by a given asset ID.
    Args:
        client (Client): The tenable.sc client object.
        args (Dict): demisto.args() object.
    Returns:
        CommandResults: command results object with the response, human readable section, and the context entries to add.
    """
    asset_id = args.get('asset_id')

    res = client.get_asset(asset_id)

    if not res or 'response' not in res:
        raise DemistoException('Asset not found')

    asset = res['response']

    ips = []  # type: List[str]
    ip_lists = [v['ipList'] for v in asset.get('viewableIPs', '')]

    for ip_list in ip_lists:
        # Extract IPs
        ips += re.findall('[0-9]+(?:\.[0-9]+){3}', ip_list)

    headers = ['ID', 'Name', 'Description', 'Tag', 'Created', 'Modified', 'Owner', 'Group', 'IPs']

    mapped_asset = {
        'ID': asset['id'],
        'Name': asset['name'],
        'Description': asset['description'],
        'Tag': asset['tags'],
        'Created': timestamp_to_utc(asset['createdTime']),
        'Modified': timestamp_to_utc(asset['modifiedTime']),
        'Owner': asset.get('owner', {}).get('username'),
        'Group': asset.get('ownerGroup', {}).get('name'),
        'IPs': ips
    }

    return CommandResults(
        outputs=createContext(mapped_asset, removeNull=True),
        outputs_prefix='TenableSC.Asset',
        raw_response=res,
        outputs_key_field='ID',
        readable_output=tableToMarkdown('Tenable.sc Asset', mapped_asset, headers, removeNull=True)
    )


def create_asset_command(client: Client, args: dict[str, Any]):
    """
    Create an asset.
    Args:
        client (Client): The tenable.sc client object.
        args (Dict): demisto.args() object.
    Returns:
        CommandResults: command results object with the response, human readable section, and the context entries to add.
    """
    name = args.get('name')
    description = args.get('description')
    owner_id = args.get('owner_id')
    tags = args.get('tags')
    ips = args.get('ip_list')

    res = client.create_asset(name, description, owner_id, tags, ips)

    if not res or 'response' not in res:
        raise DemistoException('Error: Could not retrieve the asset')

    asset = res['response']

    mapped_asset = {
        'ID': asset['id'],
        'Name': asset['name'],
        'OwnerName': asset['owner'].get('username'),
        'Tags': asset['tags'],
    }

    headers = [
        'ID',
        'Name',
        'OwnerName',
        'Tags'
    ]

    return CommandResults(
        outputs=createContext(mapped_asset, removeNull=True),
        outputs_prefix='TenableSC.Asset',
        raw_response=res,
        outputs_key_field='ID',
        readable_output=tableToMarkdown('Asset created successfully', mapped_asset, headers=headers, removeNull=True)
    )


def delete_asset_command(client: Client, args: dict[str, Any]):
    """
    Delete an asset by a given asset ID.
    Args:
        client (Client): The tenable.sc client object.
        args (Dict): demisto.args() object.
    Returns:
        CommandResults: command results object with the response and the human readable section.
    """
    asset_id = args.get('asset_id')

    res = client.delete_asset(asset_id)

    if not res:
        raise DemistoException('Error: Could not delete the asset')

    return CommandResults(
        raw_response=res,
        readable_output=f"Asset {asset_id} was deleted successfully."
    )


def list_report_definitions_command(client: Client, args: dict[str, Any]):
    """
    Lists report definitions.
    Args:
        client (Client): The tenable.sc client object.
        args (Dict): demisto.args() object.
    Returns:
        CommandResults: command results object with the response, human readable section, and the context entries to add.
    """
    res = client.get_report_definitions('id,name,description,modifiedTime,type,ownerGroup,owner')

    manageable = args.get('manageable', 'false').lower()

    if not (res and res.get('response')):
        raise DemistoException('No report definitions found')

    reports = get_elements(res['response'], manageable)
    # Remove duplicates, take latest
    reports = [functools.reduce(lambda x, y: x if int(x['modifiedTime']) > int(y['modifiedTime']) else y,
                                filter(lambda e: e['name'] == n, reports)) for n in {r['name'] for r in reports}]

    if len(reports) == 0:
        raise DemistoException('No report definitions found')

    headers = ['ID', 'Name', 'Description', 'Type', 'Group', 'Owner']

    mapped_reports = [{
        'ID': r['id'],
        'Name': r['name'],
        'Description': r['description'],
        'Type': r['type'],
        'Group': r.get('ownerGroup', {}).get('name'),
        'Owner': r.get('owner', {}).get('username')
    } for r in reports]

    hr = tableToMarkdown('Tenable.sc Report Definitions', mapped_reports, headers, removeNull=True)
    for r in mapped_reports:
        del r['Description']

    return CommandResults(
        outputs=createContext(mapped_reports, removeNull=True),
        outputs_prefix='TenableSC.ReportDefinition',
        raw_response=res,
        outputs_key_field='ID',
        readable_output=hr
    )


def list_zones_command(client: Client, args: dict[str, Any]):
    """
    Lists zones
    Args:
        client (Client): The tenable.sc client object.
        args (Dict): demisto.args() object.
    Returns:
        CommandResults: command results object with the response, human readable section, and the context entries to add.
    """
    res = client.get_zones()
    if not res or 'response' not in res:
        raise DemistoException('No zones found')
    zones = res['response']
    if len(zones) == 0:
        zones = [{
            'id': 0,
            'name': 'All Zones',
            'description': '',
            'ipList': '',
            'activeScanners': ''
        }]
    headers = ['ID', 'Name', 'Description', 'IPList', 'activeScanners']

    mapped_zones = [{
        'ID': z.get('id', ""),
        'Name': z.get('name', ""),
        'Description': z.get('description', ""),
        'IPList': z.get('ipList', ""),
        'activeScanners': z.get('activeScanners', "")
    } for z in zones]

    hr = tableToMarkdown('Tenable.sc Scan Zones', mapped_zones, headers, removeNull=True)

    mapped_scanners_total, found_ids = [], []
    for index, zone in enumerate(zones):
        if scanners := zone.get('scanners'):
            mapped_scanners = [{
                'ID': scanner['id'],
                'Name': scanner['name'],
                'Description': scanner['description'],
                'Status': scanner['status']
            } for scanner in scanners]
            mapped_zones[index]['Scanner'] = mapped_scanners
            for scanner in mapped_scanners:
                if scanner.get("ID") not in found_ids:
                    found_ids.append(scanner.get("ID"))
                    mapped_scanners_total.append(scanner)
        headers = ['ID', 'Name', 'Description', 'Status']

    if mapped_scanners_total:
        hr += tableToMarkdown('Tenable.sc Scanners', mapped_scanners_total, headers, removeNull=True)

    return CommandResults(
        outputs=createContext(mapped_zones, removeNull=True),
        outputs_prefix='TenableSC.ScanZone',
        raw_response=res,
        outputs_key_field='ID',
        readable_output=hr
    )


def get_elements(elements, manageable):
    """
    Extracts a list from the given dictionary by given filter
    Args:
        elements (Dict): The dictionary to extract from
        manageable (str): Wether to retrieve manageable or usable list
    Returns:
        List: The desired extracted list.
    """
    if manageable == 'false':
        return elements.get('usable', [])

    return elements.get('manageable', [])


def create_scan_command(client: Client, args: dict[str, Any]):
    """
    Creates a scan.
    Args:
        client (Client): The tenable.sc client object.
        args (Dict): demisto.args() object.
    Returns:
        CommandResults: command results object with the response, human readable section, and the context entries to add.
    """
    validate_create_scan_inputs(args)

    res = client.create_scan(args)

    if not res or 'response' not in res:
        raise DemistoException('Error: Could not retrieve the scan')

    scan = res['response']

    headers = [
        'ID', 'CreatorID', 'Name', 'Type', 'CreationTime', 'OwnerName', 'Reports'
    ]

    mapped_scan = {
        'ID': scan['id'],
        'CreatorID': scan['creator'].get('id'),
        'Name': scan['name'],
        'Type': scan['type'],
        'CreationTime': timestamp_to_utc(scan['createdTime']),
        'OwnerName': scan['owner'].get('name'),
        'Reports': demisto.dt(scan['reports'], 'id')
    }

    return CommandResults(
        outputs=createContext(mapped_scan, removeNull=True),
        outputs_prefix='TenableSC.Scan',
        raw_response=res,
        outputs_key_field='ID',
        readable_output=tableToMarkdown('Scan created successfully', mapped_scan, headers, removeNull=True)
    )


def validate_create_scan_inputs(args: dict[str, Any]):
    """
    Validate all given arguments are valid for create scan command.
    Args:
        args (Dict): the demisto.args() object.
    Returns:
        None: return error if arguments are invalid.
    """
    schedule = args.get('schedule')
    asset_ids = args.get('asset_ids')
    ips = args.get('ip_list')
    dependent = args.get('dependent_id')
    time_zone = args.get("time_zone")

    if time_zone and time_zone not in pytz.all_timezones:
        raise DemistoException("Invalid time zone ID. Please choose one of the following: "
                               "https://docs.oracle.com/middleware/1221/wcs/tag-ref/MISC/TimeZones.html")
    if not asset_ids and not ips:
        raise DemistoException('Error: Assets and/or IPs must be provided')

    if schedule == 'dependent' and not dependent:
        raise DemistoException('Error: Dependent schedule must include a dependent scan ID')


def process_launch_scan_response(res: dict[str, Any]):
    """
    Process the launch scan response.
    Args:
        res (Dict): the launch scan response.
    Returns:
        CommandResults: command results object with the response, human readable section, and the context entries to add.
    """
    scan_result = res['response']['scanResult']

    headers = [
        'Name',
        'ID',
        'OwnerID',
        'JobID',
        'Status'
    ]

    mapped_scan = {
        'Name': scan_result['name'],
        'ID': scan_result['id'],
        'OwnerID': scan_result['ownerID'],
        'JobID': scan_result['jobID'],
        'Status': scan_result['status']
    }

    return CommandResults(
        outputs=createContext(mapped_scan, removeNull=True),
        outputs_prefix='TenableSC.ScanResults',
        raw_response=res,
        outputs_key_field='ID',
        readable_output=tableToMarkdown('Tenable.sc Scan', mapped_scan, headers, removeNull=True)
    )


@polling_function(name='tenable-sc-launch-scan',
                  requires_polling_arg=True,
                  poll_message="Scan in progress.",
                  timeout=arg_to_number(demisto.args().get("timeout_in_seconds", '10800')))
def launch_scan_command(args: dict[str, Any], client: Client):
    """
    Polling command. Launch a scan by a given scan ID, following the scan status and retrieve the scan report.
    Args:
        args (Dict): demisto.args() object.
        client (Client): The tenable.sc client object.
    Returns:
        CommandResults: command results object with the response, human readable section, and the context entries to add.
    """
    first_execution = not args.get("scan_results_id")
    if first_execution:
        res = launch_scan(client, args)
        if not argToBoolean(args.get("polling", "false")):
            return PollResult(process_launch_scan_response(res))
        scan_results_id = res.get("response", {}).get("scanResult", {}).get("id")
        args["scan_results_id"] = scan_results_id
        demisto.info(f"Running poll command for results id: {scan_results_id}")
    else:
        scan_results_id = args.get("scan_results_id")
        args["hide_polling_output"] = True
    scan_results, _ = get_scan_status(client, args)
    scan_status = scan_results[0].get("status")
    if scan_status == "Error":
        raise DemistoException(f"Encountered the following error during the execution {scan_results[0].get('errorDetails')}")
    elif scan_status != "Completed":
        return PollResult(continue_to_poll=True, response=scan_results, args_for_next_run=args)
    else:
        return PollResult(get_scan_report_command(client, args))


def launch_scan(client: Client, args: dict[str, Any]):
    """
    Launching a scan with a given scan ID.
    Args:
        client (Client): The tenable.sc client object.
        args (Dict): demisto.args() object.
    Returns:
        Dict: The response for the launch scan request.
    """
    scan_id = args.get('scan_id')
    target_address = args.get('diagnostic_target')
    target_password = args.get('diagnostic_password')

    if (target_address and not target_password) or (target_password and not target_address):
        raise DemistoException("Error: If one of diagnostic target or password is provided, both of them must be provided.")

    res = client.launch_scan(scan_id, {'address': target_address, 'password': target_password})

    if not res or 'response' not in res or not res['response'] or 'scanResult' not in res['response']:
        raise DemistoException('Error: Could not retrieve the scan.')

    return res


def get_scan_status_command(client: Client, args: dict[str, Any]):
    """
    Return information about the scan status by a given scan results ID.
    Args:
        client (Client): The tenable.sc client object.
        args (Dict): demisto.args() object.
    Returns:
        CommandResults: command results object with the response, human readable section, and the context entries to add.
    """
    scans_results, res = get_scan_status(client, args)

    headers = ['ID', 'Name', 'Status', 'Description', 'Error']

    mapped_scans_results = [{
        'ID': scan_result['id'],
        'Name': scan_result['name'],
        'Status': scan_result['status'],
        'Description': scan_result['description'],
        'Error': scan_result['errorDetails'] if scan_result['status'] == 'Error' else ""
    } for scan_result in scans_results]

    return CommandResults(
        outputs=createContext(mapped_scans_results, removeNull=True),
        outputs_prefix='TenableSC.ScanResults',
        raw_response=res,
        outputs_key_field='ID',
        readable_output=tableToMarkdown('Tenable.sc Scan Status', mapped_scans_results, headers, removeNull=True)
    )


def get_scan_status(client: Client, args: dict[str, Any]):
    """
    Return information about the scan status by a given scan results ID.
    Args:
        client (Client): The tenable.sc client object.
        args (Dict): demisto.args() object.
    Returns:
        Dict: The relevant extracted section from the response.
        Dict: The response.
    """
    scan_results_ids = argToList(args.get('scan_results_id'))

    scans_results = []
    for scan_results_id in scan_results_ids:
        res = client.get_scan_results(scan_results_id)
        if not (res and res.get('response')):
            raise DemistoException('Scan results not found')

        scans_results.append(res['response'])
    return scans_results, res


def get_scan_report_command(client: Client, args: dict[str, Any]):
    """
    Return scan report information by a given scan results ID.
    Args:
        client (Client): The tenable.sc client object.
        args (Dict): demisto.args() object.
    Returns:
        CommandResults: command results object with the response, human readable section, and the context entries to add.
    """
    scan_results_id = args.get('scan_results_id')
    vulnerabilities_to_get = argToList(args.get('vulnerability_severity', []))

    res = client.get_scan_report(scan_results_id)

    if not (res and res.get('response')):
        raise DemistoException('Scan results not found')

    scan_results = res['response']

    headers = ['ID', 'Name', 'Description', 'Policy', 'Group', 'Owner', 'ScannedIPs',
               'StartTime', 'EndTime', 'Duration', 'Checks', 'ImportTime', 'RepositoryName', 'Status',
               'Scan Type', 'ImportStatus', 'IsScanRunning', 'CompletedIPs']
    vuln_headers = ['ID', 'Name', 'Family', 'Severity', 'Total']

    mapped_results = {
        'Scan Type': res.get('type', ''),
        'ID': scan_results.get('id', ''),
        'Name': scan_results.get('name', ''),
        'Status': scan_results.get('status', ''),
        'Description': scan_results.get('description', ''),
        'Policy': scan_results.get('details', ''),
        'Group': scan_results.get('ownerGroup', {}).get('name'),
        'Checks': scan_results.get('completedChecks', ''),
        'StartTime': timestamp_to_utc(scan_results.get('startTime', '')),
        'EndTime': timestamp_to_utc(scan_results.get('finishTime', '')),
        'Duration': scan_duration_to_demisto_format(scan_results.get('scanDuration', '')),
        'ImportTime': timestamp_to_utc(scan_results.get('importStart', '')),
        'ScannedIPs': scan_results.get('scannedIPs', ''),
        'Owner': scan_results.get('owner', {}).get('username', ''),
        'RepositoryName': scan_results.get('repository', {}).get('name', ''),
        'ImportStatus': scan_results.get('importStatus', ''),
        'IsScanRunning': scan_results.get('running', '')
    }

    if progress := scan_results.get('progress', {}):
        mapped_results["Completed IPs"] = progress.get('completedIPs', '')

    hr = tableToMarkdown('Tenable.sc Scan ' + mapped_results['ID'] + ' Report',
                         mapped_results, headers, removeNull=True)

    if len(vulnerabilities_to_get) > 0 and scan_results.get("importStatus", "") != "Error":
        vulns = get_vulnerabilities(client, scan_results_id)

        if isinstance(vulns, list):
            vulnerabilities = list(filter(lambda v: v['Severity'] in vulnerabilities_to_get, vulns))
            if vulnerabilities and len(vulnerabilities) > 0:
                hr += tableToMarkdown('Vulnerabilities', vulnerabilities, vuln_headers, removeNull=True)
                mapped_results['Vulnerability'] = vulnerabilities

    return CommandResults(
        outputs=createContext(mapped_results, removeNull=True),
        outputs_prefix='TenableSC.ScanResults',
        raw_response=res,
        outputs_key_field='ID',
        readable_output=hr
    )


def get_vulnerabilities(client: Client, scan_results_id):
    """
    Lists vulnerabilities from a scan by a given scan results ID.
    Args:
        client (Client): The tenable.sc client object.
        scan_results_id (str): The ID of the scan results to get the information from.
    Returns:
        List: Sorted vulnerabilities list.
    """
    query = client.create_query(scan_results_id, 'vulnipdetail')

    if not query or 'response' not in query:
        return 'Could not get vulnerabilites query'

    body = {
        'type': 'vuln',
        'view': 'all',
        'sourceType': 'individual',
        'scanID': scan_results_id,
        'query': {"id": query.get('response', {}).get('id')}
    }

    analysis = client.get_analysis(body=body)

    client.delete_query(query.get('response', {}).get('id'))

    if not analysis or 'response' not in analysis:
        return 'Could not get vulnerabilites analysis'

    results = analysis['response']['results']

    if not results or len(results) == 0:
        return 'No vulnerabilities found'

    mapped_vulns = []

    for vuln in results:
        mapped_vuln = {
            'ID': vuln['pluginID'],
            'Name': vuln['name'],
            'Description': vuln['pluginDescription'],
            'Family': vuln['family'].get('name'),
            'Severity': vuln['severity'].get('name'),
            'Total': vuln['total']
        }

        mapped_vulns.append(mapped_vuln)

    sv_level = {
        'Critical': 4,
        'High': 3,
        'Medium': 2,
        'Low': 1,
        'Info': 0
    }

    mapped_vulns.sort(key=lambda r: sv_level[r['Severity']])

    return mapped_vulns


def get_vulnerability_command(client: Client, args: dict[str, Any]):
    """
    Return information about a vulnerability by a given vulnerability ID.
    Args:
        client (Client): The tenable.sc client object.
        args (Dict): demisto.args() object.
    Returns:
        CommandResults: command results object with the response, human readable section, and the context entries to add.
    """
    vuln_id = args.get('vulnerability_id')
    scan_results_id = args.get('scan_results_id')

    analysis = client.get_analysis(args=args)

    if not analysis or 'response' not in analysis:
        raise DemistoException('Error: Could not get vulnerability analysis')

    results = analysis['response']['results']

    if not results or len(results) == 0:
        raise DemistoException('Error: Vulnerability not found in the scan results')

    vuln_response = client.get_vulnerability(vuln_id)

    if not vuln_response or 'response' not in vuln_response:
        raise DemistoException('Vulnerability not found')

    vuln = vuln_response['response']
    vuln['severity'] = results[0]['severity']  # The vulnerability severity is the same in all the results

    hosts = get_vulnerability_hosts_from_analysis(results)

    cves = None
    cves_output = []  # type: List[dict]
    if vuln.get('xrefs'):
        # Extract CVE
        cve_filter = list(filter(lambda x: x.strip().startswith('CVE'), vuln['xrefs'].split(',')))
        if cve_filter and len(cve_filter) > 0:
            cves = [c.replace('CVE:', '').strip() for c in cve_filter]
            cves_output += ({
                'ID': c
            } for c in cves)

    mapped_vuln = {
        'ID': vuln['id'],
        'Name': vuln['name'],
        'Description': vuln['description'],
        'Type': vuln['type'],
        'Severity': vuln.get('severity', {}).get('name'),
        'Synopsis': vuln['synopsis'],
        'Solution': vuln['solution']
    }

    vuln_info = {
        'Published': timestamp_to_utc(vuln['vulnPubDate']),
        'CPE': vuln['cpe'],
        'CVE': cves
    }

    exploit_info = {
        'ExploitAvailable': vuln['exploitAvailable'],
        'ExploitEase': vuln['exploitEase']
    }

    risk_info = {
        'RiskFactor': vuln['riskFactor'],
        'CVSSBaseScore': vuln['baseScore'],
        'CVSSTemporalScore': vuln['temporalScore'],
        'CVSSVector': vuln['cvssVector']
    }

    plugin_details = {
        'Family': vuln['family'].get('name'),
        'Published': timestamp_to_utc(vuln['pluginPubDate']),
        'Modified': timestamp_to_utc(vuln['pluginModDate']),
        'CheckType': vuln['checkType']
    }

    hr = '## Vulnerability: {} ({})\n'.format(mapped_vuln['Name'], mapped_vuln['ID'])
    hr += '### Synopsis\n{}\n### Description\n{}\n### Solution\n{}\n'.format(
        mapped_vuln['Synopsis'], mapped_vuln['Description'], mapped_vuln['Solution'])
    hr += tableToMarkdown('Hosts', hosts, removeNull=True)
    hr += tableToMarkdown('Risk Information', risk_info, removeNull=True)
    hr += tableToMarkdown('Exploit Information', exploit_info, removeNull=True)
    hr += tableToMarkdown('Plugin Details', plugin_details, removeNull=True)
    hr += tableToMarkdown('Vulnerability Information', vuln_info, removeNull=True)

    mapped_vuln.update(vuln_info)
    mapped_vuln.update(exploit_info)
    mapped_vuln.update(risk_info)
    mapped_vuln['PluginDetails'] = plugin_details
    mapped_vuln['Host'] = hosts

    scan_result = {
        'ID': scan_results_id,
        'Vulnerability': mapped_vuln,
    }
    command_results = [
        CommandResults(
            outputs=createContext(scan_result['Vulnerability'], removeNull=True),
            outputs_prefix='TenableSC.ScanResults.Vulnerability',
            raw_response=vuln_response,
            outputs_key_field='ID',
            readable_output=hr
        )
    ]

    if len(cves_output) > 0:
        command_results.append(CommandResults(outputs=createContext(cves_output), outputs_prefix='CVE', outputs_key_field='ID'))

    return command_results


def get_vulnerability_hosts_from_analysis(results):
    """
    Lists the vulnerability hosts from given analysis.
    Args:
        results (Dict): The analysis results.
    Returns:
        List: list of all the vulnerability hosts extracted from the results.
    """
    return [{
        'IP': host.get('ip'),
        'MAC': host.get('macAddress'),
        'Port': host.get('port'),
        'Protocol': host.get('protocol')
    } for host in results]


def delete_scan_command(client: Client, args: dict[str, Any]):
    """
    Deletes a scan.
    Args:
        client (Client): The tenable.sc client object.
        args (Dict): demisto.args() object.
    Returns:
        CommandResults: command results object with the response, and the human readable section.
    """
    scan_id = args.get('scan_id')

    res = client.delete_scan(scan_id)

    if not res:
        raise DemistoException('Error: Could not delete the scan')

    return CommandResults(
        raw_response=res,
        readable_output=f"Scan {scan_id} was deleted successfully."
    )


def get_device_command(client: Client, args: dict[str, Any]):
    """
    Returns device info by a given device UUID.
    Args:
        client (Client): The tenable.sc client object.
        args (Dict): demisto.args() object.
    Returns:
        CommandResults: command results object with the response, human readable section, and the context entries to add.
    """
    uuid = args.get('uuid')
    ip = args.get('ip')
    dns_name = args.get('dns_name')
    repo = args.get('repository_id')

    res = client.get_device(uuid, ip, dns_name, repo)

    if not res or 'response' not in res:
        raise DemistoException('Device not found')

    device = res['response']

    headers = [
        'IP', 'UUID', 'MacAddress', 'RepositoryID', 'RepositoryName', 'NetbiosName', 'DNSName', 'OS', 'OsCPE', 'LastScan',
        'TotalScore', 'LowSeverity', 'MediumSeverity', 'HighSeverity', 'CriticalSeverity'
    ]

    mapped_device = {
        'IP': device['ip'],
        'UUID': device.get('uuid'),
        'MacAddress': device.get('macAddress'),
        'RepositoryID': device.get('repository', {}).get('id'),
        'RepositoryName': device.get('repository', {}).get('name'),
        'NetbiosName': device.get('netbiosName'),
        'DNSName': device.get('dnsName'),
        'OS': re.sub('<[^<]+?>', ' ', device['os']).lstrip() if device.get('os') else '',
        'OsCPE': device.get('osCPE'),
        'LastScan': timestamp_to_utc(device.get('lastScan')),
        'TotalScore': device.get('total'),
        'LowSeverity': device.get('severityLow'),
        'MediumSeverity': device.get('severityMedium'),
        'HighSeverity': device.get('severityHigh'),
        'CriticalSeverity': device.get('severityCritical')
    }

    endpoint = {
        'IPAddress': mapped_device['IP'],
        'MACAddress': mapped_device['MacAddress'],
        'Hostname': mapped_device['DNSName'],
        'OS': mapped_device['OS']
    }

    command_results = [
        CommandResults(
            outputs=createContext(mapped_device, removeNull=True),
            outputs_prefix='TenableSC.Device',
            raw_response=res,
            outputs_key_field='UUID',
            readable_output=tableToMarkdown('Tenable.sc Device', mapped_device, headers=headers, removeNull=True)
        ),
        CommandResults(
            outputs=createContext(endpoint, removeNull=True),
            outputs_prefix='Endpoint',
            outputs_key_field='IP'
        )
    ]

    return command_results


def list_users_command(client: Client, args: dict[str, Any]):
    """
    Lists all users.
    Args:
        client (Client): The tenable.sc client object.
        args (Dict): demisto.args() object.
    Returns:
        CommandResults: command results object with the response, human readable section, and the context entries to add.
    """
    user_id = args.get('id')
    username = args.get('username')
    email = args.get('email')

    res = client.get_users('id,username,firstname,lastname,title,email,createdTime,modifiedTime,lastLogin,role', user_id)

    if not res or 'response' not in res:
        raise DemistoException('No users found')

    users = res['response']

    if not isinstance(users, list):
        users = [users]

    if not user_id:
        if username:
            users = list(filter(lambda u: u['username'] == username, users))
        elif email:
            users = list(filter(lambda u: u['email'] == email, users))

    if len(users) == 0:
        raise DemistoException('No users found')

    headers = [
        'ID', 'Username', 'Firstname', 'Lastname', 'Title', 'Email', 'Created', 'Modified', 'LastLogin', 'Role'
    ]

    mapped_users = [{
        'ID': user['id'],
        'Username': user['username'],
        'FirstName': user['firstname'],
        'LastName': user['lastname'],
        'Title': user['title'],
        'Email': user['email'],
        'Created': timestamp_to_utc(user['createdTime']),
        'Modified': timestamp_to_utc(user['modifiedTime']),
        'LastLogin': timestamp_to_utc(user['lastLogin']),
        'Role': user['role'].get('name')
    } for user in users]

    return CommandResults(
        outputs=createContext(mapped_users, removeNull=True),
        outputs_prefix='TenableSC.User',
        raw_response=res,
        outputs_key_field='ID',
        readable_output=tableToMarkdown('Tenable.sc Users', mapped_users, headers=headers, removeNull=True)
    )


def get_system_licensing_command(client: Client, args: dict[str, Any]):
    """
    Returns system licensing information.
    Args:
        client (Client): The tenable.sc client object.
        args (Dict): demisto.args() object.
    Returns:
        CommandResults: command results object with the response, human readable section, and the context entries to add.
    """
    res = client.get_system_licensing()

    if not res or 'response' not in res:
        raise DemistoException('Error: Could not retrieve system licensing')

    status = res['response']

    mapped_licensing = {
        'License': status['licenseStatus'],
        'LicensedIPS': status['licensedIPs'],
        'ActiveIPS': status['activeIPs']
    }

    headers = [
        'License',
        'LicensedIPS',
        'ActiveIPS'
    ]

    return CommandResults(
        outputs=createContext(mapped_licensing, removeNull=True),
        outputs_prefix='TenableSC.Status',
        raw_response=res,
        outputs_key_field='ID',
        readable_output=tableToMarkdown('Tenable.sc Licensing information', mapped_licensing, headers=headers, removeNull=True)
    )


def get_system_information_command(client: Client, args: dict[str, Any]):
    """
    Return system information.
    Args:
        client (Client): The tenable.sc client object.
        args (Dict): demisto.args() object.
    Returns:
        CommandResults: command results object with the response, human readable section, and the context entries to add.
    """
    sys_res = client.get_system()

    if not sys_res or 'response' not in sys_res:
        raise DemistoException('Error: Could not retrieve system information')

    diag_res = client.get_system_diagnostics()

    if not diag_res or 'response' not in diag_res:
        raise DemistoException('Error: Could not retrieve system information')

    sys_res.update(diag_res)
    diagnostics = diag_res['response']
    system = sys_res['response']

    mapped_information = {
        'Version': system.get('version'),
        'BuildID': system.get('buildID'),
        'ReleaseID': system.get('releaseID'),
        'License': system.get('licenseStatus'),
        'RPMStatus': diagnostics.get('statusRPM'),
        'JavaStatus': diagnostics.get('statusJava'),
        'DiskStatus': diagnostics.get('statusDisk'),
        'DiskThreshold': diagnostics.get('statusThresholdDisk'),
        'LastCheck': timestamp_to_utc(diagnostics.get('statusLastChecked')),
    }

    headers = [
        'Version', 'BuildID', 'ReleaseID', 'License', 'RPMStatus', 'JavaStatus', 'DiskStatus', 'DiskThreshold', 'LastCheck'
    ]

    return CommandResults(
        outputs=createContext(mapped_information, removeNull=True),
        outputs_prefix='TenableSC.System',
        raw_response=sys_res,
        outputs_key_field='BuildID',
        readable_output=tableToMarkdown('Tenable.sc System information', mapped_information, headers=headers, removeNull=True)
    )


def list_alerts_command(client: Client, args: dict[str, Any]):
    """
    Lists all alerts.
    Args:
        client (Client): The tenable.sc client object.
        args (Dict): demisto.args() object.
    Returns:
        CommandResults: command results object with the response, human readable section, and the context entries to add.
    """
    res = client.get_alerts(fields='id,name,description,didTriggerLastEvaluation,lastTriggered,'
                            'action,lastEvaluated,ownerGroup,owner')
    manageable = args.get('manageable', 'false').lower()

    if not (res and res.get('response')):
        raise DemistoException('No alerts found')

    alerts = get_elements(res['response'], manageable)

    if len(alerts) == 0:
        raise DemistoException('No alerts found')

    headers = ['ID', 'Name', 'Actions', 'State', 'LastTriggered', 'LastEvaluated', 'Group', 'Owner']
    mapped_alerts = [{
        'ID': a['id'],
        'Name': a['name'],
        'State': 'Triggered' if a['didTriggerLastEvaluation'] == 'true' else 'Not Triggered',
        'Actions': demisto.dt(a['action'], 'type'),
        'LastTriggered': timestamp_to_utc(a['lastTriggered'], default_returned_value='Never'),
        'LastEvaluated': timestamp_to_utc(a['lastEvaluated']),
        'Group': a['ownerGroup'].get('name'),
        'Owner': a['owner'].get('username')
    } for a in alerts]

    return CommandResults(
        outputs=createContext(mapped_alerts, removeNull=True),
        outputs_prefix='TenableSC.Alert',
        raw_response=res,
        outputs_key_field='ID',
        readable_output=tableToMarkdown('Tenable.sc Alerts', mapped_alerts, headers=headers, removeNull=True)
    )


def get_alert_command(client: Client, args: dict[str, Any]):
    """
    Return information about an alert by a given alert ID.
    Args:
        client (Client): The tenable.sc client object.
        args (Dict): demisto.args() object.
    Returns:
        CommandResults: command results object with the response, human readable section, and the context entries to add.
    """
    alert_id = args.get('alert_id')
    res = client.get_alerts(alert_id=alert_id)

    if not (res and res.get('response')):
        raise DemistoException('Alert not found')

    alert = res['response']
    query_res = client.get_query(alert.get('query', {}).get('id'))
    query = query_res.get('response')

    alert_headers = ['ID', 'Name', 'Description', 'LastTriggered', 'State', 'Behavior', 'Actions']
    query_headers = ['Trigger', 'Query']
    action_headers = ['Type', 'Values']

    filter_headers = ['Name', 'Values']
    mapped_alert = {
        'ID': alert['id'],
        'Name': alert['name'],
        'Description': alert['description'],
        'LastTriggered': timestamp_to_utc(alert['lastTriggered'], default_returned_value='Never'),
        'State': 'Triggered' if alert['didTriggerLastEvaluation'] == 'true' else 'Not Triggered',
        'Behavior': 'Execute on every trigger ' if alert['executeOnEveryTrigger'] == 'true' else 'Execute only on'
                                                                                                 ' first trigger'
    }

    mapped_condition = {
        'Trigger': '{} {} {}'.format(alert['triggerName'], alert['triggerOperator'], alert['triggerValue']),
        'Query': alert['query'].get('name')
    }

    mapped_filters = None
    if query:
        mapped_filters = [{
            'Name': f['filterName'],
            'Values': demisto.dt(f['value'], 'name') if isinstance(f['value'], list) else f['value']
        } for f in query.get('filters', [])]
        mapped_condition['Filter'] = mapped_filters

    mapped_actions = [{
        'Type': a['type'],
        'Values': demisto.dt(a, '{}.{}'.format('definition', ACTION_TYPE_TO_VALUE[a['type']]))
    } for a in alert['action']]

    hr = tableToMarkdown('Tenable.sc Alert', mapped_alert, headers=alert_headers, removeNull=True)
    hr += tableToMarkdown('Condition', mapped_condition, headers=query_headers, removeNull=True)
    if mapped_filters:
        hr += tableToMarkdown('Filters', mapped_filters, headers=filter_headers, removeNull=True)
    if mapped_actions:
        hr += tableToMarkdown('Actions', mapped_actions, headers=action_headers, removeNull=True)
        mapped_alert['Action'] = mapped_actions

    mapped_alert['Condition'] = mapped_condition

    return CommandResults(
        outputs=createContext(mapped_alert, removeNull=True),
        outputs_prefix='TenableSC.Alert',
        raw_response=res,
        outputs_key_field='ID',
        readable_output=hr
    )


def get_organization_command(client: Client, args: dict[str, Any]):
    """
    Returns organization information.
    Args:
        client (Client): The tenable.sc client object.
        args (Dict): demisto.args() object.
    Returns:
        CommandResults: command results object with the response, human readable section, and the context entries to add.
    """
    fields = argToList(args.get('fields', None))
    res = client.get_organization(fields)

    if not res or 'response' not in res:
        raise DemistoException('Error: Could not retrieve organization information')

    response = res.get('response', {})
    res_output = []
    if response:
        for curr_res in response:
            restrictedIPMap = {
                'ID': curr_res.get('id', ''),
                'Name': curr_res.get('name', ''),
            }
            for field in fields:
                restrictedIPMap[field] = curr_res.get(field, '')
            res_output.append(restrictedIPMap)

    return CommandResults(
        outputs=createContext(response, removeNull=True),
        outputs_prefix='TenableSC.Organization',
        raw_response=res,
        outputs_key_field='ID',
        readable_output=tableToMarkdown('Tenable.sc Orgnization', res_output, removeNull=True)
    )


def fetch_incidents(client: Client, first_fetch: str = '3 days'):
    """
    fetches incidents and upload them to demisto.incidents().
    Args:
        client (Client): The tenable.sc client object.
        first_fetch (str): The first_fetch integration param.
    """
    incidents = []
    last_run = demisto.getLastRun()
    if not last_run:
        last_run = {}
    if 'time' not in last_run:
        # get timestamp in seconds
        timestamp, _ = parse_date_range(first_fetch, to_timestamp=True)
        timestamp /= 1000
    else:
        timestamp = last_run['time']

    max_timestamp = timestamp
    res = client.get_alerts(
        fields='id,name,description,lastTriggered,triggerName,triggerOperator,'
               'triggerValue,action,query,owner,ownerGroup,schedule,canManage')

    alerts = get_elements(res.get('response', {}), manageable='false')
    for alert in alerts:
        # 0 corresponds to never triggered
        if int(alert.get('lastTriggered', 0)) > timestamp:
            incidents.append({
                'name': 'Tenable.sc Alert Triggered - ' + alert['name'],
                'occurred': timestamp_to_utc(alert['lastTriggered']),
                'rawJSON': json.dumps(alert)
            })

            if int(alert['lastTriggered']) > max_timestamp:
                max_timestamp = int(alert['lastTriggered'])

    demisto.incidents(incidents)
    demisto.setLastRun({'time': max_timestamp})


def list_groups_command(client: Client, args: dict[str, Any]):
    """
    Lists all groups
    Args:
        client (Client): The tenable.sc client object.
        args (Dict): demisto.args() object.
    Returns:
        CommandResults: command results object with the response, human readable section, and the context entries to add.
    """
    show_users = argToBoolean(args.get("show_users", True))
    limit = int(args.get('limit', '50'))
    res = client.list_groups(show_users)
    if not res or not res.get('response', []):
        raise DemistoException('No groups found')
    groups = res.get('response', [])
    if len(groups) > limit:
        groups = groups[:limit]
    mapped_groups = [{
        'ID': group.get('id'),
        'Name': group.get('name'),
        'Description': group.get('description')
    } for group in groups]
    headers = ['ID', 'Name', 'Description']
    hr = tableToMarkdown('Tenable.sc groups', mapped_groups, headers, removeNull=True)
    if show_users:
        headers = ['Username', 'Firstname', 'Lastname']
        users = []
        for index, group in enumerate(groups):
            users = [{
                'Username': user.get('username', ""),
                'Firstname': user.get('firstname', ""),
                'Lastname': user.get('lastname', ""),
                'ID': user.get('id', ""),
                'UUID': user.get('UUID', "")
            } for user in group.get('users')]
            mapped_groups[index]['Users'] = users
            group_id = group.get('id')
            hr += f"{tableToMarkdown(f'Group id:{group_id}', users, headers, removeNull=True)}\n"
    return CommandResults(
        outputs=createContext(response_to_context(groups), removeNull=True),
        outputs_prefix='TenableSC.Group',
        raw_response=res,
        outputs_key_field='ID',
        readable_output=hr
    )


def get_all_scan_results_command(client: Client, args: dict[str, Any]):
    """
    Lists all scan results.
    Args:
        client (Client): The tenable.sc client object.
        args (Dict): demisto.args() object.
    Returns:
        CommandResults: command results object with the response, human readable section, and the context entries to add.
    """
    res = client.get_all_scan_results()
    get_manageable_results = args.get('manageable', 'false').lower()  # 'true' or 'false'
    page = int(args.get('page', '0'))
    limit = int(args.get('limit', '50'))
    if limit > 200:
        limit = 200

    if not (res and res.get('response')):
        raise DemistoException('Scan results not found')

    elements = get_elements(res['response'], get_manageable_results)

    headers = ['ID', 'Name', 'Status', 'Description', 'Policy', 'Group', 'Owner', 'ScannedIPs',
               'StartTime', 'EndTime', 'Duration', 'Checks', 'ImportTime', 'RepositoryName']

    scan_results = [{
        'ID': elem['id'],
        'Name': elem['name'],
        'Status': elem['status'],
        'Description': elem.get('description', None),
        'Policy': elem['details'],
        'Group': elem.get('ownerGroup', {}).get('name'),
        'Checks': elem.get('completedChecks', None),
        'StartTime': timestamp_to_utc(elem['startTime']),
        'EndTime': timestamp_to_utc(elem['finishTime']),
        'Duration': scan_duration_to_demisto_format(elem['scanDuration']),
        'ImportTime': timestamp_to_utc(elem['importStart']),
        'ScannedIPs': elem['scannedIPs'],
        'Owner': elem['owner'].get('username'),
        'RepositoryName': elem['repository'].get('name'),
        'ImportStatus': elem.get('importStatus', '')
    } for elem in elements[page:page + limit]]

    readable_title = f'Tenable.sc Scan results - {page}-{page + limit - 1}'
    hr = tableToMarkdown(readable_title, scan_results, headers, removeNull=True,
                         metadata=f'Total number of elements is {len(elements)}')

    return CommandResults(
        outputs=createContext(scan_results, removeNull=True),
        outputs_prefix='TenableSC.ScanResults',
        raw_response=res,
        outputs_key_field='ID',
        readable_output=hr
    )


def create_user_command(client: Client, args: dict[str, Any]):
    """
    Create a user.
    Args:
        client (Client): The tenable.sc client object.
        args (Dict): demisto.args() object.
    Returns:
        CommandResults: command results object with the response, human readable section, and the context entries to add.
    """
    validate_user_body_params(args, "create")
    res = client.create_user(args)
    hr_header = f'User {args.get("user_name")} was created successfully.'
    return process_update_and_create_user_response(res, hr_header)


def update_user_command(client: Client, args: dict[str, Any]):
    """
    Update a user by given user ID.
    Args:
        client (Client): The tenable.sc client object.
        args (Dict): demisto.args() object.
    Returns:
        CommandResults: command results object with the response, human readable section, and the context entries to add.
    """
    user_id = args.get('user_id')
    validate_user_body_params(args, "update")
    res = client.update_user(args, user_id)
    hr_header = f'user {args.get("user_id")} was updated successfully.'
    return process_update_and_create_user_response(res, hr_header)


def process_update_and_create_user_response(res, hr_header):
    """
    Process the response returned from the update and create user requests
    Args:
        res (Dict): The response returned from the request
        hr_header (Dict): The header to add to the hr section.
    Returns:
        CommandResults: command results object with the response, human readable section, and the context entries to add.
    """
    if not res or not res.get('response', {}):
        raise DemistoException("User wasn't created successfully.")
    headers = ["User type", "User ID", "User Status", "User Name", "First Name", "Lat Name ", "Email ", "User Role Name",
               "User Group Name", "User  LDAP  Name"]
    response = res.get("response", {})
    mapped_response = {
        "User type": res.get("type"),
        "User ID": response.get("id"),
        "User Status": response.get("status"),
        "User Name": response.get("username"),
        "First Name": response.get("firstname"),
        "Lat Name ": response.get("lastname"),
        "Email ": response.get("email"),
        "User Role Name": response.get("role", {}).get("name"),
        "User Group Name": response.get("group", {}).get("name"),
        "User  LDAP  Name": response.get("ldap", {}).get("name")
    }

    return CommandResults(
        outputs=createContext(response_to_context(response), removeNull=True),
        outputs_prefix='TenableSC.User',
        raw_response=res,
        outputs_key_field='ID',
        readable_output=tableToMarkdown(hr_header, mapped_response, headers, removeNull=True)
    )


def delete_user_command(client: Client, args: dict[str, Any]):
    """
   Delete a user by a given user ID.
    Args:
        client (Client): The tenable.sc client object.
        args (Dict): demisto.args() object.
    Returns:
        CommandResults: command results object with the response, and human readable section.
    """
    user_id = args.get('user_id')
    res = client.delete_user(user_id)

    return CommandResults(
        raw_response=res,
        readable_output=f"User {user_id} was deleted successfully."
    )


def list_plugin_family_command(client: Client, args: dict[str, Any]):
    """
    return info about a query / list of queries.
    Args:
        client (Client): The tenable.sc client object.
        args (Dict): demisto.args() object.
    Returns:
        CommandResults: command results object with the response, human readable section, and the context entries to add.
    """
    is_active = args.get('is_active')
    limit = int(args.get('limit', '50'))
    plugin_id = args.get('plugin_id', '')
    res = client.list_plugin_family(plugin_id, is_active)
    if not res or not res.get('response', []):
        raise DemistoException('No plugins found')
    plugins = res.get('response')
    if isinstance(plugins, dict):
        if plugin_type := plugins.get("type") in ["active", "passive"]:
            is_active = "false" if plugin_type == "passive" else "true"
        plugins = [plugins]
    if len(plugins) > limit:
        plugins = plugins[:limit]
    mapped_plugins = [{"Plugin ID": plugin.get("id"), "Plugin Name": plugin.get("name")} for plugin in plugins]
    if is_active:
        for mapped_plugin in mapped_plugins:
            mapped_plugin["Is Active"] = is_active
    headers = ["Plugin ID", "Plugin Name", "Is Active"]
    return CommandResults(
        outputs=createContext(response_to_context(plugins), removeNull=True),
        outputs_prefix='TenableSC.PluginFamily',
        raw_response=res,
        outputs_key_field='ID',
        readable_output=tableToMarkdown('Plugin families:', mapped_plugins, headers, removeNull=True)
    )


def create_policy_command(client: Client, args: dict[str, Any]):
    """
    Creates a policy.
    Args:
        client (Client): The tenable.sc client object.
        args (Dict): demisto.args() object.
    Returns:
        CommandResults: command results object with the response, human readable section, and the context entries to add.
    """
    res = client.create_policy(args)
    created_policy = res.get("response")
    mapped_created_policy = {
        "Policy type": res.get("type"),
        "Policy ID": created_policy.get("id"),
        "name": created_policy.get("name"),
        "Description": created_policy.get("description"),
        "Created Time": created_policy.get("createdTime"),
        "Plugin Families": created_policy.get("families"),
        "Policy  Status": created_policy.get("status"),
        "Policy UUID": created_policy.get("uuid"),
        "Policy can Manage": created_policy.get("canManage"),
        "Creator Username": created_policy.get("creator", {}).get("username"),
        "Owner ID": created_policy.get("ownerID"),
        "policyTemplate ID": created_policy.get("policyTemplate", {}).get("id"),
        "policyTemplate Name": created_policy.get("policyTemplate", {}).get("name")
    }
    headers = ["Policy type", "Policy ID", "name", "Description", "Created Time", "Plugin Families", "Policy  Status",
               "Policy UUID", "Policy can Manage", "Creator Username", "Owner ID", "policyTemplate id",
               "policyTemplate Name"]

    return CommandResults(
        outputs=createContext(response_to_context(created_policy), removeNull=True),
        outputs_prefix='TenableSC.ScanPolicy',
        raw_response=res,
        outputs_key_field='ID',
        readable_output=tableToMarkdown('Policy was created successfully:', mapped_created_policy, headers, removeNull=True)
    )


def create_remediation_scan_command(client: Client, args: dict[str, Any]):
    """
    Creates remediation scan.
    Args:
        client (Client): The tenable.sc client object.
        args (Dict): demisto.args() object.
    Returns:
        CommandResults: command results object with the response, human readable section, and the context entries to add.
    """
    args["policy_template_id"] = '1'
    args["scan_type"] = "policy"
    args["schedule"] = "now"
    validate_create_scan_inputs(args)
    res = client.create_policy(args)
    created_policy = res.get("response")
    args["policy_id"] = created_policy.get("id")
    res = client.create_scan(args)
    if not res or 'response' not in res:
        raise DemistoException('Error: Could not retrieve the scan')

    scan = res.get('response', {})

    headers = ['Scan ID', 'Scan Name', 'Scan Description', 'Scan Type', 'Dhcp Tracking status', 'Created Time', 'Modified Time',
               'Max Scan Time', 'Policy id ', 'Policy context', 'Policy description', 'Schedule type', 'Start Time', 'Group',
               'Owner']

    mapped_scan = {
        'Scan ID': scan['id'],
        'Scan Name': scan['name'],
        'Scan Description': scan['description'],
        'Scan Type': scan['type'],
        'Dhcp Tracking status': scan["dhcpTracking"],
        'Created Time': timestamp_to_utc(scan['createdTime']),
        'Modified Time': scan["modifiedTime"],
        'Max Scan Time': scan["maxScanTime"],
        'Policy id ': scan["policy"]["id"],
        'Policy context': scan["policy"]["context"],
        'Policy description': scan["policy"]["description"],
        'Schedule type': scan["schedule"]["type"],
        'Start Time': scan["schedule"]["start"],
        'Group': scan["ownerGroup"]["name"],
        'Owner': scan["owner"]["username"],
    }

    return CommandResults(
        outputs=createContext(response_to_context(scan), removeNull=True),
        outputs_prefix='TenableSC.Scan',
        raw_response=res,
        outputs_key_field='ID',
        readable_output=tableToMarkdown('Remediation scan created successfully', mapped_scan, headers, removeNull=True)
    )


def list_query_command(client: Client, args: dict[str, Any]):
    """
    return info about a query / list of queries.
    Args:
        client (Client): The tenable.sc client object.
        args (Dict): demisto.args() object.
    Returns:
        CommandResults: command results object with the response, human readable section, and the context entries to add.
    """
    type = args.get('type')
    query_id = args.get('query_id', '')
    if query_id:
        res, hr, ec = get_query(client, query_id)
    else:
        res, hr, ec = list_queries(client, type)

    return CommandResults(
        outputs=createContext(response_to_context(ec), removeNull=True),
        outputs_prefix='TenableSC.Query',
        raw_response=res,
        outputs_key_field='ID',
        readable_output=hr
    )


def update_asset_command(client: Client, args: dict[str, Any]):
    """
    Update an asset by a given asset ID.
    Args:
        client (Client): The tenable.sc client object.
        args (Dict): demisto.args() object.
    Returns:
        CommandResults: command results object with the response and human readable.
    """
    asset_id = args.get('asset_id')
    res = client.update_asset(args, asset_id)
    if not res or not res.get('response', []):
        raise DemistoException("Couldn't update asset.")

    return CommandResults(
        raw_response=res,
        readable_output=f'asset {asset_id} was updated successfully.'
    )


def get_query(client: Client, query_id):
    """
    get a query by ID and return the processed results.
    Args:
        client (Client): The tenable.sc client object.
        query_id (str): The query ID to search.
    Returns:
        Dict: The response from the server.
        str: The processed human readable.
        Dict: The relevant section from the response.
    """
    res = client.get_query(query_id)
    if not res or not res.get('response', []):
        raise DemistoException(f"The query {query_id} wasn't found")
    query = res.get('response')
    mapped_query = {
        "Query ID": query_id,
        "Query  Name": query.get("name"),
        "Query Description": query.get("description"),
        "Query Filters": query.get("filters")
    }
    headers = ["Query ID", "Query  Name", "Query Description", "Query Filters"]
    hr = tableToMarkdown(f'Query {query_id}', mapped_query, headers, removeNull=True)
    return res, hr, query


def list_queries(client: Client, type):
    """
    Lists queries and return the processed results.
    Args:
        client (Client): The tenable.sc client object.
        type (str): query time to filter by.
    Returns:
        Dict: The response from the server.
        str: The processed human readable.
        Dict: The relevant section from the response.
    """
    res = client.list_queries(type)
    if not res or not res.get('response', []):
        raise DemistoException("No queries found.")
    queries = res.get('response')
    manageable_queries = queries.get("manageable", [])
    usable_queries = queries.get("usable", [])
    mapped_queries, mapped_usable_queries = [], []
    found_ids = []

    for manageable_query in manageable_queries:
        query_id = manageable_query.get("id")
        mapped_queries.append({
            "Query ID": query_id,
            "Query  Name": manageable_query.get("name"),
            "Query Description": manageable_query.get("description"),
            "Query Filters": manageable_query.get("filters"),
            "Query Manageable": "True"
        })
        found_ids.append(query_id)
    for usable_query in usable_queries:
        query_id = usable_query.get("id")
        if query_id not in found_ids:
            mapped_usable_queries.append({
                "Query ID": usable_query.get("id"),
                "Query  Name": usable_query.get("name"),
                "Query Description": usable_query.get("description"),
                "Query Filters": usable_query.get("filters"),
                "Query Usable": "True",
                "Query Manageable": "False"
            })
        else:
            for mapped_query in mapped_queries:
                if query_id == mapped_query["Query ID"]:
                    mapped_query["Query Usable"] = "True"

    for mapped_query in mapped_queries:
        if not mapped_query.get("Query Usable"):
            mapped_query["Query Usable"] = "False"

    mapped_queries.extend(mapped_usable_queries)
    headers = ["Query ID", "Query  Name", "Query Description", "Query Filters", "Query Manageable", "Query Usable"]
    hr = tableToMarkdown('Queries:', mapped_queries, headers, removeNull=True)
    return res, hr, queries


def test_module(client: Client, args: dict[str, Any]):
    """
    Lists queries and return the processed results.
    Args:
        client (Client): The tenable.sc client object.
        type (str): query time to filter by.
    Returns:
        Dict: The response from the server.
        str: The processed human readable.
        Dict: The relevant section from the response.
    """
    try:
        client.get_users()
        return "ok"
    except Exception:
        raise Exception("Authorization Error: make sure your API Key and Secret Key are correctly set")


def main():  # pragma: no cover
    params = demisto.params()
    command = demisto.command()
    args = demisto.args()
    verify_ssl = not params.get('unsecure', False)
    proxy = params.get('proxy', False)
    user_name = params.get('credentials', {}).get('identifier')
    password = params.get('credentials', {}).get('password')
    access_key = params.get('creds_keys', {}).get('identifier')
    secret_key = params.get('creds_keys', {}).get('password')
    url = params.get('server')

    demisto.info(f'Executing command {command}')

    command_dict = {
        'test-module': test_module,
        'tenable-sc-list-scans': list_scans_command,
        'tenable-sc-list-policies': list_policies_command,
        'tenable-sc-list-repositories': list_repositories_command,
        'tenable-sc-list-credentials': list_credentials_command,
        'tenable-sc-list-zones': list_zones_command,
        'tenable-sc-list-report-definitions': list_report_definitions_command,
        'tenable-sc-list-assets': list_assets_command,
        'tenable-sc-get-asset': get_asset_command,
        'tenable-sc-create-asset': create_asset_command,
        'tenable-sc-delete-asset': delete_asset_command,
        'tenable-sc-create-scan': create_scan_command,
        'tenable-sc-get-scan-status': get_scan_status_command,
        'tenable-sc-get-scan-report': get_scan_report_command,
        'tenable-sc-delete-scan': delete_scan_command,
        'tenable-sc-list-users': list_users_command,
        'tenable-sc-list-alerts': list_alerts_command,
        'tenable-sc-get-alert': get_alert_command,
        'tenable-sc-get-system-information': get_system_information_command,
        'tenable-sc-get-system-licensing': get_system_licensing_command,
        'tenable-sc-get-all-scan-results': get_all_scan_results_command,
        'tenable-sc-list-groups': list_groups_command,
        'tenable-sc-create-user': create_user_command,
        'tenable-sc-update-user': update_user_command,
        'tenable-sc-delete-user': delete_user_command,
        'tenable-sc-list-plugin-family': list_plugin_family_command,
        'tenable-sc-create-policy': create_policy_command,
        'tenable-sc-list-query': list_query_command,
        'tenable-sc-update-asset': update_asset_command,
        'tenable-sc-get-vulnerability': get_vulnerability_command,
        'tenable-sc-get-device': get_device_command,
        'tenable-sc-create-remediation-scan': create_remediation_scan_command,
        'tenable-sc-get-organization': get_organization_command
    }

    try:
        with Client(verify_ssl=verify_ssl, proxy=proxy, user_name=user_name, password=password, access_key=access_key,
                    secret_key=secret_key, url=url) as client:
            if command == 'fetch-incidents':
                first_fetch = params.get('fetch_time').strip()
                fetch_incidents(client, first_fetch)
            elif command == 'tenable-sc-launch-scan':
                return_results(launch_scan_command(args, client))
            else:
                return_results(command_dict[command](client, args))
    except Exception as e:
        return_error(
            f'Failed to execute {command} command. Error: {str(e)}'
        )


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
