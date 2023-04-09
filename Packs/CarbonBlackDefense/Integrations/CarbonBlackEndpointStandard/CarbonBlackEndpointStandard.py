import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

from typing import Dict, Any, Tuple
import json

import urllib3
# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
MAX_INCIDENTS_TO_FETCH = 50
CURRENT_VERSION_OF_THE_POLICY_API = 2  # this is the current version of the policy api
COMMAND_NOT_IMPELEMENTED_MSG = 'Command not implemented'

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """

    def __init__(self, base_url, verify, proxies, api_key, api_secret_key, policy_api_key, policy_api_secret_key,
                 organization_key):
        self.base_url = base_url
        self.verify = verify
        self.proxies = proxies
        self.api_key = api_key
        self.api_secret_key = api_secret_key
        self.policy_api_key = policy_api_key
        self.policy_api_secret_key = policy_api_secret_key
        self.organization_key = organization_key
        self.headers = {'X-Auth-Token': f'{api_secret_key}/{api_key}', 'Content-Type': 'application/json'}
        self.policy_headers = {'X-Auth-Token': f'{policy_api_secret_key}/{policy_api_key}',
                               'Content-Type': 'application/json'}
        super(Client, self).__init__(base_url, verify, proxies)

    def test_module_request(self) -> dict:
        """ Tests connectivity with the application, for some API's.

        :return: A list of alerts.
        :rtype: ``Dict[str, any]``
        """
        suffix_url = f'appservices/v6/orgs/{self.organization_key}/alerts/_search'
        return self._http_request('POST', url_suffix=suffix_url, headers=self.headers, json_data={})

    def policy_test_module_request(self) -> dict:
        """ Tests connectivity with the application, for Policy API.

        :return: A list of policies.
        :rtype: ``Dict[str, any]``
        """
        suffix_url = 'integrationServices/v3/policy'
        return self._http_request('GET', url_suffix=suffix_url, headers=self.policy_headers)

    def search_alerts_request(self, suffix_url_path: str = None, minimum_severity: int = None, create_time: Dict = None,
                              policy_id: List = None, device_username: List = None, device_id: List = None,
                              query: str = None, alert_category: List = None, sort_field: str = "create_time",
                              sort_order: str = "ASC", limit: int = 50) -> dict:
        """Searches for Carbon Black alerts using the '/appservices/v6/orgs/{org_key}/alerts/_search' API endpoint

        All the parameters are passed directly to the API as HTTP POST parameters in the request

        :type suffix_url_path: ``Optional[str]``
        :param suffix_url_path: type of the alert to search for. Options are: 'all' or 'cbanalytics' or 'devicecontrol'

        :type minimum_severity: ``Optional[int]``
        :param minimum_severity: the minimum severity of the alert to search for.

        :type create_time: ``Optional[Dict]``
        :param create_time: A dict presented the the time the alert was created.
            The syntax is {"start": "<dateTime>", "range": "<string>", "end": "<dateTime>" }.
            For example: {"start": "2010-09-25T00:10:50.00", "end": "2015-01-20T10:40:00.00Z", "range": "-1d"}.
            (s for seconds, m for minutes, h for hours, d for days, w for weeks, y for years).

        :type policy_id: ``Optional[list]``
        :param policy_id: The identifier for the policy associated with the device at the time of the alert.

        :type device_username: ``Optional[list]``
        :param device_username: The username of the logged on user during the alert.
            If the user is not available then it may be populated with the device owner

        :type device_id: ``Optional[list]``
        :param device_id: The identifier assigned by Carbon Black Cloud to the device associated with the alert.

        :type query: ``Optional[str]``
        :param query: Query in lucene syntax and/or including value searches.

        :type alert_category: ``Optional[list]``
        :param alert_category: The category of the alert. Options are: 'THREAT' or 'MONITORED'

        :type sort_field: ``Optional[str]``
        :param sort_field: The field to sort by it

        :type sort_order: ``Optional[str]``
        :param sort_order: The sort order (ASC, DESC)

        :type limit: ``Optional[int]``
        :param limit: The number of results to return. default is 50.

        :return: Dict containing a List with the found Carbon Black alerts as dicts
        :rtype: ``Dict[str, Any]``
        """

        if not suffix_url_path or suffix_url_path == "all":
            suffix_url = f'appservices/v6/orgs/{self.organization_key}/alerts/_search'
        else:
            suffix_url = f'appservices/v6/orgs/{self.organization_key}/alerts/{suffix_url_path}/_search'
        body = {
            'criteria': assign_params(
                minimum_severity=minimum_severity,
                create_time=create_time,
                policy_id=policy_id,
                device_username=device_username,
                device_id=device_id,
                category=alert_category
            ),
            'sort': [
                {
                    'field': sort_field,
                    'order': sort_order
                }
            ],
            'rows': limit,
        }
        if query:
            body['query'] = query
        return self._http_request('POST', suffix_url, headers=self.headers, json_data=body)

    # Policies API
    def create_new_policy(self, name: str = None, description: str = None, priority_level: str = None,
                          policy: dict = None):
        """Creates a new Carbon Black policy using the 'integrationServices/v3/policy' API endpoint

        :type name: ``Optional[str]``
        :param name: The name of the new policy.

        :type description: ``Optional[str]``
        :param description: A description of the policy.

        :type priority_level: ``Optional[str]``
        :param priority_level: The priority score associated with sensors assigned to this policy.
            Options are: 'HIGH' or 'MEDIUM' or 'LOW'.

        :type policy: ``Optional[dict]``
        :param policy: A JSON object containing the policy details.

        :return: A dict containing the new policy ID'.
        :rtype: ``dict``
        """
        suffix_url = 'integrationServices/v3/policy'
        body = {
            "policyInfo": assign_params(
                name=name,
                description=description,
                priorityLevel=priority_level,
                policy=policy,
                version=CURRENT_VERSION_OF_THE_POLICY_API
            )
        }
        return self._http_request(method='POST', url_suffix=suffix_url, headers=self.policy_headers,
                                  json_data=body)

    def get_policies(self):
        """Searches for Carbon Black policies using the 'integrationServices/v3/policy' API endpoint

        :return: A dict containing all policies'.
        :rtype: ``dict``
        """
        suffix_url = 'integrationServices/v3/policy'
        return self._http_request(method='GET', url_suffix=suffix_url, headers=self.policy_headers)

    def get_policy_by_id(self, policy_id: int = None):
        """Returns Carbon Black policy by ID using the 'integrationServices/v3/policy/{policy_id}' API endpoint

        :type policy_id: ``Optional[int]``
        :param policy_id: The id of the policy.

        :return: dict containing the policy data'.
        :rtype: ``dict``
        """
        suffix_url = f'integrationServices/v3/policy/{policy_id}'
        return self._http_request(method='GET', url_suffix=suffix_url, headers=self.policy_headers)

    def set_policy(self, policy_id: int = None, policy_info: dict = None):
        """Updates Carbon Black policy by ID using the 'integrationServices/v3/policy/{policy_id}' API endpoint

        :type policy_id: ``Optional[int]``
        :param policy_id: The id of the policy.

        :type policy_info: ``Optional[dict]``
        :param policy_info: A JSON object containing the policy details.

        :return: A dict containing information about the success / failure of the update.
        :rtype: ``dict``
        """
        suffix_url = f'integrationServices/v3/policy/{policy_id}'
        return self._http_request(method='PUT', url_suffix=suffix_url, headers=self.policy_headers,
                                  json_data=policy_info)

    def update_policy(self, policy_id: int = None, name: str = None, description: str = None,
                      priority_level: str = None, policy: dict = None):
        """Updates Carbon Black policy by ID using the 'integrationServices/v3/policy/{policy_id}' API endpoint

        :type policy_id: ``Optional[int]``
        :param policy_id: The id of the policy.

        :type name: ``Optional[str]``
        :param name: The name of the new policy.

        :type description: ``Optional[str]``
        :param description: A description of the policy.

        :type priority_level: ``Optional[str]``
        :param priority_level: The priority score associated with sensors assigned to this policy.
            Options are: 'HIGH' or 'MEDIUM' or 'LOW'.

        :type policy: ``Optional[dict]``
        :param policy: A JSON object containing the policy details.

        :return: A dict containing information about the success / failure of the update.
        :rtype: ``dict``
        """
        suffix_url = f'integrationServices/v3/policy/{policy_id}'
        body = assign_params(
            policyInfo=assign_params(
                id=policy_id,
                name=name,
                description=description,
                priorityLevel=priority_level,
                policy=policy,
                version=CURRENT_VERSION_OF_THE_POLICY_API
            )
        )
        return self._http_request(method='PUT', url_suffix=suffix_url, headers=self.policy_headers,
                                  json_data=body)

    def delete_policy(self, policy_id: int = None):
        """Deletes Carbon Black policy by ID using the 'integrationServices/v3/policy/{policy_id}' API endpoint

        :type policy_id: ``Optional[int]``
        :param policy_id: The id of the policy.

        :return: A dict containing information about the success / failure of the deletion.
        :rtype: ``dict``
        """
        suffix_url = f'integrationServices/v3/policy/{policy_id}'
        return self._http_request(method='DELETE', url_suffix=suffix_url, headers=self.policy_headers)

    def add_rule_to_policy(self, policy_id: int = None, action: str = None, operation: str = None, required: str = None,
                           type: str = None, value: str = None):
        """Adds a rule to a Carbon Black policy by ID using the 'integrationServices/v3/policy/{policy_id}/rule' API endpoint

        :type policy_id: ``Optional[int]``
        :param policy_id: The id of the policy.

        :type action: ``Optional[str]``
        :param action: The rule action. Options are: 'true' or 'false'.
        Options are: 'TERMINATE' or 'IGNORE' or 'TERMINATE_THREAD' or 'ALLOW' or 'DENY' or 'TERMINATE_PROCESS'

        :type operation: ``Optional[str]``
        :param operation: The rule operation.
        Options are: 'MODIFY_SYSTEM_EXE' or 'PASSTHRU' or 'CRED' or 'RANSOM' or 'NETWORK_SERVER' or
            'POL_INVOKE_NOT_TRUSTED' or 'IMPERSONATE' or 'MICROPHONE_CAMERA' or 'INVOKE_SYSAPP' or 'NETWORK_CLIENT' or
            'BYPASS_REG' or 'BUFFER_OVERFLOW' or 'BYPASS_API' or 'USER_DOC' or 'CODE_INJECTION' or 'BYPASS_NET' or
            'KEYBOARD' or 'BYPASS_ALL' or 'RUN' or 'INVOKE_CMD_INTERPRETER' or 'MODIFY_SYTEM_CONFIG' or 'ESCALATE' or
            'BYPASS_FILE' or 'RUN_AS_ADMIN' or 'BYPASS_PROCESS' or 'NETWORK' or 'KERNEL_ACCESS' or 'NETWORK_PEER' or
            'PACKED' or 'INVOKE_SCRIPT' or 'MEMORY_SCRAPE' or 'BYPASS_SELF_PROTECT' or 'TAMPER_API'

        :type required: ``Optional[bool]``
        :param required: Is the rule required. Options are: 'true' or 'false'.

        :type type: ``Optional[dict]``
        :param type: The application type. Options are: 'REPUTATION' or 'SIGNED_BY' or 'NAME_PATH'.

        :type value: ``Optional[dict]``
        :param value: The application value.

        :return: A dict containing the new rule ID. and also information about the success / failure of the update.
        :rtype: ``dict``
        """
        suffix_url = f'integrationServices/v3/policy/{policy_id}/rule'
        body = {
            'ruleInfo': assign_params(
                action=action,
                operation=operation,
                required=required,
                application=assign_params(
                    type=type,
                    value=value
                )
            )
        }
        return self._http_request(method='POST', url_suffix=suffix_url, headers=self.policy_headers, json_data=body)

    def update_rule_in_policy(self, policy_id: int = None, action: str = None, operation: str = None,
                              required: str = None, rule_id: int = None, type: str = None, value: str = None):
        """Updates a rule in a Carbon Black policy by ID
            using the 'integrationServices/v3/policy/{policy_id}/rule{rule_id}' API endpoint

        :type policy_id: ``Optional[int]``
        :param policy_id: The id of the policy.

        :type action: ``Optional[str]``
        :param action: The rule action. Options are: 'true' or 'false'.
        Options are: 'TERMINATE' or 'IGNORE' or 'TERMINATE_THREAD' or 'ALLOW' or 'DENY' or 'TERMINATE_PROCESS'

        :type operation: ``Optional[str]``
        :param operation: The rule operation.
        Options are: 'MODIFY_SYSTEM_EXE' or 'PASSTHRU' or 'CRED' or 'RANSOM' or 'NETWORK_SERVER' or
            'POL_INVOKE_NOT_TRUSTED' or 'IMPERSONATE' or 'MICROPHONE_CAMERA' or 'INVOKE_SYSAPP' or 'NETWORK_CLIENT' or
            'BYPASS_REG' or 'BUFFER_OVERFLOW' or 'BYPASS_API' or 'USER_DOC' or 'CODE_INJECTION' or 'BYPASS_NET' or
            'KEYBOARD' or 'BYPASS_ALL' or 'RUN' or 'INVOKE_CMD_INTERPRETER' or 'MODIFY_SYTEM_CONFIG' or 'ESCALATE' or
            'BYPASS_FILE' or 'RUN_AS_ADMIN' or 'BYPASS_PROCESS' or 'NETWORK' or 'KERNEL_ACCESS' or 'NETWORK_PEER' or
            'PACKED' or 'INVOKE_SCRIPT' or 'MEMORY_SCRAPE' or 'BYPASS_SELF_PROTECT' or 'TAMPER_API'

        :type required: ``Optional[bool]``
        :param required: Is the rule required. Options are: 'true' or 'false'.

        :type rule_id: ``Optional[int]``
        :param rule_id: Is the rule id.

        :type type: ``Optional[dict]``
        :param type: A JSON object containing the policy details.

        :type value: ``Optional[dict]``
        :param value: A JSON object containing the policy details.

        :return: A dict containing information about the success / failure of the update.
        :rtype: ``dict``
        """
        suffix_url = f'integrationServices/v3/policy/{policy_id}/rule/{rule_id}'
        body = {
            'ruleInfo': assign_params(
                action=action,
                operation=operation,
                required=required,
                id=rule_id,
                application=assign_params(
                    type=type,
                    value=value
                )
            )
        }
        return self._http_request(method='PUT', url_suffix=suffix_url, headers=self.policy_headers, json_data=body)

    def delete_rule_from_policy(self, policy_id: int = None, rule_id: int = None):
        """Deletes a rule of Carbon Black policy by ID
            using the 'integrationServices/v3/policy/{policy_id}/rule/{rule_id}' API endpoint

        :type policy_id: ``Optional[int]``
        :param policy_id: The id of the policy.

        :type rule_id: ``Optional[int]``
        :param rule_id: The id of the rule.

        :return: A dict containing information about the success / failure of the deletion.
        :rtype: ``dict``
        """
        suffix_url = f'integrationServices/v3/policy/{policy_id}/rule/{rule_id}'
        return self._http_request(method='DELETE', url_suffix=suffix_url, headers=self.policy_headers)

    # The events API
    def get_events(self, alert_category: List[str] = None, hash: List[str] = None,
                   device_external_ip: List[str] = None, device_id: List[int] = None,
                   device_internal_ip: List[str] = None, device_name: List[str] = None,
                   device_os: List[str] = None, event_type: List[str] = None, parent_name: List[str] = None,
                   parent_reputation: List[str] = None, process_cmdline: List[str] = None,
                   process_guid: List[str] = None, process_name: List[str] = None, process_pid: List[int] = None,
                   process_reputation: List[str] = None, process_start_time: List[str] = None,
                   process_terminated: List[bool] = None, process_username: List[str] = None,
                   sensor_action: List[str] = None, query: str = None, rows: int = 10, start: int = 0,
                   time_range: str = "{}"):
        """Searches for Carbon Black events
            using the 'api/investigate/v2/orgs/{self.organization_key}/enriched_events/search_jobs' API endpoint

        All the parameters are passed directly to the API as HTTP POST parameters in the request

        :type alert_category: ``Optional[List[str]]``
        :param alert_category: The Carbon Black Cloud classification for events tagged to an alert indicating.
            Options are: 'threat' or 'observed'.

        :type hash: ``Optional[List[str]]``
        :param hash: Searchable. Aggregate set of MD5 and SHA-256 hashes associated with the process
            (including childproc_hash, crossproc_hash, filemod_hash, modload_hash, process_hash);
            enables one-step search for any matches on the specified hashes

        :type device_external_ip: ``Optional[List[str]]``
        :param device_external_ip: The IP address of the endpoint according to the Carbon Black Cloud;
            can differ from device_internal_ip due to network proxy or NAT;
            either IPv4 (dotted decimal notation) or IPv6 (proprietary format documented below).

        :type device_id: ``Optional[List[int]]``
        :param device_id: The ID assigned to the endpoint by Carbon Black Cloud;
            unique across all Carbon Black Cloud environments.

        :type device_internal_ip ``Optional[List[str]]``
        :param device_internal_ip: The IP address of the endpoint reported by the sensor;
            either IPv4 (dotted decimal notation) or IPv6 (proprietary format, documented below).

        :type device_name: ``Optional[List[str]]``
        :param device_name: The Hostname of the endpoint recorded by the sensor when last initialized.

        :type device_os: ``Optional[List[str]]``
        :param device_os: The operating system of the endpoint.

        :type event_type: ``Optional[List[str]]``
        :param event_type: The type of enriched event observed. (Requires Endpoint Standard).

        :type parent_name: ``Optional[List[str]]``
        :param parent_name: The Filesystem path of the parent process binary.

        :type parent_reputation: ``Optional[List[str]]``
        :param parent_reputation: The Command line executed by the actor process.
            Options are: 'ADAPTIVE_WHITE_LIST' or 'ADWARE' or 'COMMON_WHITE_LIST' or 'COMPANY_BLACK_LIST' or
            'COMPANY_WHITE_LIST' or 'HEURISTIC' or 'IGNORE' or 'KNOWN_MALWARE' or 'LOCAL_WHITE' or 'NOT_LISTED' or 'PUP'
            or 'RESOLVING' or 'SUSPECT_MALWARE' or 'TRUSTED_WHITE_LIST'

        :type process_cmdline ``Optional[List[str]]``
        :param process_cmdline: The Command line executed by the actor process.

        :type process_guid: ``Optional[List[str]]``
        :param process_guid: The Unique process identifier for the actor process.

        :type process_name ``Optional[List[str]]``
        :param process_name: The Filesystem path of the actor process binary.

        :type process_pid: ``Optional[List[int]]``
        :param process_pid: The Process identifier assigned by the operating system;
            can be multi-valued in case of fork() or exec() process operations on Linux and macOS.

        :type process_reputation: ``Optional[List[str]]``
        :param process_reputation: The Reputation of the actor process;
            applied when event is processed by the Carbon Black Cloud.
            Options are: 'ADAPTIVE_WHITE_LIST' or 'ADWARE' or 'COMMON_WHITE_LIST' or 'COMPANY_BLACK_LIST' or
            'COMPANY_WHITE_LIST' or 'HEURISTIC' or 'IGNORE' or 'KNOWN_MALWARE' or 'LOCAL_WHITE' or 'NOT_LISTED' or 'PUP'
            or 'RESOLVING' or 'SUSPECT_MALWARE' or 'TRUSTED_WHITE_LIST'

        :type process_start_time: ``Optional[List[str]]``
        :param process_start_time: The Sensor reported timestamp of when the process started;
            not available for processes running before the sensor starts.

        :type process_terminated: ``Optional[List[bool]]``
        :param process_terminated: “True” indicates the process has terminated;
            always “false” for enriched events (process termination not recorded).
            Options are: 'true' or 'false'

        :type process_username: ``Optional[List[str]]``
        :param process_username: The User context in which the actor process was executed.
            MacOS - all users for the PID for fork() and exec() transitions,
            Linux - process user for exec() events, but in a future sensor release can be multi-valued due to setuid().

        :type sensor_action: ``Optional[List[str]]``
        :param sensor_action: The action performed by the sensor on the process.
            Options are: 'TERMINATE' or 'DENY' or 'SUSPEND'

        :type query: ``Optional[str]``
        :param query: The Query in lucene syntax and/or including value searches.
            query or some of the other must be included.

        :type rows: ``Optional[int]``
        :param rows: The Number of rows to request, can be paginated. default is 10.

        :type start: ``Optional[int]``
        :param start: The first row to use for pagination. default is 0.

        :type time_range: ``Optional[dict]``
        :param time_range: The time window to restrict the search to match using device_timestamp as the reference.
            Window will take priority over start and end if provided.
            For example {"end": "2020-01-21T18:34:04Z", "start": "2020-01-18T18:34:04Z", "window": "-2w"},
            (where y=year, w=week, d=day, h=hour, m=minute, s=second) start: ISO 8601 timestamp, end: ISO 8601 timestamp

        :return: Dict containing a job_id to using it in get_events_results.
        :rtype: ``Dict[str, str]``
        """
        suffix_url = f'api/investigate/v2/orgs/{self.organization_key}/enriched_events/search_jobs'
        body = assign_params(
            criteria=assign_params(  # one of the arguments (query or criteria) is required
                alert_category=argToList(alert_category),
                hash=argToList(hash),
                device_external_ip=argToList(device_external_ip),
                device_id=argToList(device_id),
                device_internal_ip=argToList(device_internal_ip),
                device_name=argToList(device_name),
                device_os=argToList(device_os),
                event_type=argToList(event_type),
                parent_name=argToList(parent_name),
                parent_reputation=argToList(parent_reputation),
                process_cmdline=argToList(process_cmdline),
                process_guid=argToList(process_guid),
                process_name=argToList(process_name),
                process_pid=argToList(process_pid),
                process_reputation=argToList(process_reputation),
                process_start_time=argToList(process_start_time),
                process_terminated=argToList(process_terminated),
                process_username=argToList(process_username),
                sensor_action=argToList(sensor_action)
            ),
            query=query,  # one of the arguments (query or criteria) is required
            rows=arg_to_number(rows),
            start=arg_to_number(start),
            time_range=json.loads(time_range)
        )
        if not body.get('criteria') and not body.get('query'):
            return "One of the required arguments is missing"
        return self._http_request(method='POST', url_suffix=suffix_url, headers=self.headers, json_data=body)

    def get_events_results(self, job_id: str = None, rows: int = 10):
        """Returns Carbon Black events by job_id
            using the 'api/investigate/v2/orgs/{org_key}/enriched_events/search_jobs/{job_id}/results' API endpoint

        :type job_id: ``Optional[str]``
        :param job_id: The id of the job.

        :type rows: ``Optional[int]``
        :param rows: The number of results to return. default is 10.

        :return: dict containing the results data'.
        :rtype: ``dict``
        """
        suffix_url = f'api/investigate/v2/orgs/{self.organization_key}/enriched_events/search_jobs/{job_id}/results' \
                     f'?rows={rows}'
        return self._http_request(method='GET', url_suffix=suffix_url, headers=self.headers)

    def get_events_details(self, event_ids: List[str] = None):
        """Returns Carbon Black events details by ID
            using the 'api/investigate/v2/orgs/{org_key}/enriched_events/search_jobs/{job_id}/results' API endpoint

        :type event_ids: ``Optional[List[str]]``
        :param event_ids: The id of the event.

        :return: dict containing a job_id to using it in get_events_details_results.
        :rtype: ``dict``
        """
        suffix_url = f'api/investigate/v2/orgs/{self.organization_key}/enriched_events/detail_jobs'
        body = assign_params(
            event_ids=event_ids
        )
        return self._http_request(method='POST', url_suffix=suffix_url, headers=self.headers, json_data=body)

    def get_events_details_results(self, job_id: str = None):
        """Returns Carbon Black event details by job_id
            using the 'api/investigate/v2/orgs/{org_key}/enriched_events/search_jobs/{job_id}/results' API endpoint

        :type job_id: ``Optional[str]``
        :param job_id: The id of the job.

        :return: dict containing the event data'.
        :rtype: ``dict``
        """
        suffix_url = f'api/investigate/v2/orgs/{self.organization_key}/enriched_events/detail_jobs/{job_id}/results'
        return self._http_request(method='GET', url_suffix=suffix_url, headers=self.headers)

    # Processes API
    def get_processes(self, alert_category: List[str] = None, hash: List[str] = None,
                      device_external_ip: List[str] = None, device_id: List[int] = None,
                      device_internal_ip: List[str] = None, device_name: List[str] = None, device_os: List[str] = None,
                      device_timestamp: List[str] = None, event_type: List[str] = None, parent_name: List[str] = None,
                      parent_reputation: List[str] = None, process_cmdline: List[str] = None,
                      process_guid: List[str] = None, process_name: List[str] = None, process_pid: List[int] = None,
                      process_reputation: List[str] = None, process_start_time: List[str] = None,
                      process_terminated: List[bool] = None, process_username: List[str] = None,
                      sensor_action: List[str] = None, query: str = None, rows: int = 10, start: int = 0,
                      time_range: str = "{}"):
        """Searches for Carbon Black events
            using the 'api/investigate/v2/orgs/{self.organization_key}/enriched_events/search_jobs' API endpoint

        All the parameters are passed directly to the API as HTTP POST parameters in the request

        :type alert_category: ``Optional[List[str]]``
        :param alert_category: The Carbon Black Cloud classification for events tagged to an alert indicating.
            Options are: 'threat' or 'observed'.

        :type hash: ``Optional[List[str]]``
        :param hash: Searchable. Aggregate set of MD5 and SHA-256 hashes associated with the process
            (including childproc_hash, crossproc_hash, filemod_hash, modload_hash, process_hash);
            enables one-step search for any matches on the specified hashes

        :type device_external_ip: ``Optional[List[str]]``
        :param device_external_ip: The IP address of the endpoint according to the Carbon Black Cloud;
            can differ from device_internal_ip due to network proxy or NAT;
            either IPv4 (dotted decimal notation) or IPv6 (proprietary format documented below).

        :type device_id: ``Optional[List[int]]``
        :param device_id: The ID assigned to the endpoint by Carbon Black Cloud;
            unique across all Carbon Black Cloud environments.

        :type device_internal_ip ``Optional[List[str]]``
        :param device_internal_ip: The IP address of the endpoint reported by the sensor;
            either IPv4 (dotted decimal notation) or IPv6 (proprietary format, documented below).

        :type device_name: ``Optional[List[str]]``
        :param device_name: The Hostname of the endpoint recorded by the sensor when last initialized.

        :type device_os: ``Optional[List[str]]``
        :param device_os: The operating system of the endpoint.

        :type device_timestamp: ``Optional[List[str]]``
        :param device_timestamp: The Sensor-reported timestamp of the batch of events
            in which this record was submitted to Carbon Black Cloud.

        :type event_type: ``Optional[List[str]]``
        :param event_type: The type of enriched event observed. (Requires Endpoint Standard).

        :type parent_name: ``Optional[List[str]]``
        :param parent_name: The Filesystem path of the parent process binary.

        :type parent_reputation: ``Optional[List[str]]``
        :param parent_reputation: The Command line executed by the actor process.
            Options are: 'ADAPTIVE_WHITE_LIST' or 'ADWARE' or 'COMMON_WHITE_LIST' or 'COMPANY_BLACK_LIST' or
            'COMPANY_WHITE_LIST' or 'HEURISTIC' or 'IGNORE' or 'KNOWN_MALWARE' or 'LOCAL_WHITE' or 'NOT_LISTED' or 'PUP'
            or 'RESOLVING' or 'SUSPECT_MALWARE' or 'TRUSTED_WHITE_LIST'

        :type process_cmdline ``Optional[List[str]]``
        :param process_cmdline: The Command line executed by the actor process.

        :type process_guid: ``Optional[List[str]]``
        :param process_guid: The Unique process identifier for the actor process.

        :type process_name ``Optional[List[str]]``
        :param process_name: The Filesystem path of the actor process binary.

        :type process_pid: ``Optional[List[int]]``
        :param process_pid: The Process identifier assigned by the operating system;
            can be multi-valued in case of fork() or exec() process operations on Linux and macOS.

        :type process_reputation: ``Optional[List[str]]``
        :param process_reputation: The Reputation of the actor process;
            applied when event is processed by the Carbon Black Cloud.
            Options are: 'ADAPTIVE_WHITE_LIST' or 'ADWARE' or 'COMMON_WHITE_LIST' or 'COMPANY_BLACK_LIST' or
            'COMPANY_WHITE_LIST' or 'HEURISTIC' or 'IGNORE' or 'KNOWN_MALWARE' or 'LOCAL_WHITE' or 'NOT_LISTED' or 'PUP'
            or 'RESOLVING' or 'SUSPECT_MALWARE' or 'TRUSTED_WHITE_LIST'

        :type process_start_time: ``Optional[List[str]]``
        :param process_start_time: The Sensor reported timestamp of when the process started;
            not available for processes running before the sensor starts.

        :type process_terminated: ``Optional[List[bool]]``
        :param process_terminated: “True” indicates the process has terminated;
            always “false” for enriched events (process termination not recorded).
            Options are: 'true' or 'false'

        :type process_username: ``Optional[List[str]]``
        :param process_username: The User context in which the actor process was executed.
            MacOS - all users for the PID for fork() and exec() transitions,
            Linux - process user for exec() events, but in a future sensor release can be multi-valued due to setuid().

        :type sensor_action: ``Optional[List[str]]``
        :param sensor_action: The action performed by the sensor on the process.
            Options are: 'TERMINATE' or 'DENY' or 'SUSPEND'

        :type query: ``Optional[str]``
        :param query: The Query in lucene syntax and/or including value searches.
            query or some of the other must be included.

        :type rows: ``Optional[int]``
        :param rows: The Number of rows to request, can be paginated. default is 10.

        :type start: ``Optional[int]``
        :param start: The first row to use for pagination. default is 0.

        :type time_range: ``Optional[dict]``
        :param time_range: The time window to restrict the search to match using device_timestamp as the reference.
            Window will take priority over start and end if provided.
            For example {"end": "2020-01-21T18:34:04Z", "start": "2020-01-18T18:34:04Z", "window": "-2w"},
            (where y=year, w=week, d=day, h=hour, m=minute, s=second) start: ISO 8601 timestamp, end: ISO 8601 timestamp

        :return: Dict containing a job_id to using it in get_process_results.
        :rtype: ``Dict[str, str]``
        """
        suffix_url = f'api/investigate/v2/orgs/{self.organization_key}/processes/search_jobs'
        body = assign_params(
            criteria=assign_params(  # one of the arguments (query or criteria) is required
                alert_category=argToList(alert_category),
                hash=argToList(hash),
                device_external_ip=argToList(device_external_ip),
                device_id=argToList(device_id),
                device_internal_ip=argToList(device_internal_ip),
                device_name=argToList(device_name),
                device_os=argToList(device_os),
                device_timestamp=argToList(device_timestamp),
                event_type=argToList(event_type),
                parent_name=argToList(parent_name),
                parent_reputation=argToList(parent_reputation),
                process_cmdline=argToList(process_cmdline),
                process_guid=argToList(process_guid),
                process_name=argToList(process_name),
                process_pid=argToList(process_pid),
                process_reputation=argToList(process_reputation),
                process_start_time=argToList(process_start_time),
                process_terminated=argToList(process_terminated),
                process_username=argToList(process_username),
                sensor_action=argToList(sensor_action)
            ),
            query=query,  # one of the arguments (query or criteria) is required
            rows=arg_to_number(rows),
            start=arg_to_number(start),
            time_range=json.loads(time_range)
        )
        if not body.get('criteria') and not body.get('query'):
            return "One of the required arguments is missing"
        return self._http_request(method='POST', url_suffix=suffix_url, headers=self.headers, json_data=body)

    def get_process_results(self, job_id: str = None, rows: int = 10):
        """Returns Carbon Black events by job_id
            using the 'api/investigate/v2/orgs/{org_key}/processes/search_jobs/{job_id}/results' API endpoint

        :type job_id: ``Optional[str]``
        :param job_id: The id of the job.

        :type rows: ``Optional[int]``
        :param rows: The number of results to return. default is 10.

        :return: dict containing the results data'.
        :rtype: ``dict``
        """
        suffix_url = f"api/investigate/v2/orgs/{self.organization_key}/processes/search_jobs/{job_id}/results?rows=" \
                     f"{rows}"
        return self._http_request(method='GET', url_suffix=suffix_url, headers=self.headers)

    # Alerts API
    def get_alerts(self, alert_type: str = None, category: List[str] = None, device_id: List[int] = None,
                   first_event_time: dict = None, policy_id: List[int] = None, process_sha256: List[str] = None,
                   reputation: List[str] = None, tag: List[str] = None, device_username: List[str] = None,
                   query: str = None, rows: int = None, start: int = None):
        """Searches for Carbon Black alerts using the '/appservices/v6/orgs/{org_key}/alerts/_search' API endpoint

        All the parameters are passed directly to the API as HTTP POST parameters in the request

        :type alert_type: ``Optional[str]``
        :param alert_type: type of the alert to search for. Options are: 'all' or 'cbanalytics' or 'devicecontrol'

        :type category: ``Optional[list]``
        :param category: The category of the alert. Options are: 'THREAT' or 'MONITORED'

        :type device_id: ``Optional[list]``
        :param device_id: The identifier assigned by Carbon Black Cloud to the device associated with the alert.

        :type first_event_time: ``Optional[dict]``
        :param first_event_time: The time of the first event associated with the alert.
            The syntax is  {"start": "<dateTime>", "range": "<string>", "end": "<dateTime>" }.
            For example: {"start": "2010-09-25T00:10:50.00", "end": "2015-01-20T10:40:00.00Z", "range": "-1d"}.
            (s for seconds, m for minutes, h for hours, d for days, w for weeks, y for years).

        :type policy_id: ``Optional[list]``
        :param policy_id: The identifier for the policy associated with the device at the time of the alert.

        :type process_sha256: ``Optional[list]``
        :param process_sha256: The SHA256 Hash of the primary involved process.

        :type device_username: ``Optional[list]``
        :param device_username: The username of the logged on user during the alert.
            If the user is not available then it may be populated with the device owner

        :type reputation: ``Optional[str]``
        :param reputation: Reputation of the primary involved process (KNOWN_MALWARE, NOT_LISTED, etc.).

        :type tag: ``Optional[str]``
        :param tag: The tags associated with the alert.

        :type query: ``Optional[str]``
        :param query: Query in lucene syntax and/or including value searches.

        :type rows: ``Optional[int]``
        :param rows: The number of results to return. default is 50.

        :type start: ``Optional[int]``
        :param start: The number of the alert where to start retrieving results from.

        :return: Dict containing a Carbon Black alert.
        :rtype: ``Dict[str, Any]``
        """
        if not alert_type or alert_type == "all":
            suffix_url = f'appservices/v6/orgs/{self.organization_key}/alerts/_search'
        else:
            suffix_url = f'appservices/v6/orgs/{self.organization_key}/alerts/{alert_type.lower()}/_search'
        body = assign_params(
            criteria=assign_params(
                category=category,
                device_id=device_id,
                first_event_time=first_event_time,
                policy_id=policy_id,
                process_sha256=process_sha256,
                reputation=reputation,
                tag=tag,
                device_username=device_username,
            ),
            query=query,
            rows=rows,
            start=start
        )
        return self._http_request(method='POST',
                                  url_suffix=suffix_url,
                                  headers=self.headers,
                                  json_data=body)

    def get_alert_by_id(self, alert_id: str = None) -> dict:
        """Searches for Carbon Black alert by ID
            using the 'appservices/v6/orgs/{org_key}/alerts/{alert_id}' API endpoint

        All the parameters are passed directly to the API as HTTP POST parameters in the request

        :type alert_id: ``Optional[str]``
        :param alert_id: The id of the alert

        :return: Dict containing a Carbon Black alert.
        :rtype: ``Dict[str, Any]``
        """
        res = self._http_request(method='GET',
                                 url_suffix=f'appservices/v6/orgs/{self.organization_key}/alerts/{alert_id}',
                                 headers=self.headers)
        return res

    # Devices API
    def get_devices(self, device_id: List = None, status: List = None, device_os: List = None,
                    last_contact_time: Dict[str, Optional[Any]] = None, target_priority: List = None, query: str = None,
                    rows: int = None) -> Dict:
        """Searches for Carbon Black devices
            using the 'appservices/v6/orgs/{org_key}/devices/_search' API endpoint

        All the parameters are passed directly to the API as HTTP POST parameters in the request

        :type device_id: ``Optional[List[str]]``
        :param device_id: The id of the device

        :type status: ``Optional[List[str]]``
        :param status: The status of the device.
            Options are: 'PENDING' or 'REGISTERED' or 'DEREGISTERED' or 'BYPASS ,ACTIVE' or 'INACTIVE' or 'ERROR' or
            'ALL' or 'BYPASS_ON' or 'LIVE' or 'SENSOR_PENDING_UPDATE'

        :type device_os: ``Optional[List[str]]``
        :param device_os: The Operating System.
            Options are: 'WINDOWS' or 'MAC' or 'LINUX' or 'OTHER'.

        :type last_contact_time: ``Optional[dict]``
        :param last_contact_time:

        :type target_priority: ``Optional[List[str]]``
        :param target_priority: The id of the device

        :type query: ``Optional[str]``
        :param query: Query in lucene syntax.

        :type rows: ``Optional[int]``
        :param rows: The number of results to return. default is 20.

        :return: Dict containing a List with the found Carbon Black devices as dicts
        :rtype: ``Dict[str, Any]``
        """
        suffix_url = f'/appservices/v6/orgs/{self.organization_key}/devices/_search'
        body = assign_params(
            criteria=assign_params(
                id=device_id,
                status=status,
                os=device_os,
                last_contact_time=last_contact_time,
                target_priority=target_priority
            ),
            query=query,
            rows=rows
        )
        return self._http_request(method='POST', url_suffix=suffix_url, headers=self.headers, json_data=body)

    def execute_an_action_on_the_device(self, device_id: List[int] = None, action_type: str = None,
                                        options: dict = None) -> str:
        """execute actions on devices
            using the 'appservices/v6/orgs/{org_key}/device_actions' API endpoint

        All the parameters are passed directly to the API as HTTP POST parameters in the request

        :type device_id: ``Optional[List[int]]``
        :param device_id: The id of the device

        :type action_type: ``Optional[str]``
        :param action_type: Action to perform on selected devices.

        :type options: ``Optional[dict]``
        :param options: A dict {"toggle": "ON/OFF"}
        """
        suffix_url = f'appservices/v6/orgs/{self.organization_key}/device_actions'
        body = assign_params(
            action_type=action_type,
            device_id=device_id,
            options=options
        )
        return self._http_request(method='POST', url_suffix=suffix_url, headers=self.headers, json_data=body,
                                  resp_type='text')


def fetch_incident_filters(params: dict):
    filters = {
        'suffix_url_path': params.get('suffix_url_path', 'all'),
        'min_severity': params.get('min_severity'),
        'category': argToList(params.get('category')),
        'device_id': argToList(params.get('device_id')),
        'policy_id': argToList(params.get('policy_id')),
        'device_username': argToList(params.get('device_username')),
        'query': params.get('query')
    }
    if filters.get('query'):
        filters_without_query = dict(filters)
        del filters_without_query['suffix_url_path']
        del filters_without_query['query']
        if not any(filters_without_query.values()):
            return filters
        raise DemistoException("The 'query' parameter should be used without additional parameters to fetch incidents.")
    else:
        return filters


def test_module(client: Client, params: dict) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param client: client to use

    :type params: ``Dict``
    :param params: parameters that initialized by creating the instance

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    """There is 2 sets of api_key&api_secret_key 1 for all API's and 1 for the policy API.
    check which set of keys to test (organization_key is not needed for the policy pair of keys).
    at least one of the 2 sets is required.
    Fetch uses the general api_key."""

    is_fetch = params.get('isFetch')

    # if is_fetch = true and custom API key's is no provided
    if is_fetch and not(client.api_key and client.api_secret_key and client.organization_key):
        return 'To fetch incidents you must fill the following parameters: ' \
               'Custom API key, Custom API secret key and Organization key'

    message = "Missing parameters Error: At least one complete set of API keys " \
              "(Custom API keys or Api/Live-Response API keys) is required"

    # if all of the custom API key's is provided
    if client.api_key and client.api_secret_key and client.organization_key:
        try:
            client.test_module_request()

            # if is_fetch = true, try to fetch
            if is_fetch:
                filters = fetch_incident_filters(params)
                client.search_alerts_request(suffix_url_path=filters.get('suffix_url_path'),
                                             minimum_severity=filters.get('min_severity'),
                                             policy_id=filters.get('policy_id'),
                                             device_username=filters.get('device_username'),
                                             device_id=filters.get('device_id'),
                                             query=filters.get('query'),
                                             alert_category=filters.get('category'))

            message = 'ok'
        except Exception as e:
            if 'authenticated' in str(e) or 'Forbidden' in str(e):
                return 'Authorization Error: make sure Custom API Key is correctly set'
            else:
                raise e
    # if one or more of the custom API keys are provided
    elif client.api_key or client.api_secret_key or client.organization_key:
        return 'Missing custom API parameters. Please fill all the relevant parameters: ' \
               'Custom API key, Custom API secret key and Organization key.'

    # if all of the api/live-response API key's is provided
    if client.policy_api_key and client.policy_api_secret_key:
        try:
            client.policy_test_module_request()
            message = 'ok'
        except Exception as e:
            if 'Authentication' in str(e) or 'authenticated' in str(e):
                return 'Authorization Error: make sure API Key is correctly set'
            else:
                raise e
    # if only one of the api/live-response API keys are provided
    elif client.policy_api_key or client.policy_api_secret_key:
        return 'Missing API parameters. Please fill all the relevant parameters: API key, API secret key'

    return message


def convert_to_demisto_severity(severity: int) -> int:
    """Maps Carbon Black severity to Cortex XSOAR severity

    Converts the Carbon Black alert severity level (1 to 10) to Cortex XSOAR incident severity (1 to 4)
    for mapping.

    :type severity: ``int``
    :param severity: severity as returned from the Carbon Black API (int: 1 to 10)

    :return: Cortex XSOAR Severity (int: 1 to 4)
    :rtype: ``int``
    """

    return {
        1: IncidentSeverity.LOW,
        2: IncidentSeverity.LOW,
        3: IncidentSeverity.LOW,
        4: IncidentSeverity.MEDIUM,
        5: IncidentSeverity.MEDIUM,
        6: IncidentSeverity.MEDIUM,
        7: IncidentSeverity.HIGH,
        8: IncidentSeverity.HIGH,
        9: IncidentSeverity.CRITICAL,
        10: IncidentSeverity.CRITICAL
    }[severity]


def fetch_incidents(client: Client, fetch_time: str, fetch_limit: int, last_run: dict, filters: dict) -> \
        Tuple[List[dict], Dict[str, int]]:
    """This function retrieves new alerts every interval (default is 1 minute).

    This function has to implement the logic of making sure that incidents are
    fetched only once and no incidents are missed. By default it's invoked by
    XSOAR every minute. It will use last_run to save the timestamp of the last
    incident it processed. If last_run is not provided, it should use the
    integration parameter first_fetch to determine when to start fetching
    the first time.

    :type client: ``Client``
    :param client: client to use

    :type fetch_time: ``Optional[str]``
    :param fetch_time:
        If last_run is None (first time we are fetching), it contains
        the timestamp in milliseconds on when to start fetching incidents

    :type fetch_limit: ``int``
    :param fetch_limit: Maximum incidents per fetch.

    :type last_run: ``Optional[Dict[str, int]]``
    :param last_run:
        A dict with a key containing the latest incident created time we got
        from last fetch.

    :type filters: ``Optional[dict]``
    :param filters: Some filters to filter alerts by device_id or query etc..

    :return:
        A tuple containing two elements:
            next_run (``Dict[str, int]``): Contains the timestamp that will be
                    used in ``last_run`` on the next fetch.
            incidents (``List[dict]``): List of incidents that will be created in XSOAR

    :rtype: ``Tuple[List[dict], Dict[str, int]]``
    """
    last_fetched_alert_create_time = last_run.get('last_fetched_alert_create_time')
    last_fetched_alert_id = last_run.get('last_fetched_alert_id', '')
    if not last_fetched_alert_create_time:
        last_fetched_alert_create_time, _ = parse_date_range(fetch_time, date_format='%Y-%m-%dT%H:%M:%S.000Z')
    else:
        fetch_limit += 1  # We skip the first alert
    alert_create_date = last_fetched_alert_create_time
    alert_id = last_fetched_alert_id

    incidents = []

    response = client.search_alerts_request(
        suffix_url_path=filters.get('suffix_url_path'),
        minimum_severity=filters.get('min_severity'),
        alert_category=filters.get('category'),
        device_id=filters.get('device_id'),
        policy_id=filters.get('policy_id'),
        device_username=filters.get('device_username'),
        query=filters.get('query'),
        sort_field='create_time',
        sort_order='ASC',
        create_time=assign_params(
            start=last_fetched_alert_create_time,
            end=datetime.now().strftime('%Y-%m-%dT%H:%M:%S.000Z')
        ),
        limit=fetch_limit
    )
    alerts = response.get('results', [])

    for alert in alerts:
        if alert_id == alert.get('id'):
            continue
        alert_create_date = alert.get('create_time')
        alert_id = alert.get('id')

        incident = {
            'type': 'Carbon Black Endpoint Standard',
            'name': f'Carbon Black Defense alert {alert_id}',
            'occurred': alert_create_date,
            'rawJSON': json.dumps(alert),
            'severity': convert_to_demisto_severity(alert.get('severity', 1)),
        }
        incidents.append(incident)

    res = {'last_fetched_alert_create_time': alert_create_date, 'last_fetched_alert_id': alert_id}
    return incidents, res


def create_policy_command(client: Client, args: dict):
    name = args.get('name')
    description = args.get('description')
    priority_level = args.get('priorityLevel')
    policy = args.get('policy')

    if not policy:
        return "The policy argument is required."
    res = client.create_new_policy(name, description, priority_level, json.loads(policy))

    if res.get('message') == 'Success':
        return get_policy_command(client, {'policyId': res.get('policyId')})
    return CommandResults(
        readable_output=res,
        raw_response=res
    )


def get_policies_command(client: Client, args: dict):
    res = client.get_policies()
    human_readable = []
    policies = res.get('results', [])
    headers = ["id", "priorityLevel", "systemPolicy", "latestRevision", "version"]

    if not policies:
        return 'No policy found.'
    for policy in policies:
        human_readable.append({
            "id": policy.get('id'),
            "priorityLevel": policy.get('priorityLevel'),
            "systemPolicy": policy.get('systemPolicy'),
            "latestRevision": timestamp_to_datestring(policy.get('latestRevision')),
            "version": policy.get('version')
        })

    readable_output = tableToMarkdown('Carbon Black Defense Policies',
                                      human_readable,
                                      headers=headers,
                                      headerTransform=pascalToSpace,
                                      removeNull=True)

    return CommandResults(
        outputs_prefix='CarbonBlackDefense.Policy',
        outputs_key_field='id',
        outputs=policies,
        readable_output=readable_output,
        raw_response=res
    )


def get_policy_command(client: Client, args: dict):
    policy_id = args.get('policyId')
    headers = ["id", "description", "name", "latestRevision", "version", "priorityLevel", "systemPolicy"]

    res = client.get_policy_by_id(policy_id)

    policy_info = dict(res.get('policyInfo'))
    if not policy_info:
        return "Policy not found, You may not have sent a correct policy id."
    del policy_info['policy']  # we delete the policy info (it's too big) from the human readable
    policy_info['latestRevision'] = timestamp_to_datestring(policy_info.get('latestRevision', ''))

    readable_output = tableToMarkdown('Carbon Black Defense Policy',
                                      policy_info,
                                      headers=headers,
                                      headerTransform=pascalToSpace,
                                      removeNull=True)

    return CommandResults(
        outputs_prefix='CarbonBlackDefense.Policy',
        outputs_key_field='id',
        outputs=res.get('policyInfo'),
        readable_output=readable_output,
        raw_response=res
    )


def set_policy_command(client: Client, args: dict):
    policy_id = args.get('policy')
    policy_info = args.get('keyValue')

    if not policy_info:
        return "The policy_info argument is required."
    res = client.set_policy(policy_id, json.loads(policy_info))

    if res.get('message') == 'Success':
        return get_policy_command(client, {'policyId': policy_id})
    return CommandResults(
        readable_output=res,
        raw_response=res
    )


def update_policy_command(client: Client, args: dict):
    policy_id = args.get('id')
    name = args.get('name')
    description = args.get('description')
    priority_level = args.get('priorityLevel')
    policy = args.get('policy')

    if not policy:
        return "The policy argument is required."
    res = client.update_policy(policy_id, name, description, priority_level, json.loads(policy))

    if res.get('message') == 'Success':
        return get_policy_command(client, {'policyId': policy_id})
    return CommandResults(
        readable_output=res,
        raw_response=res
    )


def delete_policy_command(client: Client, args: dict):
    policy_id = args.get('policyId')

    res = client.delete_policy(policy_id)

    return CommandResults(
        readable_output=tableToMarkdown(f"The policy {policy_id} was deleted successfully", res,
                                        headerTransform=string_to_table_header),
        raw_response=res
    )


def add_rule_to_policy_command(client: Client, args: dict):
    policy_id = args.get('policyId')
    action = args.get('action')
    operation = args.get('operation')
    required = args.get('required')
    type = args.get('type')
    value = args.get('value')

    res = client.add_rule_to_policy(policy_id, action, operation, required, type, value)

    if res.get('message') == 'Success':
        return get_policy_command(client, {'policyId': policy_id})
    return CommandResults(
        readable_output=res,
        raw_response=res
    )


def update_rule_in_policy_command(client: Client, args: dict):
    policy_id = args.get('policyId')
    action = args.get('action')
    operation = args.get('operation')
    required = args.get('required')
    rule_id = args.get('id')
    type = args.get('type')
    value = args.get('value')

    res = client.update_rule_in_policy(policy_id, action, operation, required, rule_id, type, value)

    if res.get('message') == 'Success':
        return get_policy_command(client, {'policyId': policy_id})
    return CommandResults(
        readable_output=res,
        raw_response=res
    )


def delete_rule_from_policy_command(client: Client, args: dict):
    policy_id = arg_to_number(args.get('policyId'))
    rule_id = arg_to_number(args.get('ruleId'))

    res = client.delete_rule_from_policy(policy_id, rule_id)
    readable_output = tableToMarkdown("The rule was successfully deleted from the policy",
                                      res,
                                      headerTransform=string_to_table_header)

    return CommandResults(
        readable_output=readable_output,
        raw_response=res
    )


def find_events_command(client: Client, args: dict):
    res = client.get_events(**assign_params(**args))

    # In case the request failed (for example if the query & all other required arguments is empty)
    if "job_id" not in res:
        return res

    readable_output = tableToMarkdown('Carbon Black Defense Events Search',
                                      res,
                                      headerTransform=string_to_table_header)

    return CommandResults(
        outputs_prefix='CarbonBlackDefense.Events.Search',
        outputs_key_field='job_id',
        outputs=res,
        readable_output=readable_output,
        raw_response=res
    )


def find_events_results_command(client: Client, args: dict):
    job_id = args.get('job_id')
    rows = args.get('rows', 10)

    res = client.get_events_results(job_id, rows)

    headers = ['event_id', 'device_id', 'event_network_remote_port', 'event_network_remote_ipv4',
               'event_network_local_ipv4', 'enriched_event_type']

    res['job_id'] = job_id
    human_readable = res.get('results', {})
    readable_output = tableToMarkdown('Carbon Black Defense Event Results',
                                      human_readable,
                                      headers=headers,
                                      headerTransform=string_to_table_header,
                                      removeNull=True)

    return CommandResults(
        outputs_prefix='CarbonBlackDefense.Events.Results',
        outputs_key_field='job_id',
        outputs=res,
        readable_output=readable_output,
        raw_response=res
    )


def find_events_details_command(client: Client, args: dict):
    event_ids = argToList(args.get('event_ids'))

    res = client.get_events_details(event_ids)
    readable_output = tableToMarkdown('Carbon Black Defense Event Details Search',
                                      res,
                                      headerTransform=string_to_table_header)

    return CommandResults(
        outputs_prefix='CarbonBlackDefense.EventDetails.Search',
        outputs_key_field='job_id',
        outputs=res,
        readable_output=readable_output,
        raw_response=res
    )


def find_events_details_results_command(client: Client, args: dict):
    job_id = args.get('job_id')

    res = client.get_events_details_results(job_id)
    headers = ['event_id', 'device_id', 'event_network_remote_port', 'event_network_remote_ipv4',
               'event_network_local_ipv4', 'enriched_event_type']

    res['job_id'] = job_id
    human_readable = res.get('results')
    readable_output = tableToMarkdown('Carbon Black Defense Event Details Results',
                                      human_readable,
                                      headers=headers,
                                      headerTransform=string_to_table_header,
                                      removeNull=True)

    return CommandResults(
        outputs_prefix='CarbonBlackDefense.EventDetails.Results',
        outputs_key_field='job_id',
        outputs=res,
        readable_output=readable_output,
        raw_response=res
    )


def find_processes_command(client: Client, args: dict):
    res = client.get_processes(**assign_params(**args))

    # In case the request failed (for example if the query & all other required arguments is empty)
    if "job_id" not in res:
        return res

    readable_output = tableToMarkdown('Carbon Black Defense Processes Search',
                                      res,
                                      headerTransform=string_to_table_header)
    return CommandResults(
        outputs_prefix='CarbonBlackDefense.Process.Search',
        outputs_key_field='job_id',
        outputs=res,
        readable_output=readable_output,
        raw_response=res
    )


def find_processes_results_command(client: Client, args: dict):
    job_id = args.get('job_id')
    rows = args.get('rows')

    if not rows:
        rows = 10
    res = client.get_process_results(job_id, rows)
    headers = ['device_id', 'device_name', 'process_name', 'device_policy_id', 'enriched_event_type']

    res['job_id'] = job_id
    human_readable = res.get('results')
    readable_output = tableToMarkdown('The Results For The Process Search',
                                      human_readable,
                                      headers=headers,
                                      removeNull=True,
                                      headerTransform=string_to_table_header)

    return CommandResults(
        outputs_prefix='CarbonBlackDefense.Process.Results',
        outputs_key_field='job_id',
        outputs=res,
        readable_output=readable_output,
        raw_response=res
    )


def alerts_search_command(client: Client, args: dict):
    alert_type = args.get('type', 'all')
    category = argToList(args.get('category'))
    device_id = argToList(args.get('device_id'))
    first_event_time = args.get('first_event_time')
    policy_id = argToList(args.get('policy_id'))
    process_sha256 = argToList(args.get('process_sha256'))
    reputation = argToList(args.get('reputation'))
    tag = argToList(args.get('tag'))
    device_username = argToList(args.get('device_username'))
    query = args.get('query')
    rows = args.get('rows')
    start = args.get('start')
    headers = ['id', 'category', 'device_id', 'device_name', 'device_username', 'create_time', 'ioc_hit', 'policy_name',
               'process_name', 'type', 'severity']

    if first_event_time:
        first_event_time = json.loads(first_event_time)
    res = client.get_alerts(alert_type, category, device_id, first_event_time, policy_id, process_sha256, reputation,
                            tag, device_username, query, rows, start)

    alerts = res.get('results', [])
    if not alerts:
        return 'No alerts were found.'

    readable_output = tableToMarkdown('Carbon Black Defense Alerts List Results', alerts, headers,
                                      headerTransform=string_to_table_header, removeNull=True)
    return CommandResults(
        outputs_prefix='CarbonBlackDefense.Alert',
        outputs_key_field='id',
        outputs=alerts,
        readable_output=readable_output,
        raw_response=res
    )


def get_alert_details_command(client: Client, args: dict):
    alert_id = args.get('alertId')

    res = client.get_alert_by_id(alert_id)

    if 'id' not in res.keys():
        return f'The alert id: {alert_id} was not found'

    headers = ['id', 'category', 'device_id', 'device_name', 'device_username', 'create_time', 'ioc_hit', 'policy_name',
               'process_name', 'type', 'severity']
    readable_output = tableToMarkdown('Carbon Black Defense Get Alert Details',
                                      res,
                                      headers,
                                      headerTransform=string_to_table_header,
                                      removeNull=True)

    return CommandResults(
        outputs_prefix='CarbonBlackDefense.Alert',
        outputs_key_field='id',
        outputs=res,
        readable_output=readable_output,
        raw_response=res
    )


def device_search_command(client: Client, args: dict):
    device_id = argToList(args.get('device_id'))
    device_os = argToList(args.get('os'))
    device_status = argToList(args.get('status'))
    last_location = {
        'start': args.get('start_time'),
        'end': args.get('end_time')
    }
    target_priority = argToList(args.get('target_priority'))
    query = args.get('query')
    rows = args.get('rows')
    headers = ['id', 'name', 'os', 'policy_name', 'quarantined', 'status', 'target_priority',
               'last_internal_ip_address',
               'last_external_ip_address', 'last_contact_time', 'last_location']

    result = client.get_devices(device_id, device_status, device_os, last_location, target_priority, query, rows)

    devices = result.get('results', [])
    if not devices:
        return 'No devices were found.'

    readable_output = tableToMarkdown('Carbon Black Defense Devices List Results',
                                      devices,
                                      headers,
                                      headerTransform=string_to_table_header,
                                      removeNull=True)
    return CommandResults(
        outputs_prefix='CarbonBlackDefense.Device',
        outputs_key_field='id',
        outputs=devices,
        readable_output=readable_output,
        raw_response=result
    )


def device_quarantine_command(client: Client, args: dict):
    device_id = argToList(args.get('device_id'))

    client.execute_an_action_on_the_device(device_id, 'QUARANTINE', {"toggle": "ON"})

    return CommandResults(
        readable_output="Device quarantine successfully",
    )


def device_unquarantine_command(client: Client, args: dict):
    device_id = argToList(args.get('device_id'))

    client.execute_an_action_on_the_device(device_id, 'QUARANTINE', {"toggle": "OFF"})

    return CommandResults(
        readable_output="Device unquarantine successfully",
    )


def device_background_scan_command(client: Client, args: dict):
    device_id = argToList(args.get('device_id'))

    client.execute_an_action_on_the_device(device_id, 'BACKGROUND_SCAN', {"toggle": "ON"})

    return CommandResults(
        readable_output="Background scan started successfully",
    )


def device_background_scan_stop_command(client: Client, args: dict):
    device_id = argToList(args.get('device_id'))

    client.execute_an_action_on_the_device(device_id, 'BACKGROUND_SCAN', {"toggle": "OFF"})

    return CommandResults(
        readable_output="Background scan stopped successfully",
    )


def device_bypass_command(client: Client, args: dict):
    device_id = argToList(args.get('device_id'))

    client.execute_an_action_on_the_device(device_id, 'BYPASS', {"toggle": "ON"})

    return CommandResults(
        readable_output="Device bypass successfully",
    )


def device_unbypass_command(client: Client, args: dict):
    device_id = argToList(args.get('device_id'))

    client.execute_an_action_on_the_device(device_id, 'BYPASS', {"toggle": "OFF"})

    return CommandResults(
        readable_output="Device unbypass successfully",
    )


def device_policy_update_command(client: Client, args: dict):
    device_id = argToList(args.get('device_id'))
    policy_id = args.get('policy_id')

    client.execute_an_action_on_the_device(device_id, 'UPDATE_POLICY', {"policy_id": policy_id})

    return CommandResults(
        readable_output="Policy updated successfully",
    )


def device_update_sensor_version_command(client: Client, args: dict):
    device_id = argToList(args.get('device_id'))
    sensor_version = args.get('sensor_version')

    if not sensor_version:
        return "The sensor_version argument is required."
    client.execute_an_action_on_the_device(device_id, 'UPDATE_SENSOR_VERSION',
                                           {"sensor_version": json.loads(sensor_version)})
    return CommandResults(
        readable_output=f"Version update to {sensor_version} was successful",
    )


''' MAIN FUNCTION '''


def main() -> None:
    command = demisto.command()

    # Get the parameters
    params = demisto.params()
    base_url = params.get('url')
    api_key = params.get('custom_credentials').get('identifier')
    api_secret_key = params.get('custom_credentials').get('password')
    policy_api_key = params.get('live_response_credentials').get('identifier')
    policy_api_secret_key = params.get('live_response_credentials').get('password')
    organization_key = params.get('organization_key')

    verify_certificate = not params.get('insecure', False)

    demisto.info(f'Command being called is {command}')

    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            proxies=handle_proxy(),
            api_key=api_key,
            api_secret_key=api_secret_key,
            policy_api_key=policy_api_key,
            policy_api_secret_key=policy_api_secret_key,
            organization_key=organization_key
        )

        commands = {
            'cbd-create-policy': create_policy_command,
            'cbd-get-policies': get_policies_command,
            'cbd-get-policy': get_policy_command,
            'cbd-set-policy': set_policy_command,
            'cbd-update-policy': update_policy_command,
            'cbd-delete-policy': delete_policy_command,
            'cbd-add-rule-to-policy': add_rule_to_policy_command,
            'cbd-update-rule-in-policy': update_rule_in_policy_command,
            'cbd-delete-rule-from-policy': delete_rule_from_policy_command,
            'cbd-find-events': find_events_command,
            'cbd-find-events-results': find_events_results_command,
            'cbd-find-events-details': find_events_details_command,
            'cbd-find-events-details-results': find_events_details_results_command,
            'cbd-find-processes': find_processes_command,
            'cbd-find-processes-results': find_processes_results_command,
            'cbd-alerts-search': alerts_search_command,
            'cbd-get-alert-details': get_alert_details_command,
            'cbd-device-search': device_search_command,
            'cbd-device-quarantine': device_quarantine_command,
            'cbd-device-unquarantine': device_unquarantine_command,
            'cbd-device-background-scan': device_background_scan_command,
            'cbd-device-background-scan-stop': device_background_scan_stop_command,
            'cbd-device-bypass': device_bypass_command,
            'cbd-device-unbypass': device_unbypass_command,
            'cbd-device-policy-update': device_policy_update_command,
            'cbd-device-update-sensor-version': device_update_sensor_version_command
        }

        if command == 'test-module':
            return_results(test_module(client, params))
        elif command == 'fetch-incidents':
            fetch_time = params.get('first_fetch', '7 days')
            fetch_limit = int(params.get('max_fetch', 50))
            filters = fetch_incident_filters(params)
            # Set and define the fetch incidents command to run after activated via integration settings.
            incidents, last_run = fetch_incidents(client, fetch_time, fetch_limit, last_run=demisto.getLastRun(),
                                                  filters=filters)
            demisto.incidents(incidents)
            demisto.setLastRun(last_run)
        elif command in commands:
            command_results = commands[command](client, demisto.args())
            return_results(command_results)
        else:
            raise NotImplementedError(f'{COMMAND_NOT_IMPELEMENTED_MSG}: {command}')

    # Log exceptions and return error
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
