import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from CommonServerUserPython import *  # noqa

import urllib3

urllib3.disable_warnings()  # Disable insecure warnings


INTERVAL_FOR_POLLING_DEFAULT = 30
TIMEOUT_FOR_POLLING_DEFAULT = 600

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
        super().__init__(base_url, verify, proxies)

    def test_module_request(self) -> dict:
        """ Tests connectivity with the application, for some API's.

        :return: A list of alerts.
        :rtype: ``Dict[str, any]``
        """
        suffix_url = f'api/alerts/v7/orgs/{self.organization_key}/alerts/_search'
        return self._http_request('POST', url_suffix=suffix_url, headers=self.headers, json_data={})

    def policy_test_module_request(self) -> dict:
        """ Tests connectivity with the application, for Policy API.

        :return: A list of policies.
        :rtype: ``Dict[str, any]``
        """
        suffix_url = f'policyservice/v1/orgs/{self.organization_key}/policies/summary'
        return self._http_request(method='GET', url_suffix=suffix_url, headers=self.policy_headers)

    def search_alerts_request(self, type: str | None = None, minimum_severity: int | None = None, create_time: dict | None = None,
                              policy_id: List | None = None, device_username: List | None = None, device_id: List | None = None,
                              query: str | None = None, sort_field: str = "backend_timestamp",
                              sort_order: str = "ASC", limit: int = 50) -> dict:
        """Searches for Carbon Black alerts

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

        suffix_url = f'api/alerts/v7/orgs/{self.organization_key}/alerts/_search'

        body = assign_params(
            criteria=assign_params(
                minimum_severity=minimum_severity,
                policy_id=policy_id,
                device_username=device_username,
                device_id=device_id,
                type=type
            ),
            time_range=create_time,
            sort=[assign_params(
                field=sort_field,
                order=sort_order
            )],
            rows=limit,
            query=query
        )
        demisto.debug(f"Fetch query: {suffix_url} wite the request bode: {body}")

        return self._http_request('POST', suffix_url, headers=self.headers, json_data=body)

    def get_alert_by_id(self, alert_id: str) -> dict:
        return self._http_request(
            method='GET',
            url_suffix=f'api/alerts/v7/orgs/{self.organization_key}/alerts/{alert_id}',
            headers=self.headers
        )

    def get_alerts(self, type: str | None = None, device_id: List[int] | None = None,
                   first_event_time: dict | None = None, policy_id: List[int] | None = None,
                   process_sha256: List[str] | None = None, reputation: List[str] | None = None,
                   tags: List[str] | None = None, device_username: List[str] | None = None,
                   query: str | None = None, rows: int | None = None, start: int | None = None):
        suffix_url = f'api/alerts/v7/orgs/{self.organization_key}/alerts/_search'

        body = assign_params(
            criteria=assign_params(
                device_id=device_id,
                first_event_time=first_event_time,
                policy_id=policy_id,
                process_sha256=process_sha256,
                reputation=reputation,
                tags=tags,
                device_username=device_username,
                type=type
            ),
            query=query,
            rows=rows,
            start=start
        )

        return self._http_request(method='POST',
                                  url_suffix=suffix_url,
                                  headers=self.headers,
                                  json_data=body)

    def get_policies_summary(self):
        """Searches for Carbon Black policies using the 'integrationServices/v3/policy' API endpoint

        :return: A dict containing all policies'.
        :rtype: ``dict``
        """
        suffix_url = f'policyservice/v1/orgs/{self.organization_key}/policies/summary'
        return self._http_request(method='GET', url_suffix=suffix_url, headers=self.policy_headers)

    def get_policy_by_id(self, policy_id: int):
        """Returns Carbon Black policy by ID.

        :type policy_id: ``Optional[int]``
        :param policy_id: The id of the policy.

        :return: dict containing the policy data'.
        :rtype: ``dict``
        """
        suffix_url = f'policyservice/v1/orgs/{self.organization_key}/policies/{policy_id}'
        return self._http_request(method='GET', url_suffix=suffix_url, headers=self.policy_headers)

    def create_new_policy(self, body: dict):
        suffix_url = f'policyservice/v1/orgs/{self.organization_key}/policies'
        return self._http_request(method='POST', url_suffix=suffix_url, headers=self.policy_headers, json_data=body)

    def delete_policy(self, policy_id: int):
        """Deletes Carbon Black policy by ID using the 'integrationServices/v3/policy/{policy_id}' API endpoint

        :type policy_id: ``Optional[int]``
        :param policy_id: The id of the policy.

        :return: A dict containing information about the success / failure of the deletion.
        :rtype: ``dict``
        """
        suffix_url = f'policyservice/v1/orgs/{self.organization_key}/policies/{policy_id}'
        return self._http_request(method='DELETE', url_suffix=suffix_url, headers=self.policy_headers)

    def update_policy(self, policy_id: int, body: dict):
        suffix_url = f'policyservice/v1/orgs/{self.organization_key}/policies/{policy_id}'
        return self._http_request(method='POST', url_suffix=suffix_url, headers=self.policy_headers, json_data=body)

    def add_rule_to_policy(self, policy_id: int, action: str, operation: str, required: str, type: str, value: str):
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
        suffix_url = f'policyservice/v1/orgs/{self.organization_key}/policies/{policy_id}/rules'
        body = assign_params(
            action=action,
            operation=operation,
            required=required,
            application=assign_params(
                type=type,
                value=value
            )
        )
        return self._http_request(method='POST', url_suffix=suffix_url, headers=self.policy_headers, json_data=body)

    def update_rule_in_policy(self, policy_id: int, action: str, operation: str,
                              required: str, rule_id: int, type: str, value: str):
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
        suffix_url = f'policyservice/v1/orgs/{self.organization_key}/policies/{policy_id}/rules/{rule_id}'
        body = assign_params(
            action=action,
            operation=operation,
            required=required,
            id=rule_id,
            application=assign_params(
                type=type,
                value=value
            )
        )
        return self._http_request(method='PUT', url_suffix=suffix_url, headers=self.policy_headers, json_data=body)

    def delete_rule_from_policy(self, policy_id: int, rule_id: int):
        """Deletes a rule of Carbon Black policy by ID
            using the 'integrationServices/v3/policy/{policy_id}/rule/{rule_id}' API endpoint

        :type policy_id: ``Optional[int]``
        :param policy_id: The id of the policy.

        :type rule_id: ``Optional[int]``
        :param rule_id: The id of the rule.

        :return: A dict containing information about the success / failure of the deletion.
        :rtype: ``dict``
        """
        suffix_url = f'policyservice/v1/orgs/{self.organization_key}/policies/{policy_id}/rules/{rule_id}'
        return self._http_request(method='DELETE', url_suffix=suffix_url, headers=self.policy_headers,
                                  return_empty_response=True)  # Carbon black api return 204 for a successfully request

    def get_processes(self, alert_category: List[str] | None = None, hash: List[str] | None = None,
                      device_external_ip: List[str] | None = None, device_id: List[int] | None = None,
                      device_internal_ip: List[str] | None = None, device_name: List[str] | None = None,
                      device_os: List[str] | None = None, device_timestamp: List[str] | None = None,
                      event_type: List[str] | None = None, parent_name: List[str] | None = None,
                      parent_reputation: List[str] | None = None, process_cmdline: List[str] | None = None,
                      process_guid: List[str] | None = None, process_name: List[str] | None = None,
                      process_pid: List[int] | None = None, process_reputation: List[str] | None = None,
                      process_start_time: List[str] | None = None, process_terminated: List[bool] | None = None,
                      process_username: List[str] | None = None, sensor_action: List[str] | None = None,
                      query: str | None = None, rows: int = 10, start: int = 0, time_range: str = "{}") -> dict:
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
            raise DemistoException("At least one criteria filter or query must be provided.")
        return self._http_request(method='POST', url_suffix=suffix_url, headers=self.headers, json_data=body)

    def get_process_results(self, job_id: str, rows: int = 10) -> dict:
        """Returns Carbon Black events by job_id
            using the 'api/investigate/v2/orgs/{org_key}/processes/search_jobs/{job_id}/results' API endpoint

        :type job_id: ``Optional[str]``
        :param job_id: The id of the job.

        :type rows: ``Optional[int]``
        :param rows: The number of results to return. default is 10.

        :return: dict containing the results data'.
        :rtype: ``dict``
        """
        suffix_url = f"api/investigate/v2/orgs/{self.organization_key}/processes/search_jobs/{job_id}/results?rows={str(rows)}"
        return self._http_request(method='GET', url_suffix=suffix_url, headers=self.headers)


''' COMMAND FUNCTIONS '''


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
    if is_fetch and not (client.api_key and client.api_secret_key and client.organization_key):
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
                client.search_alerts_request(type=filters.get('type'),
                                             minimum_severity=filters.get('min_severity'),
                                             policy_id=filters.get('policy_id'),
                                             device_username=filters.get('device_username'),
                                             device_id=filters.get('device_id'),
                                             query=filters.get('query'))

            message = 'ok'
        except Exception as e:
            if 'authenticated' in str(e) or 'Forbidden' in str(e):
                return 'Authorization Error: make sure Custom API Key is correctly set'
            else:
                raise e
    # if one or more of the custom API keys are provided
    elif client.api_key or client.api_secret_key:
        return 'Missing custom API parameters. Please fill all the relevant parameters: ' \
               'Custom API key, Custom API secret key and Organization key.'

    # if all of the api/live-response API key's is provided
    if client.policy_api_key and client.policy_api_secret_key and client.organization_key:
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


def fetch_incidents(client: Client, fetch_time: str, fetch_limit: int, last_run: dict, type, min_severity,
                    device_id, policy_id, device_username, query) -> tuple[List[dict], dict[str, int]]:
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
        last_fetched_alert_create_time = arg_to_datetime(fetch_time).strftime('%Y-%m-%dT%H:%M:%S.000Z')
    else:
        fetch_limit += 1  # We skip the first alert
    alert_create_date = last_fetched_alert_create_time
    alert_id = last_fetched_alert_id

    incidents = []

    demisto.debug("Starting to fetch.")
    demisto.debug(f"Last run value before starting: {last_fetched_alert_create_time}.")

    response = client.search_alerts_request(
        type=type,
        minimum_severity=min_severity,
        device_id=device_id,
        policy_id=policy_id,
        device_username=device_username,
        query=query,
        sort_field='backend_timestamp',
        sort_order='ASC',
        create_time=assign_params(
            start=last_fetched_alert_create_time,
            end=datetime.now().strftime('%Y-%m-%dT%H:%M:%S.000Z')
        ),
        limit=fetch_limit
    )
    demisto.debug(f"Fetch server response: {response}")
    alerts = response.get('results', [])
    demisto.debug(f"Number of incidents before filtering: {len(alerts)}")

    for alert in alerts:
        if alert_id == alert.get('id'):
            demisto.debug(f"Incident with ID: {alert_id} filtered out. reason: duplicate from the last fetch, skipping")
            continue
        alert_create_date = alert.get('backend_timestamp')
        alert_id = alert.get('id')

        incident = {
            'type': 'Carbon Black Endpoint Standard',
            'name': f'Carbon Black Defense alert {alert_id}',
            'occurred': alert_create_date,
            'rawJSON': json.dumps(alert),
            'severity': convert_to_demisto_severity(alert.get('severity', 1)),
        }
        incidents.append(incident)

    demisto.debug(f"Number of Incidents after filtering: {len(incidents)}")

    new_last_run = {'last_fetched_alert_create_time': alert_create_date, 'last_fetched_alert_id': alert_id}
    demisto.debug(f"New lest run: {new_last_run}")
    return incidents, new_last_run


def get_alert_details_command(client: Client, alert_id: str):
    res = client.get_alert_by_id(alert_id)

    # headers = ['id', 'device_id', 'device_name', 'device_username', 'create_time', 'ioc_hit', 'policy_name',
    #            'process_name', 'type', 'severity']
    new_headers = ['id', 'device_id', 'device_name', 'device_username', 'ioc_hit', 'reason', 'type',
                   'threat_id', 'policy_name', 'severity']

    readable_output = tableToMarkdown('Carbon Black Defense Get Alert Details', res, new_headers,
                                      headerTransform=string_to_table_header)  # , removeNull=True)

    return CommandResults(
        outputs_prefix='CarbonBlackDefense.Alert',
        outputs_key_field='id',
        outputs=res,
        readable_output=readable_output,
        raw_response=res
    )


def alerts_search_command(client: Client, type: str, device_id: str | None = None,
                          first_event_time: str | None = None, policy_id: str | None = None, process_sha256: str | None = None,
                          reputation: str | None = None, tags: str | None = None, device_username: str | None = None,
                          query: str | None = None, rows: str | None = None, start: str | None = None):
    device_id_list = argToList(device_id)
    policy_id_list = argToList(policy_id)
    process_sha256_list = argToList(process_sha256)
    reputation_list = argToList(reputation)
    tags_list = argToList(tags)
    device_username_list = argToList(device_username)
    first_event_time_json = json.loads(first_event_time) if first_event_time else None
    rows_int = arg_to_number(rows, required=False)
    start_int = arg_to_number(start, required=False)
    type_underscore = argToList(map_alert_type(type))

    res = client.get_alerts(type_underscore, device_id_list, first_event_time_json, policy_id_list,
                            process_sha256_list, reputation_list, tags_list, device_username_list, query, rows_int, start_int)

    alerts = res.get('results', [])
    if not alerts:
        return 'No alerts were found.'

    # headers = ['id', 'category', 'device_id', 'device_name', 'device_username', 'create_time', 'ioc_hit', 'policy_name',
    #            'process_name', 'type', 'severity']
    new_headers = ['id', 'device_id', 'device_name', 'device_username', 'create_time']

    readable_output = tableToMarkdown('Carbon Black Defense Alerts List Results', alerts, new_headers,
                                      headerTransform=string_to_table_header)  # , removeNull=True)
    return CommandResults(
        outputs_prefix='CarbonBlackDefense.Alert',
        outputs_key_field='id',
        outputs=alerts,
        readable_output=readable_output,
        raw_response=res
    )


def get_policy_command(client: Client, policy_id: str):
    policy_id_int = arg_to_number(policy_id, required=True)

    res = client.get_policy_by_id(policy_id_int)

    # headers = ["id", "description", "name", "latestRevision", "version", "priorityLevel", "systemPolicy"]
    new_headers = ["id", "description", "name", "priority_level", "is_system"]

    return CommandResults(
        outputs_prefix='CarbonBlackDefense.Policy',
        outputs_key_field='id',
        outputs=res,
        readable_output=tableToMarkdown('Carbon Black Defense Policy', res, headers=new_headers,
                                        headerTransform=string_to_table_header),  # , removeNull=True),
        raw_response=res
    )


def get_policies_summary_command(client: Client):
    res = client.get_policies_summary()

    return CommandResults(
        outputs_prefix='CarbonBlackDefense.Policy',
        outputs_key_field='id',
        outputs=res.get('policies'),
        readable_output=tableToMarkdown('Policies summaries', res.get('policies')),
        raw_response=res
    )


def create_policy_command(client: Client, name: str, description: str, priority_level: str, policy: str):
    policy_json = json.loads(policy)

    # If the policy is in the old format, transform it
    # if 'policyInfo' in policy_json:
    #     policy_json = transform_policy_to_new_format(policy_json['policyInfo'])

    policy_json["name"] = name
    policy_json["description"] = description
    policy_json["priority_level"] = priority_level

    res = client.create_new_policy(policy_json)

    headers = ["id", "description", "name", "priority_level", "is_system"]

    return CommandResults(
        outputs_prefix='CarbonBlackDefense.Policy',
        outputs_key_field='id',
        outputs=res,
        readable_output=tableToMarkdown('Carbon Black Defense Policy created successfully', res, headers=headers,
                                        headerTransform=string_to_table_header, removeNull=True),
        raw_response=res
    )


def delete_policy_command(client: Client, policy_id: str):
    policy_id_int = arg_to_number(policy_id, required=True)

    client.delete_policy(policy_id_int)
    return CommandResults(readable_output=f"Policy with ID {policy_id_int} was was deleted successfully")


def add_rule_to_policy_command(client: Client, policy_id: str, action: str, operation: str, required: str, type: str, value: str):
    policy_id_int = arg_to_number(policy_id, required=True)

    res = client.add_rule_to_policy(policy_id_int, action, operation, required, type, value)

    return CommandResults(
        outputs_prefix='CarbonBlackDefense.Rule',
        outputs_key_field='id',
        outputs=res,
        readable_output=tableToMarkdown('New rule', res),
        raw_response=res
    )


def update_rule_in_policy_command(client: Client, policy_id: str, action: str, operation: str,
                                  required: str, id: str, type: str, value: str):
    policy_id_int = arg_to_number(policy_id, required=True)
    rule_id_int = arg_to_number(id, required=True)

    res = client.update_rule_in_policy(policy_id_int, action, operation, required, rule_id_int, type, value)

    return CommandResults(
        outputs_prefix='CarbonBlackDefense.Rule',
        outputs_key_field='id',
        outputs=res,
        readable_output=tableToMarkdown('New rule', res),
        raw_response=res
    )


def delete_rule_from_policy_command(client: Client, policy_id: str, rule_id: str):
    policy_id_int = arg_to_number(policy_id, required=True)
    rule_id_int = arg_to_number(rule_id, required=True)

    client.delete_rule_from_policy(policy_id_int, rule_id_int)

    return CommandResults(readable_output="The rule was successfully deleted from policy")


@polling_function(
    name='cbd-find-processes',
    interval=arg_to_number(demisto.args().get("interval_in_seconds", INTERVAL_FOR_POLLING_DEFAULT)),
    timeout=arg_to_number(demisto.args().get("timeout", TIMEOUT_FOR_POLLING_DEFAULT)),
    poll_message='search jobs in process',
    requires_polling_arg=False
)
def find_processes_command(args: dict, client: Client):
    rows = arg_to_number(args.get("rows", 10))

    if 'job_id' not in args:  # first polling iteration
        res = client.get_processes(**assign_params(**args))
        job_id = res['job_id']
        return PollResult(
            continue_to_poll=True,
            args_for_next_run={"job_id": job_id, "rows": rows},
            response=res
        )

    job_id = args['job_id']
    res = client.get_process_results(job_id=job_id, rows=rows)

    if res.get('contacted') == res.get('completed'):  # contacted == completed means done processing
        readable_output = tableToMarkdown(
            'The Results For The Process Search', res.get('results', []),
            headers=['device_id', 'device_name', 'process_name', 'device_policy_id', 'enriched_event_type'],
            removeNull=True, headerTransform=string_to_table_header
        )

        return PollResult(
            continue_to_poll=False,
            response=CommandResults(
                outputs_prefix='CarbonBlackDefense.Process.Results',
                outputs_key_field='job_id',
                outputs=res,
                readable_output=readable_output,
                raw_response=res
            )
        )

    return PollResult(
        continue_to_poll=True,
        args_for_next_run={"job_id": job_id, "rows": rows},
        response=res
    )


''' HELPER FUNCTIONS '''


def map_alert_type(old_type: str | None):
    alert_type_mapping = {
        'cbanalytics': 'CB_ANALYTICS',
        'containerruntime': 'CONTAINER_RUNTIME',
        'devicecontrol': 'DEVICE_CONTROL',
        'hostnasedfirewall': 'HOST_BASED_FIREWALL',
        'intrusiondetectionsystem': 'INTRUSION_DETECTION_SYSTEM',
        'watchlist': 'WATCHLIST',
        'all': None
    }
    return alert_type_mapping.get(old_type, None) if old_type else None


def fetch_incident_filters(params: dict):
    filters = {
        'type': argToList(map_alert_type(params.get('type'))),
        'min_severity': params.get('min_severity'),
        'device_id': argToList(params.get('device_id')),
        'policy_id': argToList(params.get('policy_id')),
        'device_username': argToList(params.get('device_username')),
        'query': params.get('query'),
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


def convert_response_to_old_format(new_response):
    old_response = {
        "policyInfo": {
            "id": new_response.get("id"),
            "name": new_response.get("name"),
            "description": new_response.get("description"),
            "priorityLevel": new_response.get("priority_level"),
            "systemPolicy": new_response.get("is_system"),
            "latestRevision": None,  # Unused field in new format
            "version": new_response.get("version"),
            "vdiAutoDeregInactiveIntervalMs": new_response.get("auto_deregister_inactive_vdi_interval_ms"),
            "knownBadHashAutoDeleteDelayMs": new_response.get("auto_delete_known_bad_hashes_delay"),
            "policy": {
                "id": None,  # Unused field in new format
                "updateVersion": None,  # Unused field in new format
                "maxRuleID": None,  # Unused field in new format
                "sensorAutoUpdateEnabled": None,  # Unused field in new format
                "pscReportingRules": None,  # Unused field in new format
                "mobileSensorSettings": None,  # Unused field in new format
                "phishingSetting": None,  # Unused field in new format
                "sensorSettings": new_response.get("sensor_settings"),
                "directoryActionRules": [
                    {
                        "actions": {
                            "FILE_UPLOAD": rule.get("file_upload"),
                            "PROTECTION": rule.get("protection")
                        }
                    } for rule in new_response.get("directory_action_rules", [])
                ],
                "rules": new_response.get("rules"),
                "avSettings": {
                    "apc": {
                        "enabled": new_response.get("av_settings", {}).get("avira_protection_cloud", {}).get("enabled"),
                        "maxFileSize": new_response.get("av_settings", {}).get("avira_protection_cloud", {}).get("max_file_size"),
                        "riskLevel": new_response.get("av_settings", {}).get("avira_protection_cloud", {}).get("risk_level"),
                        "maxExeDelay": new_response.get("av_settings", {}).get("avira_protection_cloud", {}).get("max_exe_delay")
                    },
                    "onAccessScan": {
                        "enabled": new_response.get("av_settings", {}).get("on_access_scan", {}).get("enabled"),
                        "mode": new_response.get("av_settings", {}).get("on_access_scan", {}).get("mode")
                    },
                    "onDemandScan": {
                        "enabled": new_response.get("av_settings", {}).get("on_demand_scan", {}).get("enabled"),
                        "profile": new_response.get("av_settings", {}).get("on_demand_scan", {}).get("profile"),
                        "schedule": {
                            "days": new_response.get("av_settings", {}).get("on_demand_scan", {}).get("schedule", {}).get("days"),
                            "startHour": new_response.get("av_settings", {}).get("on_demand_scan", {}).get("schedule", {}).get("start_hour"),
                            "rangeHours": new_response.get("av_settings", {}).get("on_demand_scan", {}).get("schedule", {}).get("range_hours"),
                            "recoveryScanIfMissed": new_response.get("av_settings", {}).get("on_demand_scan", {}).get("schedule", {}).get("recovery_scan_if_missed")
                        },
                        "scanUsb": new_response.get("av_settings", {}).get("on_demand_scan", {}).get("scan_usb"),
                        "scanCdDvd": new_response.get("av_settings", {}).get("on_demand_scan", {}).get("scan_cd_dvd")
                    },
                    "signatureUpdate": {
                        "enabled": new_response.get("av_settings", {}).get("signature_update", {}).get("enabled"),
                        "schedule": {
                            "fullIntervalHours": new_response.get("av_settings", {}).get("signature_update", {}).get("schedule", {}).get("full_interval_hours"),
                            "initialRandomDelayHours": new_response.get("av_settings", {}).get("signature_update", {}).get("schedule", {}).get("initial_random_delay_hours"),
                            "intervalHours": new_response.get("av_settings", {}).get("signature_update", {}).get("schedule", {}).get("interval_hours")
                        }
                    },
                    "updateServers": {
                        "serversOverride": new_response.get("av_settings", {}).get("update_servers", {}).get("servers_override"),
                        "serversForOffSiteDevices": new_response.get("av_settings", {}).get("update_servers", {}).get("servers_for_offsite_devices"),
                        "servers": [
                            {
                                "server": server.get("server"),
                                "preferred": server.get("preferred")
                            } for server in new_response.get("av_settings", {}).get("update_servers", {}).get("servers_for_onsite_devices", [])
                        ]
                    }
                }
            }
        },
        "threatSightMdrConfiguration": {
            "policyModificationPermission": new_response.get("managed_detection_response_permissions", {}).get("policy_modification"),
            "quarantinePermission": new_response.get("managed_detection_response_permissions", {}).get("quarantine")
        }
    }
    return old_response


''' MAIN FUNCTION '''


def main() -> None:
    command = demisto.command()
    args = demisto.args()

    params = demisto.params()
    base_url = params.get('url')
    api_key = params['custom_credentials'].get('identifier')
    api_secret_key = params['custom_credentials'].get('password')
    policy_api_key = params['live_response_credentials'].get('identifier')
    policy_api_secret_key = params['live_response_credentials'].get('password')
    organization_key = params.get('organization_key')

    verify_certificate = not params.get('insecure', False)

    demisto.info(f'Command being called is {command}')
    results = ''
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
        if command == 'test-module':
            results = test_module(client, params)
        elif command == 'fetch-incidents':
            fetch_time = params.get('first_fetch', '7 days')
            fetch_limit = int(params.get('max_fetch', 50))
            filters = fetch_incident_filters(params)
            incidents, last_run = fetch_incidents(client=client, fetch_time=fetch_time, fetch_limit=fetch_limit,
                                                  last_run=demisto.getLastRun(), **filters)
            demisto.incidents(incidents)
            demisto.setLastRun(last_run)
            return_results('')
        elif command == 'cbd-get-alert-details':
            results = get_alert_details_command(client=client, alert_id=args["alertId"])
        elif command == 'cbd-alerts-search':
            results = alerts_search_command(client=client, **args)
        elif command == 'cbd-get-policy':
            results = get_policy_command(client=client, policy_id=args["policyId"])
        elif command == 'cbd-delete-policy':
            results = delete_policy_command(client=client, **args)
        elif command == 'cbd-get-policies-summary':
            results = get_policies_summary_command(client=client)
        elif command == 'cbd-create-policy':
            results = create_policy_command(client=client, priority_level=args.pop('priorityLevel', None), **args)
        elif command == 'cbd-add-rule-to-policy':
            results = add_rule_to_policy_command(client=client, policy_id=args.pop('policyId'), **args)
        elif command == 'cbd-update-rule-in-policy':
            results = update_rule_in_policy_command(client=client, policy_id=args.pop('policyId'), **args)
        elif command == 'cbd-delete-rule-from-policy':
            results = delete_rule_from_policy_command(client=client, policy_id=args.pop('policyId'), rule_id=args.pop('ruleId'))
        elif command == 'cbd-find-processes':
            results = find_processes_command(client=client, args=args)
        else:
            raise NotImplementedError(f"Command {command} not implemented.")

        return_results(results)

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
