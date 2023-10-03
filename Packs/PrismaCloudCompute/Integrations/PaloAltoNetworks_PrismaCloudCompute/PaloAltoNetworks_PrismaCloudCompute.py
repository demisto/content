import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import urllib.parse
from collections import defaultdict


''' IMPORTS '''
import urllib3
import ipaddress
import dateparser
import tempfile
import urllib
# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

ALERT_TITLE = 'Prisma Cloud Compute Alert - '
ALERT_TYPE_VULNERABILITY = 'vulnerability'
ALERT_TYPE_COMPLIANCE = 'compliance'
ALERT_TYPE_AUDIT = 'audit'
# this is a list of known headers arranged in the order to be displayed in the markdown table
HEADERS_BY_NAME = {
    'vulnerabilities': ['severity', 'cve', 'status', 'packages', 'sourcePackage', 'packageVersion', 'link'],
    'entities': ['name', 'containerGroup', 'resourceGroup', 'nodesCount', 'image', 'status', 'runningTasksCount',
                 'activeServicesCount', 'version', 'createdAt', 'runtime', 'arn', 'lastModified', 'protected'],
    'compliance': ['type', 'id', 'description']
}
MAX_API_LIMIT = 50

''' COMMANDS + REQUESTS FUNCTIONS '''


class PrismaCloudComputeClient(BaseClient):
    def __init__(self, base_url, verify, project, proxy=False, ok_codes=(), headers=None, auth=None):
        """
        Extends the init method of BaseClient by adding the arguments below,

        verify: A 'True' or 'False' string, in which case it controls whether we verify
            the server's TLS certificate, or a string that represents a path to a CA bundle to use.
        project: A projectID string, set in the integration parameters.
            the projectID is saved under self._project
        """

        self._project = project

        if verify in ['True', 'False']:
            super().__init__(base_url, str_to_bool(verify), proxy, ok_codes, headers, auth)
        else:
            # verify points a path to certificate
            super().__init__(base_url, True, proxy, ok_codes, headers, auth)
            self._verify = verify

    def _http_request(self, method, url_suffix, full_url=None, headers=None,
                      auth=None, json_data=None, params=None, data=None, files=None,
                      timeout=10, resp_type='json', ok_codes=None, **kwargs):
        """
        Extends the _http_request method of BaseClient.
        If self._project is available, a 'project=projectID' query param is automatically added to all requests.
        """
        # if project is given add it to params and call super method
        if self._project:
            params = params or {}
            params.update({'project': self._project})

        return super()._http_request(method=method, url_suffix=url_suffix, full_url=full_url, headers=headers,
                                     auth=auth, json_data=json_data, params=params, data=data, files=files,
                                     timeout=timeout, resp_type=resp_type, ok_codes=ok_codes, **kwargs)

    def test(self):
        """
        Calls the fetch alerts endpoint with to=epoch_time to check connectivity, authentication and authorization
        """
        return self.list_incidents(to_=time.strftime('%Y-%m-%d', time.gmtime(0)))

    def list_incidents(self, to_=None, from_=None):
        """
        Sends a request to fetch available alerts from last call
        No need to pass here TO/FROM query params, the API returns new alerts from the last request
        Can be used with TO/FROM query params to get alerts in a specific time period
        REMARK: alerts are deleted from the endpoint once were successfully fetched
        """
        params = {}
        if to_:
            params['to'] = to_
        if from_:
            params['from'] = from_

        # If the endpoint not found, fallback to the previous demisto-alerts endpoint (backward compatibility)
        try:
            return self._http_request(
                method='GET',
                url_suffix='xsoar-alerts',
                params=params
            )
        except Exception as e:
            if '[404]' in str(e):
                return self._http_request(
                    method='GET',
                    url_suffix='demisto-alerts',
                    params=params
                )
            raise e

    def get_host_profiles(self, params: Optional[dict] = None) -> List[dict]:
        """
        Sends a request to get all the host profiles.

        Args:
            params (dict): query parameters.

        Returns:
            list[dict]: host profiles api response.
        """
        return self._http_request(method="GET", url_suffix="/profiles/host", params=params)

    def get_container_profiles(self, params: Optional[dict] = None) -> List[dict]:
        """
        Sends a request to get all the container profiles.

        Args:
            params (dict): query parameters.

        Returns:
            list[dict]: host profiles api response.
        """
        return self._http_request(method="GET", url_suffix="/profiles/container", params=params)

    def get_containers_hosts(self, container_id: str) -> List[str]:
        """
        Sends a request to get the hosts that host a specific container.

        Args:
            container_id (str): the container ID.

        Returns:
            list[str]: hosts IDs that host the container.
        """
        return self._http_request(method="GET", url_suffix=f"profiles/container/{container_id}/hosts")

    def get_container_forensics(self, container_id: str, params: Optional[dict] = None) -> List[dict]:
        """
        Sends a request to get a specific container forensics.

        Args:
            container_id (str): the container ID.
            params (dict): query parameters.

        Returns:
            list[dict]: container forensics.
        """
        return self._http_request(method="GET", url_suffix=f"profiles/container/{container_id}/forensic", params=params)

    def get_host_forensics(self, host_id, params: Optional[dict] = None) -> List[dict]:
        """
        Sends a request to get a specific host forensics.

        Args:
            host_id (str): the host ID.
            params (dict): query parameters.

        Returns:
            list[dict]: host forensics.
        """
        return self._http_request(method="GET", url_suffix=f"/profiles/host/{host_id}/forensic", params=params)

    def get_console_version(self) -> str:
        """
        Sends a request to get the prisma cloud compute console version.

        Returns:
            str: console version.
        """
        return self._http_request(method="GET", url_suffix="/version")

    def get_custom_ip_feeds(self) -> dict:
        """
        Sends a request to get the custom IP feeds.

        Returns:
            dict: existing IP feeds.
        """
        return self._http_request(method="GET", url_suffix="/feeds/custom/ips")

    def add_custom_ip_feeds(self, feeds: List[str]):
        """
        Sends a request to add custom IP feeds.

        Args:
            feeds (list[str]): IP feeds to add.
        """
        self._http_request(method="PUT", url_suffix="/feeds/custom/ips", resp_type="text", json_data={"feed": feeds})

    def get_custom_md5_malware(self) -> dict:
        """
        Sends a request to get the list of all custom uploaded md5 malware records

        Returns:
            dict: custom md5 malware records
        """
        return self._http_request(method="GET", url_suffix="/feeds/custom/malware")

    def add_custom_md5_malware(self, feeds: List[str]) -> None:
        """
        Sends a request to add md5 malware hashes.

        Args:
            feeds: (list[dict]): md5 malware feeds to add.
        """
        self._http_request(
            method="PUT", url_suffix="/feeds/custom/malware", json_data={"feed": feeds}, resp_type="text"
        )

    def get_cve_info(self, cve_id: str) -> List[dict]:
        """
        Sends a request to get information about a cve.

        Args:
            cve_id (str): the cve to get information about.

        Returns:
            list[dict]: cves information.
        """
        return self._http_request(method="GET", url_suffix="/cves", params={"id": cve_id})

    def get_defenders(self, params: Optional[dict] = None) -> List[dict]:
        """
        Sends a request to get defenders information.

        Returns:
            list[dict]: defenders information.
        """
        return self._http_request(method="GET", url_suffix="/defenders", params=params)

    def get_collections(self) -> List[dict]:
        """
        Sends a request to get the collections information.

        Returns:
            list[dict]: collections information.
        """
        return self._http_request(method="GET", url_suffix="/collections")

    def get_namespaces(self, params: Optional[dict] = None) -> List[str]:
        """
        Sends a request to get the namespaces.

        Args:
            params (dict): query parameters.

        Returns:
            list[str]: available namespaces
        """
        return self._http_request(method="GET", url_suffix="/radar/container/namespaces", params=params)

    def get_images_scan_info(self, params: Optional[dict] = None) -> List[dict]:
        """
        Sends a request to get information about images scans.

        Args:
            params (dict): query parameters.

        Returns:
            list[dict]: images scan information.
        """
        return self._http_request(method="GET", url_suffix="/images", params=params)

    def get_hosts_scan_info(self, params: Optional[dict] = None) -> List[dict]:
        """
        Sends a request to get information about hosts scans.

        Args:
            params (dict): query parameters.

        Returns:
            list[dict]: hosts scan information.
        """
        return self._http_request(method="GET", url_suffix="/hosts", params=params)

    def get_impacted_resources(self, cve: str, resource_type: str) -> dict:
        """
        Get the impacted resources that are based on a specific CVE.

        Args:
            cve (str): The CVE from which impacted resources will be retrieved.
            resource_type (str): ResourceType is the single resource type to return vulnerability data for.

        Returns:
            dict: the impacted resources from the CVE.
        """
        params = {"cve": cve}
        # When there is no specific resource then images and hosts will be returned if they exist
        if resource_type:
            params["resourceType"] = resource_type
        return self._http_request(
            method="GET", url_suffix="/stats/vulnerabilities/impacted-resources",
            params=params
        )

    def get_waas_policies(self) -> dict:
        """
        Get the current WAAS policy

        Returns:
            dict: the current policy.
        """
        return self._http_request(
            method="GET", url_suffix="policies/firewall/app/container"
        )

    def update_waas_policies(self, policy: dict) -> dict:
        """
        Update the waas policy.

        Args:
            policy (dict): the previous waas policy.

        Returns:
            dict: the updated policy.
        """
        return self._http_request(
            method="PUT", url_suffix="policies/firewall/app/container", json_data=policy, resp_type="response", ok_codes=(200),
            error_handler=lambda res: f"Error: {res.status_code} - {res.text}"
        )

    def get_firewall_audit_container_alerts(self, image_name: str, from_time: str, to_time: str, limit: int, audit_type: str):
        """
        Get the container audit alerts for a specific image.

        Args:
            image_name (str): The container image name.
            from_time (str): The start time of the query for alerts.
            to_time (str): The end time to query alerts.
            limit (num): the limit of alerts returned.
            audit_type (str): the alert audit type.

        Returns:
            dict: the container alerts.
        """
        params = {
            "type": audit_type,
            "imageName": image_name,
            "from": from_time,
            "to": to_time,
            "limit": limit
        }
        return self._http_request(
            method="GET", url_suffix="audits/firewall/app/container", params=params
        )

    def get_alert_profiles_request(self, project):
        """
        Get the alert profiles.

        Args:
            project (str): The project name

        Returns:
            dict: the alert profiles
        """
        params = assign_params(project=project)
        headers = self._headers

        return self._http_request('get', 'alert-profiles', headers=headers, params=params)

    def get_settings_defender_request(self, hostname):
        """
        Get the defender settings.

        Returns:
            dict: the defender settings
        """
        headers = self._headers
        params = assign_params(hostname=hostname)

        return self._http_request('get', 'settings/defender', headers=headers, params=params)

    def get_logs_defender_request(self, hostname, lines):
        """
        Get the defender logs.

        Returns:
            list: the defender logs
        """
        params = assign_params(hostname=hostname, lines=lines)
        headers = self._headers

        return self._http_request('get', 'logs/defender', params=params, headers=headers)

    def get_backups_request(self, project):
        """
        Get the defender backups.

        Args:
            project (str): The project name

        Returns:
            list: the defender backups
        """
        params = assign_params(project=project)
        headers = self._headers

        return self._http_request('get', 'backups', headers=headers, params=params)

    def get_logs_defender_download_request(self, hostname, lines):
        """
        Download all logs for a certain defender

        Args:
            hostname (str): The hostname to get the logs for
            lines (int): The number of logs to return

        Returns:
            list: the logs to download
        """
        params = assign_params(hostname=hostname, lines=lines)

        headers = self._headers
        return self._http_request('get', 'logs/defender/download', params=params, headers=headers, resp_type="content")


def format_context(context):
    """
    Format the context keys
    """
    if context and isinstance(context, dict):
        context = {pascalToSpace(key).replace(" ", ""): format_context(value) for key, value in context.items()}
    elif context and isinstance(context, list):
        context = [format_context(item) for item in context]
    return context


def str_to_bool(s):
    """
    Translates string representing boolean value into boolean value
    """
    if s == 'True':
        return True
    elif s == 'False':
        return False
    else:
        raise ValueError


def translate_severity(sev):
    """
    Translates Prisma Cloud Compute alert severity into Demisto's severity score
    """

    sev = sev.capitalize()

    if sev == 'Critical':
        return 4
    elif sev in ['High', 'Important']:
        return 3
    elif sev == 'Medium':
        return 2
    elif sev == 'Low':
        return 1
    return 0


def camel_case_transformer(s):
    """
    Converts a camel case string into space separated words starting with a capital letters
    E.g. input: 'camelCase' output: 'Camel Case'
    REMARK: the exceptions list below is returned uppercase, e.g. "cve" => "CVE"
    """

    transformed_string = re.sub('([a-z])([A-Z])', r'\g<1> \g<2>', str(s))
    if transformed_string in ['id', 'cve', 'arn']:
        return transformed_string.upper()
    return transformed_string.title()


def get_headers(name: str, data: list) -> list:
    """
    Returns a list of headers to the given list of objects
    If the list name is known (listed in the HEADERS_BY_NAME) it returns the list and checks for any additional headers
     in the given list
    Else returns the given headers from the given list
    Args:
        name: name of the list (e.g. vulnerabilities)
        data: list of dicts

    Returns: list of headers
    """

    # check the list for any additional headers that might have been added
    known_headers = HEADERS_BY_NAME.get(name)
    headers = known_headers[:] if known_headers else []

    if isinstance(data, list):
        for d in data:
            if isinstance(d, dict):
                for key in d:
                    if key not in headers:
                        headers.append(key)
    return headers


def test_module(client):
    """
    Test connection, authentication and user authorization
    Args:
        client: Requests client
    Returns:
        'ok' if test passed, error from client otherwise
    """

    client.test()
    return 'ok'


@logger
def is_command_is_fetch():
    """
    Rules wether the executed command is fetch_incidents or classifier
    - If Last Run is set, then it's a fetch_incident command.
    Otherwise, the results are dependent on the fetched_incidents_list section in integration context:
    If it's empty, then it means that fetch_incidents already ran once and therefore it must be a classifier.

    :return: True if this is a fetch_incidents command, otherwise return false.
    :rtype: ``bool``
    """
    if demisto.getLastRun():
        return True
    else:
        return not demisto.getIntegrationContext().get('fetched_incidents_list', [])


def fetch_incidents(client):
    """
    Fetches new alerts from Prisma Cloud Compute and returns them as a list of Demisto incidents
    - A markdown table will be added for alerts with a list object,
      If the alert has a list under field "tableField", another field will be added to the
      incident "tableFieldMarkdownTable" representing the markdown table
    Args:
        client: Prisma Compute client
    Returns:
        list of incidents
    """
    if is_command_is_fetch():
        demisto.debug("is_command_is_fetch = true, calling list_incidents")
        alerts = client.list_incidents()

        incidents = []
        if alerts:
            for a in alerts:
                alert_type = a.get('kind')
                name = ALERT_TITLE
                severity = 0

                # fix the audit category from camel case to display properly
                if alert_type == ALERT_TYPE_AUDIT:
                    a['category'] = camel_case_transformer(a.get('category'))

                # always save the raw JSON data under this argument (used in scripts)
                a['rawJSONAlert'] = json.dumps(a)

                # parse any list into a markdown table, since tableToMarkdown takes the headers from the first object in
                # the list check headers manually since some entries might have omit empty fields
                tables = {}
                for key, value in a.items():
                    # check only if we got a non empty list of dict
                    if isinstance(value, list) and value and isinstance(value[0], dict):
                        tables[key + 'MarkdownTable'] = tableToMarkdown(camel_case_transformer(key + ' table'),
                                                                        value,
                                                                        headers=get_headers(key, value),
                                                                        headerTransform=camel_case_transformer,
                                                                        removeNull=True)

                a.update(tables)

                if alert_type == ALERT_TYPE_VULNERABILITY:
                    # E.g. "Prisma Cloud Compute Alert - imageName Vulnerabilities"
                    name += a.get('imageName') + ' Vulnerabilities'
                    # Set the severity to the highest vulnerability, take the first from the list
                    severity = translate_severity(a.get('vulnerabilities')[0].get('severity'))

                elif alert_type in (ALERT_TYPE_COMPLIANCE, ALERT_TYPE_AUDIT):
                    # E.g. "Prisma Cloud Compute Alert - Incident"
                    name += camel_case_transformer(a.get('type'))
                    # E.g. "Prisma Cloud Compute Alert - Image Compliance" \ "Prisma Compute Alert - Host Runtime Audit"
                    if a.get('type') != "incident":
                        name += ' ' + camel_case_transformer(alert_type)

                else:
                    # E.g. "Prisma Cloud Compute Alert - Cloud Discovery"
                    name += camel_case_transformer(alert_type)

                incidents.append({
                    'name': name,
                    'occurred': a.get('time'),
                    'severity': severity,
                    'rawJSON': json.dumps(a)
                })

        demisto.debug("Setting last run to 'id': 'a'")
        demisto.setLastRun({"id": "a"})

        ctx = demisto.getIntegrationContext()
        demisto.debug(f"Integration Context before update = {ctx}")

        incidents_to_update = incidents or ctx.get('fetched_incidents_list')
        ctx.update({'fetched_incidents_list': incidents_to_update})
        demisto.setIntegrationContext(ctx)
        demisto.debug(f"Integration Context after update = {ctx}")

        return incidents

    else:
        ctx = demisto.getIntegrationContext().get('fetched_incidents_list', [])
        demisto.debug(f"Integration Context (is_command_is_fetch = false) = {ctx}")
        return ctx


def parse_limit_and_offset_values(limit: str, offset: str = "0") -> tuple[int, int]:
    """
    Parse the offset and limit parameters to integers and verify that the offset/limit are valid.

    Args:
        limit (str): limit argument.
        offset (str): offset argument.

    Returns:
        Tuple[int, int]: parsed offset and parsed limit
    """
    limit, offset = arg_to_number(arg=limit, arg_name="limit"), arg_to_number(arg=offset, arg_name="offset")

    assert offset is not None
    assert offset >= 0, f"offset {offset} is invalid, scope >= 0"
    assert limit is not None
    assert 0 < limit <= MAX_API_LIMIT, f"limit {limit} is invalid, scope = 1-50"

    return limit, offset


def parse_date_string_format(date_string: str, new_format: str = "%B %d, %Y %H:%M:%S %p") -> str:
    """
    Parses a date string format to a different date string format.

    Args:
        date_string (str): the date in string representation.
        new_format (str): the new requested format for the date string.

    Returns:
        str: date as a new format, in case of a failure returns the original date string.
    """
    try:
        parsed_date = dateparser.parse(date_string=date_string)  # type: ignore
        return parsed_date.strftime(new_format)  # type: ignore
    except AttributeError:
        return date_string


def epochs_to_timestamp(epochs: int, date_format: str = "%B %d, %Y %H:%M:%S %p") -> str:
    """
    Converts epochs time representation to a new string date format.

    Args:
        epochs (int): time in epochs (seconds)
        date_format (str): the desired format that the timestamp will be.

    Returns:
        str: timestamp in the new format, empty string in case of a failure
    """
    try:
        return datetime.utcfromtimestamp(epochs).strftime(date_format)
    except TypeError:
        return ""


def filter_api_response(api_response: Optional[list], limit: int, offset: int = 0) -> Optional[list]:
    """
    Filter the api response according to the offset/limit.

    Args:
        api_response (list): api response from an endpoint.
        offset (int): the offset from which to begin listing the response.
        limit (int): the maximum limit of records in the response to fetch.

    Returns:
        list: api filtered response, None in case the api response is empty
    """
    if not api_response:
        return api_response

    start = min(offset, len(api_response))
    end = min(offset + limit, len(api_response))
    return api_response[start:end]


def get_hostname_description_info(host_info: dict) -> dict:
    """
    Get the hostname description information.

    Args:
        host_info (dict): host's information from the api.

    Returns:
        dict: host description information.
    """
    if (labels := host_info.get("labels")) and len(labels) == 2:
        dist = labels[0].replace("osDistro:", "") + " " + labels[1].replace("osVersion:", "")
    else:
        dist = ""

    return {
        "Hostname": host_info.get("_id"),
        "Distribution": dist,
        "Collections": host_info.get("collections")
    }


def get_profile_host_list(client: PrismaCloudComputeClient, args: dict) -> CommandResults:
    """
    Get information about the hosts and their profile events.
    Implement the command 'prisma-cloud-compute-profile-host-list'

    Args:
        client (PrismaCloudComputeClient): prisma-cloud-compute client.
        args (dict): prisma-cloud-compute-profile-host-list command arguments.

    Returns:
        CommandResults: command-results object.
    """
    if "hostname" in args:
        args["hostName"] = args.pop("hostname")

    args["limit"], args["offset"] = parse_limit_and_offset_values(
        limit=args.get("limit", "15"), offset=args.get("offset", "0")
    )

    if hosts_profile_info := client.get_host_profiles(params=assign_params(**args)):
        for host_profile in hosts_profile_info:
            for event in host_profile.get("sshEvents", []):
                if "ip" in event:
                    # transforms ip as integer representation to ip as string representation
                    event["ip"] = str(ipaddress.IPv4Address(event.get("ip")))
                if "time" in event:
                    event["time"] = parse_date_string_format(date_string=host_profile.get("time", ""))

                # loginTime is in unix format
                if "loginTime" in event:
                    event["loginTime"] = epochs_to_timestamp(epochs=event.get("loginTime"))

        if len(hosts_profile_info) == 1:  # means we have only one host
            host_info = hosts_profile_info[0]

            host_description_table = tableToMarkdown(
                name="Host Description",
                t=get_hostname_description_info(host_info=host_info),
                headers=["Hostname", "Distribution", "Collections"],
                removeNull=True
            )

            apps_table = tableToMarkdown(
                name="Apps",
                t=[
                    {
                        "AppName": app.get("name"),
                        "StartupProcess": app.get("startupProcess").get("path"),
                        "User": app.get("startupProcess").get("user"),
                        "LaunchTime": parse_date_string_format(date_string=app.get("startupProcess").get("time"))
                    } for app in host_info.get("apps", [])
                ],
                headers=["AppName", "StartupProcess", "User", "LaunchTime"],
                removeNull=True
            )
            ssh_events_table = tableToMarkdown(
                name="SSH Events",
                t=[
                    {
                        "User": event.get("user"),
                        "Ip": event.get("ip"),
                        "ProcessPath": event.get("path"),
                        "Command": event.get("command"),
                        "Time": event.get("time")
                    } for event in host_info.get("sshEvents", [])
                ],
                headers=["User", "Ip", "ProcessPath", "Command", "Time"],
                removeNull=True
            )

            table = host_description_table + apps_table + ssh_events_table
        else:
            table = tableToMarkdown(
                name="Host Description",
                t=[get_hostname_description_info(host_info=host_info) for host_info in hosts_profile_info],
                headers=["Hostname", "Distribution", "Collections"],
                removeNull=True
            )
    else:
        table = "No results found."

    return CommandResults(
        outputs_prefix="PrismaCloudCompute.ProfileHost",
        outputs_key_field="_id",
        outputs=hosts_profile_info,
        readable_output=table,
        raw_response=hosts_profile_info
    )


def get_container_description_info(container_info: dict) -> dict:
    """
    Get the container description information.

    Args:
        container_info (dict): container information from the api.

    Returns:
        dict: container description information.
    """
    return {
        "ContainerID": container_info.get("_id"),
        "Image": container_info.get("image"),
        "Os": container_info.get("os"),
        "State": container_info.get("state"),
        "Created": parse_date_string_format(date_string=container_info.get("created", "")),
        "EntryPoint": container_info.get("entrypoint")
    }


def get_container_profile_list(client: PrismaCloudComputeClient, args: dict) -> CommandResults:
    """
    Get information about the containers and their profile events.
    Implement the command 'prisma-cloud-compute-profile-container-list'

    Args:
        client (PrismaCloudComputeClient): prisma-cloud-compute client.
        args (dict): prisma-cloud-compute-profile-container-list command arguments.

    Returns:
        CommandResults: command-results object.
    """
    if "image_id" in args:
        args["imageID"] = args.pop("image_id")
    args["limit"], args["offset"] = parse_limit_and_offset_values(
        limit=args.get("limit", "15"), offset=args.get("offset", "0")
    )

    if containers_info := client.get_container_profiles(params=assign_params(**args)):
        container_description_headers = ["ContainerID", "Image", "Os", "State", "Created", "EntryPoint"]

        if len(containers_info) == 1:  # means we have only one container
            container_info = containers_info[0]

            container_description_table = tableToMarkdown(
                name="Container Description",
                t=get_container_description_info(container_info=container_info),
                headers=container_description_headers,
                removeNull=True
            )

            processes_table = tableToMarkdown(
                name="Processes",
                t=[
                    {
                        "Type": process_type,
                        "Md5": process.get("md5"),
                        "Path": process.get("path"),
                        "DetectionTime": parse_date_string_format(date_string=process.get("time"))
                    } for process_type in ["static", "behavioral"]
                    for process in container_info.get("processes", {}).get(process_type, "")
                ],
                headers=["Type", "Path", "DetectionTime", "Md5"],
                removeNull=True
            )

            table = container_description_table + processes_table
        else:
            table = tableToMarkdown(
                name="Container Description",
                t=[get_container_description_info(container_info=container_info) for container_info in containers_info],
                headers=container_description_headers,
                removeNull=True
            )
    else:
        table = "No results found."

    return CommandResults(
        outputs_prefix='PrismaCloudCompute.ProfileContainer',
        outputs_key_field='_id',
        outputs=containers_info,
        readable_output=table,
        raw_response=containers_info
    )


def get_container_hosts_list(client: PrismaCloudComputeClient, args: dict) -> CommandResults:
    """
    Returns the hosts where the containers are running.
    Implement the command 'prisma-cloud-compute-profile-container-hosts-list'.

    Args:
        client (PrismaCloudComputeClient): prisma-cloud-compute client.
        args (dict): prisma-cloud-compute-profile-container-hosts-list command arguments.

    Returns:
        CommandResults: command-results object.
    """
    container_id = args.pop("id")
    limit, offset = parse_limit_and_offset_values(limit=args.get("limit", "50"), offset=args.get("offset", "0"))

    if hosts := filter_api_response(
        api_response=client.get_containers_hosts(container_id=container_id),
        limit=limit,
        offset=offset
    ):
        context_output = {
            "containerID": container_id,
            "hostsIDs": hosts
        }
        table = tableToMarkdown(
            name="Hosts",
            t=context_output,
            headers=["hostsIDs"],
            headerTransform=lambda word: word[0].upper() + word[1:]
        )
    else:
        context_output, table = {}, "No results found."

    return CommandResults(
        outputs_prefix="PrismaCloudCompute.ProfileContainerHost",
        outputs=context_output if context_output else None,
        readable_output=table,
        outputs_key_field="containerID",
        raw_response=hosts
    )


def get_profile_container_forensic_list(client: PrismaCloudComputeClient, args: dict) -> CommandResults:
    """
    Returns runtime forensics data for a specific container on a specific host.
    Implement the command 'prisma-cloud-compute-profile-container-forensic-list'

    Args:
        client (PrismaCloudComputeClient): prisma-cloud-compute client.
        args (dict): prisma-cloud-compute-profile-container-forensic-list command arguments.

    Returns:
        CommandResults: command-results object.
    """
    if "incident_id" in args:
        args["incidentID"] = args.pop("incident_id")

    container_id = args.pop("id")
    # api request does not support offset only, but does support limit.
    limit, offset = parse_limit_and_offset_values(limit=args.get("limit", "20"), offset=args.pop("offset", "0"))
    # because the api supports only limit, it is necessary to add the requested offset to the limit be able to take the
    # correct offset:limit after the api call.
    args["limit"] = limit + offset

    if container_forensics := filter_api_response(
        api_response=client.get_container_forensics(container_id=container_id, params=assign_params(**args)),
        limit=limit,
        offset=offset
    ):
        for forensic in container_forensics:
            remove_nulls_from_dictionary(data=forensic)
            if "timestamp" in forensic:
                forensic["timestamp"] = parse_date_string_format(date_string=forensic.get("timestamp", ""))
            if "listeningStartTime" in forensic:
                forensic["listeningStartTime"] = parse_date_string_format(
                    date_string=forensic.get("listeningStartTime", "")
                )

        context_output = {
            "containerID": container_id,
            "hostname": args.get("hostname"),
            "Forensics": container_forensics
        }

        table = tableToMarkdown(
            name="Containers forensic report",
            t=context_output["Forensics"],
            headers=["type", "path", "user", "pid", "containerId", "timestamp", "command"],
            removeNull=True,
            headerTransform=lambda word: word[0].upper() + word[1:]
        )
    else:
        context_output, table = {}, "No results found."

    return CommandResults(
        outputs_prefix='PrismaCloudCompute.ContainerForensic',
        outputs=context_output if context_output else None,
        readable_output=table,
        outputs_key_field=["containerID", "hostname"],
        raw_response=container_forensics
    )


def get_profile_host_forensic_list(client: PrismaCloudComputeClient, args: dict) -> CommandResults:
    """
    Returns runtime forensics data for a specific host.
    Implement the command 'prisma-cloud-compute-host-forensic-list'

    Args:
        client (PrismaCloudComputeClient): prisma-cloud-compute client.
        args (dict): prisma-cloud-compute-host-forensic-list command arguments.

    Returns:
        CommandResults: command-results object.
    """
    if "incident_id" in args:
        args["incidentID"] = args.pop("incident_id")

    host_id = args.pop("id")
    # api request does not support offset only, but does support limit.
    limit, offset = parse_limit_and_offset_values(limit=args.get("limit", "15"), offset=args.pop("offset", "0"))
    # because the api supports only limit, it is necessary to add the requested offset to the limit be able to take the
    # correct offset:limit after the api call.
    args["limit"] = limit + offset

    if host_forensics := filter_api_response(
        api_response=client.get_host_forensics(host_id=host_id, params=assign_params(**args)),
        limit=limit,
        offset=offset
    ):
        for forensic in host_forensics:
            remove_nulls_from_dictionary(data=forensic)
            if "timestamp" in forensic:
                forensic["timestamp"] = parse_date_string_format(date_string=forensic.get("timestamp", ""))
            if "listeningStartTime" in forensic:
                forensic["listeningStartTime"] = parse_date_string_format(
                    date_string=forensic.get("listeningStartTime", "")
                )

        context_output = {
            "hostID": host_id,
            "Forensics": host_forensics
        }

        table = tableToMarkdown(
            name="Host forensics report",
            t=host_forensics,
            headers=["type", "path", "user", "pid", "timestamp", "command", "app"],
            removeNull=True,
            headerTransform=lambda word: word[0].upper() + word[1:]
        )
    else:
        context_output, table = {}, "No results found."

    return CommandResults(
        outputs_prefix='PrismaCloudCompute.HostForensic',
        outputs=context_output if context_output else None,
        readable_output=table,
        outputs_key_field="hostID",
        raw_response=host_forensics
    )


def get_console_version(client: PrismaCloudComputeClient) -> CommandResults:
    """
    Returns the version of the prisma cloud compute console.
    Implement the command 'prisma-cloud-compute-console-version-info'.

    Args:
        client (PrismaCloudComputeClient): prisma-cloud-compute client.

    Returns:
        CommandResults: command-results object.
    """
    version = client.get_console_version()

    return CommandResults(
        outputs_prefix="PrismaCloudCompute.Console.Version",
        outputs=version,
        readable_output=tableToMarkdown(name="Console version", t={"Version": version}, headers=["Version"]),
        raw_response=version
    )


def get_custom_feeds_ip_list(client: PrismaCloudComputeClient) -> CommandResults:
    """
    Get all the BlackListed IP addresses in the system.
    Implement the command 'prisma-cloud-compute-custom-feeds-ip-list'

    Args:
        client (PrismaCloudComputeClient): prisma-cloud-compute client.

    Returns:
        CommandResults: command-results object.
    """
    if feeds := client.get_custom_ip_feeds():
        if "modified" in feeds:
            feeds["modified"] = parse_date_string_format(date_string=feeds.get("modified", ""))
        if "_id" in feeds:
            feeds.pop("_id")
        table = tableToMarkdown(
            name="IP Feeds",
            t=feeds,
            headers=["modified", "feed"],
            removeNull=True,
            headerTransform=lambda word: word[0].upper() + word[1:]
        )
    else:
        table = "No results found."

    return CommandResults(
        outputs_prefix="PrismaCloudCompute.CustomFeedIP",
        outputs=feeds,
        readable_output=table,
        outputs_key_field="digest",
        raw_response=feeds
    )


def add_custom_ip_feeds(client: PrismaCloudComputeClient, args: dict) -> CommandResults:
    """
    Add a list of banned IPs to be blocked by the system.
    Implement the command 'prisma-cloud-compute-custom-feeds-ip-add'

    Args:
        client (PrismaCloudComputeClient): prisma-cloud-compute client.
        args (dict): prisma-cloud-compute-custom-feeds-ip-add command arguments.

    Returns:
        CommandResults: command-results object.
    """
    # the api overrides the blacklisted IPs, therefore it is necessary to add those who exist to the 'PUT' request.
    current_ip_feeds = (client.get_custom_ip_feeds() or {}).get("feed") or []
    new_ip_feeds = argToList(arg=args.pop("ip"))

    # remove duplicates, the api doesn't give error on duplicate IPs
    combined_feeds = list(set(current_ip_feeds + new_ip_feeds))

    client.add_custom_ip_feeds(feeds=combined_feeds)

    return CommandResults(readable_output="Successfully updated the custom IP feeds")


def get_custom_malware_feeds(client: PrismaCloudComputeClient, args: dict) -> CommandResults:
    """
    List all custom uploaded md5 malware records.
    Implement the command 'prisma-cloud-compute-custom-feeds-malware-list'

    Args:
        client (PrismaCloudComputeClient): prisma-cloud-compute client.
        args (dict): prisma-cloud-compute-custom-feeds-malware-list command arguments.

    Returns:
        CommandResults: command-results object.
    """
    limit, _ = parse_limit_and_offset_values(limit=args.get("limit", "50"))
    feeds_info = client.get_custom_md5_malware() or {}

    if "_id" in feeds_info:
        feeds_info.pop("_id")  # not needed, it will be removed from the api in the future.
    if "modified" in feeds_info:
        feeds_info["modified"] = parse_date_string_format(date_string=feeds_info.get("modified", ""))

    # api does not support limit/offset
    if malware_feeds := filter_api_response(api_response=feeds_info.get("feed", []), limit=limit):
        for feed in malware_feeds:
            if "modified" in feed:
                # there is no option to modify a specific malware feed, hence its redundant (and always returns 0)
                feed.pop("modified")

        table = tableToMarkdown(
            name="Malware Md5 Feeds",
            t=malware_feeds,
            headers=["name", "md5", "allowed"],
            headerTransform=lambda word: word[0].upper() + word[1:],
            removeNull=True
        )
        feeds_info["feed"] = malware_feeds
    else:
        table = "No results found."

    return CommandResults(
        outputs_prefix="PrismaCloudCompute.CustomFeedMalware",
        outputs=feeds_info if table != "No results found." else None,
        readable_output=table,
        outputs_key_field="digest",
        raw_response=feeds_info
    )


def add_custom_malware_feeds(client: PrismaCloudComputeClient, args: dict) -> CommandResults:
    """
    Add custom md5 hashes of malware to the prisma cloud compute.
    Implement the command 'prisma-cloud-compute-custom-feeds-malware-add'

    Args:
        client (PrismaCloudComputeClient): prisma-cloud-compute client.
        args (dict): prisma-cloud-compute-custom-feeds-malware-add command arguments.

    Returns:
        CommandResults: command-results object.
    """
    # the api overrides the md5 malware hashes, therefore it is necessary to add those who exist to the 'PUT' request.
    feeds = (client.get_custom_md5_malware() or {}).get('feed') or []

    name = args.get("name")
    md5s = argToList(arg=args.get("md5", []))

    existing_md5s = {feed.get("md5") for feed in feeds}
    for md5 in md5s:
        if md5 not in existing_md5s:  # verify that there are no duplicates because the api doesn't handle it
            feeds.append({"name": name, "md5": md5})

    client.add_custom_md5_malware(feeds=feeds)

    return CommandResults(readable_output="Successfully updated the custom md5 malware feeds")


def get_cves(client: PrismaCloudComputeClient, args: dict) -> List[CommandResults]:
    """
    Get cves information, implement the command 'cve'.

    Args:
        client (PrismaCloudComputeClient): prisma-cloud-compute client.
        args (dict): cve command arguments.

    Returns:
        CommandResults: command-results object.
    """
    cve_ids = argToList(arg=args.get("cve", [])) or argToList(arg=args.get("cve_id", []))

    if not cve_ids:
        raise DemistoException("You must provide a value to the `cve` argument")

    all_cves_information, results, unique_cve_ids = [], [], set()

    for _id in cve_ids:
        if cves_info := client.get_cve_info(cve_id=_id):
            all_cves_information.extend(cves_info)

    if filtered_cves_information := filter_api_response(api_response=all_cves_information, limit=MAX_API_LIMIT):
        for cve_info in filtered_cves_information:
            cve_id, cvss = cve_info.get("cve"), cve_info.get("cvss")
            modified, description = epochs_to_timestamp(epochs=cve_info.get("modified")), cve_info.get("description")

            if cve_id not in unique_cve_ids:
                unique_cve_ids.add(cve_id)

                cve_data = {
                    "ID": cve_id, "CVSS": cvss, "Modified": modified, "Description": description
                }

                results.append(
                    CommandResults(
                        outputs_prefix="CVE",
                        outputs_key_field=["ID"],
                        outputs=cve_data,
                        indicator=Common.CVE(
                            id=cve_id, cvss=cvss, published="", modified=modified, description=description
                        ),
                        raw_response=filtered_cves_information,
                        readable_output=tableToMarkdown(name=cve_id, t=cve_data)
                    )
                )

        return results

    return [CommandResults(readable_output="No results found.")]


def get_defenders(client: PrismaCloudComputeClient, args: dict) -> CommandResults:
    """
    Retrieve a list of defenders and their information.
    Implement the command 'prisma-cloud-compute-defenders-list'.

    Args:
        client (PrismaCloudComputeClient): prisma-cloud-compute client.
        args (dict): prisma-cloud-compute-defenders-list command arguments.

    Returns:
        CommandResults: command-results object.
    """
    limit, offset = parse_limit_and_offset_values(
        limit=args.get("limit", "20"), offset=args.get("offset", "0")
    )
    cluster, connected, hostname, type = (
        args.get("cluster"), args.get("connected"), args.get("hostname"), args.get("type")
    )
    params = assign_params(
        cluster=cluster, connected=connected, hostname=hostname, type=type, limit=limit, offset=offset
    )

    if defenders := client.get_defenders(params=params):
        for defender in defenders:
            if "lastModified" in defender:
                defender["lastModified"] = parse_date_string_format(date_string=defender.get("lastModified", ""))

        table = tableToMarkdown(
            name="Defenders Information",
            t=[
                {
                    "hostname": defender.get("hostname"),
                    "version": defender.get("version"),
                    "cluster": defender.get("cluster"),
                    "status": f"Connected since {defender.get('lastModified')}"
                    if defender.get("connected") else f"Disconnected since {defender.get('lastModified')}",
                    "listener": defender.get("features", {}).get("proxyListenerType")
                } for defender in defenders
            ],
            headers=["hostname", "version", "cluster", "status", "listener"],
            removeNull=True,
            headerTransform=lambda word: word[0].upper() + word[1:]
        )
    else:
        table = "No results found."

    return CommandResults(
        outputs_prefix="PrismaCloudCompute.DefenderDetails",
        outputs_key_field="hostname",
        outputs=defenders,
        readable_output=table,
        raw_response=defenders
    )


def get_collections(client: PrismaCloudComputeClient, args: dict) -> CommandResults:
    """
    Get collections information, implement the 'command prisma-cloud-compute-collections-list'

    Args:
        client (PrismaCloudComputeClient): prisma-cloud-compute client.
        args (dict): prisma-cloud-compute-collections-list command arguments

    Returns:
        CommandResults: command-results object.
    """
    limit, _ = parse_limit_and_offset_values(limit=args.get("limit", "50"))

    # api does not support limit
    if collections := filter_api_response(api_response=client.get_collections(), limit=limit):
        for collection in collections:
            if "modified" in collection:
                collection["modified"] = parse_date_string_format(date_string=collection.get("modified"))

        table = tableToMarkdown(
            name="Collections Information",
            t=collections,
            headers=["name", "description", "owner", "modified"],
            removeNull=True,
            headerTransform=lambda word: word[0].upper() + word[1:]
        )
    else:
        collections, table = [], "No results found."

    return CommandResults(
        outputs_prefix="PrismaCloudCompute.Collection",
        outputs_key_field=["name", "owner", "description"],
        outputs=collections if collections else None,
        readable_output=table,
        raw_response=collections
    )


def get_namespaces(client: PrismaCloudComputeClient, args: dict) -> CommandResults:
    """
    Get the list of the namespaces.
    Implement the command 'prisma-cloud-compute-container-namespace-list'

    Args:
        client (PrismaCloudComputeClient): prisma-cloud-compute client.
        args (dict): prisma-cloud-compute-container-namespace-list command arguments

    Returns:
        CommandResults: command-results object.
    """
    limit, _ = parse_limit_and_offset_values(limit=args.pop("limit", "50"))
    cluster, collections = args.get("cluster"), args.get("collections")
    params = assign_params(cluster=cluster, collections=collections)

    # api does not support limit
    if namespaces := filter_api_response(api_response=client.get_namespaces(params=params), limit=limit):
        # when the api returns [""] (a list with empty string), it means that the system does not have any namespaces
        if len(namespaces) == 1 and namespaces[0] == "":
            namespaces, table = [], "No results found."
        else:
            table = tableToMarkdown(
                name="Namespaces",
                t=[{"Namespace": namespace} for namespace in namespaces],
                headers=["Namespace"]
            )
    else:
        namespaces, table = [], "No results found."

    return CommandResults(
        outputs_prefix="PrismaCloudCompute.RadarContainerNamespace",
        outputs=namespaces if namespaces else None,
        readable_output=table,
        raw_response=namespaces
    )


def get_image_descriptions(images_scans: List[dict]) -> List[dict]:
    """
    Get the image descriptions

    Args:
        images_scans (list[dict]): images scans information.

    Returns:
        List[dict]: images descriptions.
    """
    return [
        {
            "Image": (image_scan.get("instances") or [{}])[0].get("image"),
            "ID": image_scan.get("_id"),
            "OS Distribution": image_scan.get("distro"),
            "Vulnerabilities Count": image_scan.get("vulnerabilitiesCount"),
            "Compliance Issues Count": image_scan.get("complianceIssuesCount")
        } for image_scan in images_scans
    ]


def get_images_scan_list(client: PrismaCloudComputeClient, args: dict) -> CommandResults:
    """
    Get the images scan list.
    Implement the command 'prisma-cloud-compute-images-scan-list'

    Args:
        client (PrismaCloudComputeClient): prisma-cloud-compute client.
        args (dict): prisma-cloud-compute-images-scan-list command arguments

    Returns:
        CommandResults: command-results object.
    """
    limit, offset = parse_limit_and_offset_values(
        limit=args.pop("limit_record", "10"), offset=args.get("offset", "0")
    )
    stats_limit, _ = parse_limit_and_offset_values(limit=args.pop("limit_stats", "10"))
    compact = argToBoolean(value=args.get("compact", "true"))
    clusters, fields, hostname, id, name = (
        args.get("clusters"), args.get("fields"), args.get("hostname"), args.get("id"), args.get("name")
    )
    registry, repository = args.get("registry"), args.get("repository")

    params = assign_params(
        limit=limit, offset=offset, compact=compact, clusters=clusters, fields=fields,
        hostname=hostname, id=id, name=name, registry=registry, repository=repository
    )

    if images_scans := client.get_images_scan_info(params=params):
        for scan in images_scans:
            if "vulnerabilities" in scan:
                # filter the vulnerabilities amount according to stats_limit
                scan["vulnerabilities"] = filter_api_response(
                    api_response=scan.get("vulnerabilities"), limit=stats_limit
                )
                if vulnerabilities := scan.get("vulnerabilities"):
                    for vuln in vulnerabilities:
                        if "fixDate" in vuln:
                            vuln["fixDate"] = epochs_to_timestamp(epochs=vuln.get("fixDate", 0))
            if "complianceIssues" in scan:
                # filter the complianceIssues amount according to stats_limit
                scan["complianceIssues"] = filter_api_response(
                    api_response=scan.get("complianceIssues"), limit=stats_limit
                )
                if compliances := scan.get("complianceIssues"):
                    for compliance in compliances:
                        if "fixDate" in compliance:
                            compliance["fixDate"] = epochs_to_timestamp(epochs=compliance.get("fixDate", 0))

        image_description_table = tableToMarkdown(
            name="Image description",
            t=get_image_descriptions(images_scans=images_scans),
            headers=["ID", "Image", "OS Distribution", "Vulnerabilities Count", "Compliance Issues Count"],
            removeNull=True
        )

        if len(images_scans) == 1:  # then there is only one image scan report
            if compact:
                # if the compact is True, the api will filter
                # the response and send back only vulnerability/compliance statistics
                vuln_statistics_table = tableToMarkdown(
                    name="Vulnerability Statistics",
                    t=images_scans[0].get("vulnerabilityDistribution"),
                    headers=["critical", "high", "medium", "low"],
                    removeNull=True,
                    headerTransform=lambda word: word[0].upper() + word[1:]
                )

                compliance_statistics_table = tableToMarkdown(
                    name="Compliance Statistics",
                    t=images_scans[0].get("complianceDistribution"),
                    headers=["critical", "high", "medium", "low"],
                    removeNull=True,
                    headerTransform=lambda word: word[0].upper() + word[1:]
                )

                table = image_description_table + vuln_statistics_table + compliance_statistics_table
            else:
                # handle the case where there is an image scan without vulnerabilities
                vulnerabilities = images_scans[0].get("vulnerabilities")
                if not vulnerabilities:
                    vulnerabilities = []

                vulnerabilities_table = tableToMarkdown(
                    name="Vulnerabilities",
                    t=vulnerabilities,
                    headers=["cve", "description", "severity", "packageName", "status", "fixDate"],
                    removeNull=True,
                    headerTransform=pascalToSpace,
                )
                # handle the case where there is an image scan without compliances
                compliances = images_scans[0].get("complianceIssues")
                if not compliances:
                    compliances = []

                compliances_table = tableToMarkdown(
                    name="Compliances",
                    t=compliances,
                    headers=["id", "severity", "status", "description", "packageName", "fixDate"],
                    removeNull=True,
                    headerTransform=pascalToSpace
                )

                table = image_description_table + vulnerabilities_table + compliances_table
        else:
            table = image_description_table
    else:
        table = "No results found."

    return CommandResults(
        outputs_prefix="PrismaCloudCompute.ReportsImagesScan",
        outputs_key_field="id",
        outputs=images_scans,
        readable_output=table,
    )


def get_hosts_descriptions(hosts_scans):
    """
    Get the hosts descriptions

    Args:
        hosts_scans (list[dict]): hosts scans information.

    Returns:
        List[dict]: images descriptions.
    """
    return [
        {
            "Hostname": scan.get("hostname"),
            "OS Distribution": scan.get("distro"),
            "Docker Version": scan.get("applications", [{}])[0].get("version"),
            "Vulnerabilities Count": scan.get("vulnerabilitiesCount"),
            "Compliance Issues Count": scan.get("complianceIssuesCount")
        } for scan in hosts_scans
    ]


def get_hosts_scan_list(client: PrismaCloudComputeClient, args: dict) -> CommandResults:
    """
    Get the host scan list.
    Implement the command 'prisma-cloud-compute-hosts-scan-list'

    Args:
        client (PrismaCloudComputeClient): prisma-cloud-compute client.
        args (dict): prisma-cloud-compute-hosts-scan-list command arguments

    Returns:
        CommandResults: command-results object.
    """
    limit, offset = parse_limit_and_offset_values(
        limit=args.pop("limit_record", "10"), offset=args.get("offset", "0")
    )
    stats_limit, _ = parse_limit_and_offset_values(limit=args.pop("limit_stats", "10"))
    compact = argToBoolean(value=args.get("compact", "true"))
    clusters, fields, hostname, provider, distro = (
        args.get("clusters"), args.get("fields"), args.get("hostname"), args.get("provider"), args.get("distro")
    )

    params = assign_params(
        limit=limit, offset=offset, compact=compact, clusters=clusters,
        fields=fields, hostname=hostname, provider=provider, distro=distro
    )

    if hosts_scans := client.get_hosts_scan_info(params=params):
        for scan in hosts_scans:
            if "vulnerabilities" in scan:
                scan["vulnerabilities"] = filter_api_response(
                    api_response=scan.get("vulnerabilities"), limit=stats_limit
                )
                if vulnerabilities := scan.get("vulnerabilities"):
                    for vuln in vulnerabilities:
                        if "fixDate" in vuln:
                            vuln["fixDate"] = epochs_to_timestamp(epochs=vuln.get("fixDate", 0))
            if "complianceIssues" in scan:
                scan["complianceIssues"] = filter_api_response(
                    api_response=scan.get("complianceIssues"), limit=stats_limit
                )
                if compliances := scan.get("complianceIssues"):
                    for compliance in compliances:
                        if "fixDate" in compliance:
                            compliance["fixDate"] = epochs_to_timestamp(epochs=compliance.get("fixDate", 0))

        host_description_table = tableToMarkdown(
            name="Host description",
            t=get_hosts_descriptions(hosts_scans=hosts_scans),
            headers=[
                "Hostname", "Docker Version", "OS Distribution", "Vulnerabilities Count", "Compliance Issues Count"
            ],
            removeNull=True
        )

        if len(hosts_scans) == 1:  # then there is only one host scan report
            if compact:
                # if the compact is True, the api will filter
                # the response and send back only vulnerability/compliance statistics
                vuln_statistics_table = tableToMarkdown(
                    name="Vulnerability Statistics",
                    t=hosts_scans[0].get("vulnerabilityDistribution"),
                    headers=["critical", "high", "medium", "low"],
                    removeNull=True,
                    headerTransform=lambda word: word[0].upper() + word[1:]
                )

                compliance_statistics_table = tableToMarkdown(
                    name="Compliance Statistics",
                    t=hosts_scans[0].get("complianceDistribution"),
                    headers=["critical", "high", "medium", "low"],
                    removeNull=True,
                    headerTransform=lambda word: word[0].upper() + word[1:]
                )

                table = host_description_table + vuln_statistics_table + compliance_statistics_table
            else:
                # handle the case where there is an host scan without vulnerabilities
                vulnerabilities = hosts_scans[0].get("vulnerabilities")
                if not vulnerabilities:
                    vulnerabilities = []

                vulnerabilities_table = tableToMarkdown(
                    name="Vulnerabilities",
                    t=vulnerabilities,
                    headers=["cve", "description", "severity", "packageName", "status", "fixDate"],
                    removeNull=True,
                    headerTransform=pascalToSpace,
                )
                # handle the case where there is an host scan without compliances
                compliances = hosts_scans[0].get("complianceIssues")
                if not compliances:
                    compliances = []

                compliances_table = tableToMarkdown(
                    name="Compliances",
                    t=compliances,
                    headers=["id", "severity", "status", "description", "packageName", "fixDate"],
                    removeNull=True,
                    headerTransform=pascalToSpace
                )

                table = host_description_table + vulnerabilities_table + compliances_table
        else:
            table = host_description_table
    else:
        table = "No results found."

    return CommandResults(
        outputs_prefix="PrismaCloudCompute.ReportHostScan",
        outputs_key_field="_id",
        outputs=hosts_scans,
        readable_output=table,
    )


def get_impacted_resources(client: PrismaCloudComputeClient, args: dict) -> CommandResults:
    """
    Get the impacted resources list.
    Implement the command 'prisma-cloud-compute-vulnerabilities-impacted-resources-list'

    Args:
        client (PrismaCloudComputeClient): prisma-cloud-compute client.
        args (dict): prisma-cloud-compute-vulnerabilities-impacted-resources-list command arguments

    Returns:
        CommandResults: command-results object.
    """
    limit, offset = parse_limit_and_offset_values(limit=args.pop("limit", "50"), offset=args.pop("offset", "0"))
    cves = argToList(arg=args.get("cve", []))
    resource_type = args.get("resourceType", "")

    context_output, raw_response = [], {}
    final_impacted_resources: defaultdict[str, list] = defaultdict(list)
    resources_list = ["images", "registryImages", "hosts", "functions", "codeRepos"]
    for cve in cves:
        # api does not support offset/limit
        if cve_impacted_resources := client.get_impacted_resources(cve=cve, resource_type=resource_type):
            raw_response[cve] = cve_impacted_resources
            for resources in resources_list:
                if resources in cve_impacted_resources and cve_impacted_resources.get(resources) is not None:
                    cve_impacted_resources[resources] = filter_api_response(
                        api_response=cve_impacted_resources[resources],  # type: ignore[arg-type]
                        limit=limit,
                        offset=offset
                    )

                    for resource in (cve_impacted_resources.get(resources) or []):
                        resource_id_table_details = {
                            "resourceID": resource.get("resourceID"),
                        }
                        if containers := (resource.get('containers') or []):
                            for container in containers:
                                resource_id_table_details['Cve'] = cve
                                resource_id_table_details['Image'] = container.get('image')
                                resource_id_table_details['Container'] = container.get('container')
                                resource_id_table_details['Host'] = container.get("host")
                                resource_id_table_details['Namespace'] = container.get("namespace")

                        if resource_id_table_details not in final_impacted_resources[resources]:
                            final_impacted_resources[resources].append(resource_id_table_details)

            context_output.append(cve_impacted_resources)

    if context_output:
        impacted_resources_tables = []
        mapping_resources_to_names = {"images": "Impacted Images",
                                      "registryImages": "Impacted Registry Images",
                                      "hosts": "Impacted Hosts",
                                      "functions": "Impacted Functions",
                                      "codeRepos": "Impacted CodeRepos"
                                      }
        for resources in resources_list:
            if final_impacted_resources.get(resources):
                impacted_resources_tables.append(tableToMarkdown(
                    name=mapping_resources_to_names.get(resources),
                    t=final_impacted_resources.get(resources),
                    headers=["resourceID", "Cve", "Image", "Container", "Host", "Namespace"],
                    removeNull=True)
                )
        table = ''.join(impacted_resources_tables)
    else:
        context_output, table = [], "No results found."

    return CommandResults(
        outputs_prefix="PrismaCloudCompute.VulnerabilitiesImpactedResource",
        outputs_key_field="_id",
        outputs=context_output if context_output else None,
        readable_output=table,
        raw_response=raw_response
    )


def get_waas_policies(client: PrismaCloudComputeClient, args: dict) -> List[CommandResults]:
    """
    Get the WAAS policies.
    Implement the command 'prisma-cloud-compute-get-waas-policies'

    Args:
        client (PrismaCloudComputeClient): prisma-cloud-compute client.
        args (dict): prisma-cloud-compute-get-waas-policies command arguments

    Returns:
        CommandResults: command-results object.
    """
    policies = client.get_waas_policies()
    entry = []
    for rule in policies.get("rules") or {}:
        for spec in rule.get("applicationsSpec") or {}:
            formatted_waas_policy = {
                "SQLInjection": spec.get("sqli").get("effect"),
                "CrossSiteScriptingXSS": spec.get("xss").get("effect"),
                "OSCommandInjetion": spec.get("cmdi").get("effect"),
                "CodeInjection": spec.get("codeInjection").get("effect"),
                "LocalFileInclusion": spec.get("lfi").get("effect"),
                "AttackToolsAndVulnScanners": spec.get("attackTools").get("effect"),
                "Shellshock": spec.get("shellshock").get("effect"),
                "MalformedHTTPRequest": spec.get("malformedReq").get("effect"),
                "ATP": spec.get("networkControls").get("advancedProtectionEffect"),
                "DetectInformationLeakage": spec.get("intelGathering").get("infoLeakageEffect")
            }
            data = {
                "Name": rule.get("name"),
                "WaasPolicy": formatted_waas_policy
            }

            entry.append(CommandResults(
                outputs_prefix="PrismaCloudCompute.Policies",
                outputs_key_field="Name",
                outputs=data,
                readable_output=tableToMarkdown(data["Name"], data["WaasPolicy"]),
                raw_response=policies
            ))

    return entry


def update_waas_policies(client: PrismaCloudComputeClient, args: dict) -> CommandResults:
    """
    Update the WAAS policy.
    Implement the command 'prisma-cloud-compute-update-waas-policies'

    Args:
        client (PrismaCloudComputeClient): prisma-cloud-compute client.
        args (dict): prisma-cloud-compute-update-waas-policies command arguments

    Returns:
        CommandResults: command-results object.
    """
    # waas_settings = ["sqli", "xss", "attackTools", "shellshock", "malformedReq", "cmdi", "lfi", "codeInjection"]

    policy = args.get("policy", {})

    for index, rule in enumerate(policy.get("rules")):
        if rule["name"] != args.get("rule_name"):
            continue
        for spec in policy.get("rules")[index].get("applicationsSpec"):
            spec[args.get("attack_type")] = {"effect": args.get("action")}

    client.update_waas_policies(policy)
    txt = "Successfully updated the WaaS policy"

    return CommandResults(
        readable_output=txt
    )


def get_audit_firewall_container_alerts(client: PrismaCloudComputeClient, args: dict) -> CommandResults:
    """
    Get the firewall container alerts.
    Implement the command 'prisma-cloud-compute-get-audit-firewall-container-alerts'

    Args:
        client (PrismaCloudComputeClient): prisma-cloud-compute client.
        args (dict): prisma-cloud-compute-get-audit-firewall-container-alerts command arguments

    Returns:
        CommandResults: command-results object.
    """
    now = datetime.now()
    from_day = arg_to_number(args.get("FromDays", 2))
    from_time = now - timedelta(days=from_day)      # type: ignore
    image_name = urllib.parse.quote(args.get("ImageName"), safe='')     # type: ignore
    audit_type = args.get("audit_type")
    limit = arg_to_number(args.get("limit", 25))
    data = client.get_firewall_audit_container_alerts(
        image_name=image_name, from_time=f"{from_time.isoformat()}Z", to_time=f"{now.isoformat()}Z",
        limit=limit, audit_type=audit_type)  # type: ignore

    return CommandResults(
        outputs_prefix="PrismaCloudCompute.Audits",
        outputs_key_field="_id",
        outputs=data,
        readable_output=tableToMarkdown("Audits", data),
        raw_response=data
    )


def get_alert_profiles_command(client: PrismaCloudComputeClient, args: dict):
    """
    Get the alert profiles.

    Args:
        client (PrismaCloudComputeClient): prisma-cloud-compute client.
        args (dict): prisma-cloud-compute-get-alert-profiles command arguments

    Returns:
        CommandResults: command-results object.
    """
    project = args.get("project")
    response = client.get_alert_profiles_request(project)
    policies = []
    for res in response:
        policies.append(res.get("policy"))
    return CommandResults(
        outputs_prefix='PrismaCloudCompute.AlertProfiles',
        outputs_key_field='_Id',
        outputs=format_context(response),
        readable_output=tableToMarkdown("Alert Profiles", policies),
        raw_response=response
    )


def get_settings_defender_command(client: PrismaCloudComputeClient, args: dict):
    """
    Get the defender settings.

    Args:
        client (PrismaCloudComputeClient): prisma-cloud-compute client.
        args (dict): prisma-cloud-compute-get-settings-defender command arguments

    Returns:
        CommandResults: command-results object.
    """
    hostname = args.get("hostname")
    response = client.get_settings_defender_request(hostname)
    return CommandResults(
        outputs_prefix='PrismaCloudCompute.DefenderSettings',
        outputs=format_context(response),
        raw_response=response
    )


def get_logs_defender_command(client: PrismaCloudComputeClient, args: dict):
    """
    Get the defender logs.

    Args:
        client (PrismaCloudComputeClient): prisma-cloud-compute client.
        args (dict): prisma-cloud-compute-logs-defender command arguments

    Returns:
        CommandResults: command-results object.
    """
    hostname = args.get('hostname', '')
    lines = args.get('lines')

    response = client.get_logs_defender_request(hostname, lines) or []
    entry = {
        "Hostname": hostname,
        "Logs": response
    }
    return CommandResults(
        outputs_prefix='PrismaCloudCompute.Defenders',
        outputs=format_context(entry),
        outputs_key_field='Hostname',
        raw_response=response,
        readable_output=tableToMarkdown("Logs", entry.get("Logs"))
    )


def get_backups_command(client: PrismaCloudComputeClient, args: dict):
    """
    Get the defender backups.

    Args:
        client (PrismaCloudComputeClient): prisma-cloud-compute client.
        args (dict): prisma-cloud-compute-get-backups command arguments

    Returns:
        CommandResults: command-results object.
    """
    project = args.get("project")
    response = client.get_backups_request(project) or []
    return CommandResults(
        outputs_prefix='PrismaCloudCompute.Backups',
        outputs_key_field='Id',
        outputs=format_context(response),
        raw_response=response
    )


def get_logs_defender_download_command(client: PrismaCloudComputeClient, args: dict):
    """
    Get the defender logs download bundle.

    Args:
        client (PrismaCloudComputeClient): prisma-cloud-compute client.
        args (dict): prisma-cloud-compute-logs-defender-download command arguments

    Returns:
        CommandResults: command-results object.
    """
    hostname = args.get('hostname')
    lines = args.get('lines')

    response = client.get_logs_defender_download_request(hostname, lines)
    return fileResult(f"{hostname}-logs.tar.gz", response, entryTypes["entryInfoFile"])


def main():
    """
    PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params = demisto.params()
    username = params.get('credentials').get('identifier')
    password = params.get('credentials').get('password')
    base_url = params.get('address')
    project = params.get('project', '')
    verify_certificate = not params.get('insecure', False)
    cert = params.get('certificate')
    proxy = params.get('proxy', False)

    # If checked to verify and given a certificate, save the certificate as a temp file
    # and set the path to the requests client
    if verify_certificate and cert:
        tmp = tempfile.NamedTemporaryFile(delete=False, mode='w')
        tmp.write(cert)
        tmp.close()
        verify = tmp.name
    else:
        # Save boolean as a string
        verify = str(verify_certificate)

    try:
        requested_command = demisto.command()
        LOG(f'Command being called is {requested_command}')

        # Init the client
        client = PrismaCloudComputeClient(
            base_url=urljoin(base_url, 'api/v1/'),
            verify=verify,
            auth=(username, password),
            proxy=proxy,
            project=project
        )

        if requested_command == 'test-module':
            # This is the call made when pressing the integration test button
            result = test_module(client)
            demisto.results(result)

        elif requested_command == 'fetch-incidents':
            # Fetch incidents from Prisma Cloud Compute
            # this method is called periodically when 'fetch incidents' is checked
            incidents = fetch_incidents(client)
            demisto.incidents(incidents)
        elif requested_command == 'prisma-cloud-compute-profile-host-list':
            return_results(results=get_profile_host_list(client=client, args=demisto.args()))
        elif requested_command == 'prisma-cloud-compute-profile-container-list':
            return_results(results=get_container_profile_list(client=client, args=demisto.args()))
        elif requested_command == 'prisma-cloud-compute-profile-container-hosts-list':
            return_results(results=get_container_hosts_list(client=client, args=demisto.args()))
        elif requested_command == 'prisma-cloud-compute-profile-container-forensic-list':
            return_results(results=get_profile_container_forensic_list(client=client, args=demisto.args()))
        elif requested_command == 'prisma-cloud-compute-host-forensic-list':
            return_results(results=get_profile_host_forensic_list(client=client, args=demisto.args()))
        elif requested_command == 'prisma-cloud-compute-custom-feeds-ip-add':
            return_results(results=add_custom_ip_feeds(client=client, args=demisto.args()))
        elif requested_command == 'prisma-cloud-compute-console-version-info':
            return_results(results=get_console_version(client=client))
        elif requested_command == 'prisma-cloud-compute-custom-feeds-ip-list':
            return_results(results=get_custom_feeds_ip_list(client=client))
        elif requested_command == 'prisma-cloud-compute-profile-host-list':
            return_results(results=get_profile_host_list(client=client, args=demisto.args()))
        elif requested_command == 'prisma-cloud-compute-profile-container-list':
            return_results(results=get_container_profile_list(client=client, args=demisto.args()))
        elif requested_command == 'prisma-cloud-compute-profile-container-hosts-list':
            return_results(results=get_container_hosts_list(client=client, args=demisto.args()))
        elif requested_command == 'prisma-cloud-compute-profile-container-forensic-list':
            return_results(results=get_profile_container_forensic_list(client=client, args=demisto.args()))
        elif requested_command == 'prisma-cloud-compute-host-forensic-list':
            return_results(results=get_profile_host_forensic_list(client=client, args=demisto.args()))
        elif requested_command == 'prisma-cloud-compute-custom-feeds-ip-add':
            return_results(results=add_custom_ip_feeds(client=client, args=demisto.args()))
        elif requested_command == 'prisma-cloud-compute-console-version-info':
            return_results(results=get_console_version(client=client))
        elif requested_command == 'prisma-cloud-compute-custom-feeds-ip-list':
            return_results(results=get_custom_feeds_ip_list(client=client))
        elif requested_command == 'prisma-cloud-compute-custom-feeds-malware-list':
            return_results(results=get_custom_malware_feeds(client=client, args=demisto.args()))
        elif requested_command == 'prisma-cloud-compute-custom-feeds-malware-add':
            return_results(results=add_custom_malware_feeds(client=client, args=demisto.args()))
        elif requested_command == 'cve':
            return_results(results=get_cves(client=client, args=demisto.args()))
        elif requested_command == 'prisma-cloud-compute-defenders-list':
            return_results(results=get_defenders(client=client, args=demisto.args()))
        elif requested_command == 'prisma-cloud-compute-collections-list':
            return_results(results=get_collections(client=client, args=demisto.args()))
        elif requested_command == 'prisma-cloud-compute-container-namespace-list':
            return_results(results=get_namespaces(client=client, args=demisto.args()))
        elif requested_command == 'prisma-cloud-compute-images-scan-list':
            return_results(results=get_images_scan_list(client=client, args=demisto.args()))
        elif requested_command == 'prisma-cloud-compute-hosts-scan-list':
            return_results(results=get_hosts_scan_list(client=client, args=demisto.args()))
        elif requested_command == 'prisma-cloud-compute-vulnerabilities-impacted-resources-list':
            return_results(results=get_impacted_resources(client=client, args=demisto.args()))
        elif requested_command == 'prisma-cloud-compute-get-waas-policies':
            return_results(results=get_waas_policies(client=client, args=demisto.args()))
        elif requested_command == 'prisma-cloud-compute-update-waas-policies':
            return_results(update_waas_policies(client=client, args=demisto.args()))
        elif requested_command == 'prisma-cloud-compute-get-audit-firewall-container-alerts':
            return_results(results=get_audit_firewall_container_alerts(client, args=demisto.args()))
        elif requested_command == "prisma-cloud-compute-get-alert-profiles":
            return_results(results=get_alert_profiles_command(client=client, args=demisto.args()))
        elif requested_command == "prisma-cloud-compute-get-settings-defender":
            return_results(results=get_settings_defender_command(client=client, args=demisto.args()))
        elif requested_command == "prisma-cloud-compute-logs-defender":
            return_results(results=get_logs_defender_command(client=client, args=demisto.args()))
        elif requested_command == "prisma-cloud-compute-get-backups":
            return_results(results=get_backups_command(client=client, args=demisto.args()))
        elif requested_command == "prisma-cloud-compute-logs-defender-download":
            return_results(results=get_logs_defender_download_command(client=client, args=demisto.args()))
    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {requested_command} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
