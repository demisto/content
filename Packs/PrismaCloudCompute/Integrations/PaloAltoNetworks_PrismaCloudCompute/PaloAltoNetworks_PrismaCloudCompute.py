import demistomock as demisto
from CommonServerPython import *

''' IMPORTS '''
import requests
import ipaddress
import dateparser
import tempfile
from typing import Tuple

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

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
    def __init__(self, base_url, verify, project, proxy=False, ok_codes=tuple(), headers=None, auth=None):
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
    elif sev == 'High':
        return 3
    elif sev == 'Important':
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
    if known_headers:
        headers = known_headers[:]
    else:
        headers = []

    if isinstance(data, list):
        for d in data:
            if isinstance(d, dict):
                for key in d.keys():
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
    incidents = []
    alerts = client.list_incidents()

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

            elif alert_type == ALERT_TYPE_COMPLIANCE or alert_type == ALERT_TYPE_AUDIT:
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

    return incidents


def parse_limit_and_offset_values(limit: str, offset: str) -> Tuple[int, int]:
    """
    Parse the offset and limit parameters to integers and verify that the offset/limit are valid.

    Args:
        limit (str): limit argument.
        offset (str): offset argument.

    Returns:
        Tuple[int, int]: parsed offset and parsed limit
    """
    limit, offset = arg_to_number(arg=limit, arg_name="limit"), arg_to_number(arg=offset, arg_name="offset")

    assert offset is not None and offset >= 0, f"offset {offset} is invalid, scope >= 0"
    assert limit is not None and 0 < limit <= MAX_API_LIMIT, f"limit {limit} is invalid, scope = 1-50"

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
        return dateparser.parse(date_string=date_string).strftime(new_format)
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


def filter_api_response(api_response: Optional[list], offset: int, limit: int) -> Optional[list]:
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
        table = "No results found"

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
        table = "No results found"

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
        context_output, table = {}, "No results found"

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
        context_output, table = {}, "No results found"

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
        context_output, table = {}, "No results found"

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
        table = "No results found"

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
    current_ip_feeds = client.get_custom_ip_feeds().get("feed", [])
    new_ip_feeds = argToList(arg=args.pop("ip"))

    # remove duplicates, the api doesn't give error on duplicate IPs
    combined_feeds = list(set(current_ip_feeds + new_ip_feeds))

    client.add_custom_ip_feeds(feeds=combined_feeds)

    return CommandResults(readable_output="Successfully updated the custom IP feeds")


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
    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {requested_command} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
