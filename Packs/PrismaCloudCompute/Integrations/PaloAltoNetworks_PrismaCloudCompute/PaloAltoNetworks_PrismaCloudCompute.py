import demistomock as demisto
from CommonServerPython import *

''' IMPORTS '''
import requests
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

    def api_request(
        self, method, url_suffix, full_url=None, headers=None, auth=None, json_data=None, params=None, data=None,
        files=None, timeout=10, resp_type='json', ok_codes=None, **kwargs
    ):
        """
        A wrapper method for the http request.
        """
        if method == 'PUT':
            resp_type = 'text'

        return self._http_request(
            method=method, url_suffix=url_suffix, full_url=full_url, headers=headers, auth=auth, json_data=json_data,
            params=params, data=data, files=files, timeout=timeout, resp_type=resp_type, ok_codes=ok_codes, **kwargs
        )

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


def validate_limit_and_offset(func):
    """
    Decorator to validate that the limit and offset in the command arguments are correct.
    The maximum objects that can be returned is 50.
    """
    def wrapper(*args, **kwargs):

        # maximum of objects per request
        api_limit_call = 50

        command_args = kwargs.get('args')
        offset = arg_to_number(arg=command_args.get('offset'), arg_name='offset')  # type:ignore
        if offset < 0:  # type:ignore
            offset = 0
        command_args['offset'] = offset  # type:ignore

        limit = arg_to_number(arg=command_args.get('limit'), arg_name='limit')  # type:ignore
        if limit > api_limit_call:  # type:ignore
            limit = api_limit_call  # type:ignore
        command_args['limit'] = limit  # type:ignore

        return func(*args, **kwargs)

    return wrapper


def update_query_params_names(names: List[Tuple[str, str]], args: dict) -> None:
    """
    Update the query parameters names.

    Args:
        names (list): a list of old name and new names to replace.
        args (dict): a dict to replace its old key names with new key names.
    """
    for old_name, new_name in names:
        if old_name in args:
            args[new_name] = args.pop(old_name)


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


def capitalize_api_response(api_response: Union[List[dict], dict]) -> Union[List[dict], dict]:
    """
    Capitalize an api response.

    Args:
        api_response (list/dict): The api response.

    Returns:
        list/dict where its keys are capitalized.
    """
    if isinstance(api_response, dict):
        return capitalize_dict_keys(dictionary=api_response)
    return [capitalize_dict_keys(dictionary=response) for response in api_response]


def capitalize_dict_keys(dictionary):
    """
    Capitalize dict keys.

    Args:
        dictionary (dict): any dictionary where its keys are strings.

    Returns:
        Capitalized dict keys.
    """
    return {key[0].upper() + key[1:] if "_" not in key else key.title(): val for key, val in dictionary.items()}


def get_api_filtered_response(
    client: PrismaCloudComputeClient,
        url_suffix: str,
        offset: int,
        limit: int,
        args: Optional[dict] = None,
        capitalize: bool = True
) -> list:
    """
    Filter the api response according to the offset/limit, used in case the api doesn't support limit/offset

    Args:
        client (PrismaCloudComputeClient): prisma-cloud-compute client.
        url_suffix (str): url suffix of the base api url.
        offset (int): the offset from which to begin listing the response.
        limit (int): the maximum limit of records in the response to fetch.
        args (dict): any command arguments if exist.
        capitalize (bool): whether or not to capitalize the response keys.

    Returns:
        list: api filtered response, empty list in case there aren't any records in the api response.
    """
    if not args:
        args = {}

    response = client.api_request(method='GET', url_suffix=url_suffix, params=assign_params(**args))

    if response:
        if capitalize:
            response = capitalize_api_response(api_response=response)
        start = min(offset, len(response))
        end = min(offset + limit, len(response))
        return response[start:end]

    return []


def build_profile_host_table_response(hosts_info: List[dict]) -> str:
    """
    Build a table from the api response of the profile host
    list for the command 'prisma-cloud-compute-profile-host-list'

    Args:
        hosts_info (list[dict]): the api raw response.

    Returns:
        str: markdown table output for the apps and ssh events of a host.
    """
    if not hosts_info:
        return tableToMarkdown(name="No results found", t={})

    apps_table = []
    ssh_events_table = []

    for response in hosts_info:
        for app in response.get('apps', []):
            apps_table.append(
                {
                    'HostId': response.get('_Id'),
                    'AppName': app.get('name'),
                    'StartupProcess': app.get('startupProcess').get('path'),
                    'User': app.get('startupProcess').get('user'),
                    'LaunchTime': parse_date_string_format(date_string=app.get('startupProcess').get('time'))

                }
            )
        for event in response.get('SshEvents', []):
            ssh_events_table.append(
                {
                    'HostId': response.get('_Id'),
                    'User': event.get('user'),
                    'Ip': event.get('ip'),
                    'ProcessPath': event.get('path'),
                    'Command': event.get('command'),
                    'Time': parse_date_string_format(date_string=event.get('time'))
                }
            )

    apps_markdown_table = tableToMarkdown(
        name='Apps', t=apps_table, headers=['HostId', 'AppName', 'StartupProcess', 'User', 'LaunchTime']
    )
    ssh_events_markdown_table = tableToMarkdown(
        name='SSH Events', t=ssh_events_table, headers=['HostId', 'User', 'Ip', 'ProcessPath', 'Command', 'Time']
    )

    return apps_markdown_table + ssh_events_markdown_table


@validate_limit_and_offset
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
    update_query_params_names(names=[("hostname", "hostName")], args=args)
    hosts_profile_info_raw_response = client.api_request(
        method='GET', url_suffix='/profiles/host', params=assign_params(**args)
    )
    hosts_profile_info = None

    if hosts_profile_info_raw_response:
        hosts_profile_info = capitalize_api_response(api_response=hosts_profile_info_raw_response)

    return CommandResults(
        outputs_prefix='PrismaCloudCompute.ProfileHost',
        outputs_key_field='_Id',
        outputs=hosts_profile_info,
        readable_output=build_profile_host_table_response(hosts_info=hosts_profile_info),  # type:ignore
        raw_response=hosts_profile_info_raw_response
    )


def build_profile_container_table_response(containers_info: List[dict]) -> str:
    """
    Build a table from the api response of the profile container
    list for the command 'prisma-cloud-compute-profile-container-list'

    Args:
        containers_info (list[dict]): the api raw response.

    Returns:
        str: markdown table output.
    """
    if not containers_info:
        return tableToMarkdown(name="No results found", t={})

    container_details = []
    processes = []

    for container_info in containers_info:
        container_details.append(
            {
                "ContainerID": container_info.get("_Id"),
                "Image": container_info.get("Image"),
                "OS": container_info.get("Os"),
                "State": container_info.get("State"),
                "Created": parse_date_string_format(date_string=container_info.get("Created"))  # type:ignore
            }
        )

        for process_type in ["static", "behavioral"]:
            for static_process in container_info.get("processes", {}).get(process_type, ""):
                processes.append(
                    {
                        "ContainerID": container_info.get("_id"),
                        "Type": process_type,
                        "Path": static_process.get("path"),
                        "DetectionTime": parse_date_string_format(date_string=static_process.get("time"))
                    }
                )

    container_details_table = tableToMarkdown(
        name='Container information',
        t=container_details,
        headers=['ContainerID', 'Image', 'OS', 'State', 'Created']
    )
    processes_table = tableToMarkdown(
        name='Containers processes',
        t=processes,
        headers=['ContainerID', 'Type', 'Path', 'DetectionTime']
    )

    return container_details_table + processes_table


@validate_limit_and_offset
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
    update_query_params_names(names=[("image_id", "imageID")], args=args)
    containers_info_raw_response = client.api_request(
        method='GET', params=assign_params(**args), url_suffix='/profiles/container'
    )
    containers_info = None

    if containers_info_raw_response:
        containers_info = capitalize_api_response(api_response=containers_info_raw_response)

    return CommandResults(
        outputs_prefix='PrismaCloudCompute.ProfileContainer',
        outputs_key_field='_Id',
        outputs=containers_info,
        readable_output=build_profile_container_table_response(containers_info=containers_info),  # type:ignore
        raw_response=containers_info_raw_response
    )


def build_container_hosts_response(
    client: PrismaCloudComputeClient, container_id: str, args: dict
) -> Tuple[dict, str]:
    """
    Build a table and a context response for the 'prisma-cloud-compute-profile-container-hosts-list' command.

    Args:
        client (PrismaCloudComputeClient): prisma-cloud-compute client.
        container_id (str): container ID.
        args (dict): prisma-cloud-compute-profile-container-list command arguments.

    Returns:
        Tuple[dict, str]: Context and table response.
    """
    # this api endpoint does not support either limit/offset.
    limit, offset = args.pop("limit"), args.pop("offset")

    hosts_ids = get_api_filtered_response(
        client=client,
        url_suffix=f"profiles/container/{container_id}/hosts",
        offset=offset,
        limit=limit,
        args=args,
        capitalize=False
    )

    if hosts_ids:
        context_output = {
            "ContainerID": container_id,
            "HostsIDs": hosts_ids
        }
        return context_output, tableToMarkdown(
            name="Containers hosts list", t=context_output, headers=["ContainerID", "HostsIDs"]
        )
    return {}, tableToMarkdown(name="No results found", t=[])


@validate_limit_and_offset
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
    context, table = build_container_hosts_response(client=client, container_id=container_id, args=args)

    return CommandResults(
        outputs_prefix="PrismaCloudCompute.ProfileContainerHost",
        outputs=context if context else None,
        readable_output=table,
        outputs_key_field="ContainerID"
    )


def build_containers_forensic_response(
    client: PrismaCloudComputeClient, container_id: str, args: dict
) -> Tuple[dict, str]:
    """
    Build a table and a context response for the 'prisma-cloud-compute-profile-container-forensic-list' command.

    Args:
        client (PrismaCloudComputeClient): prisma-cloud-compute client.
        container_id (str): container ID.
        args (dict): prisma-cloud-compute-profile-container-forensic-list command arguments.

    Returns:
        Tuple[dict, str]: Context and table response.
    """
    table = []
    # api request does not support offset only, but does support limit.
    offset = args.pop("offset")
    # because the api supports only limit, it is necessary to add the requested offset to the limit be able to take the
    # correct offset:limit after the api call.
    limit = args.get("limit", 20)
    args["limit"] = offset + args["limit"]

    container_forensics = get_api_filtered_response(
        client=client, url_suffix=f"profiles/container/{container_id}/forensic", offset=offset, limit=limit, args=args
    )

    if container_forensics:
        context_output = {
            "ContainerID": container_id,
            "Hostname": args.get("hostname"),
            "Forensics": container_forensics
        }

        for report in container_forensics:
            if report.get("containerId"):
                table.append(
                    {
                        "ContainerID": report.get("containerId"),
                        "Type": report.get("type"),
                        "Path": report.get("path"),
                    }
                )
        return context_output, tableToMarkdown(
            name="Containers forensic report",
            t=table,
            headers=["ContainerID", "Type", "Path", "Process"],
            removeNull=True
        )
    return {}, tableToMarkdown(name="No results found", t=[])


@validate_limit_and_offset
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
    container_id = args.pop("id")
    update_query_params_names(names=[("incident_id", "incidentID")], args=args)
    context, table = build_containers_forensic_response(
        client=client, container_id=container_id, args=args  # type:ignore
    )

    return CommandResults(
        outputs_prefix='PrismaCloudCompute.ContainerForensic',
        outputs=context if context else None,
        readable_output=table,
        outputs_key_field=["ContainerID", "Hostname"]
    )


def build_host_forensic_response(
    client: PrismaCloudComputeClient, host_id: str, args: dict
) -> Tuple[dict, str]:
    """
    Build a table and a context response for the 'prisma-cloud-compute-host-forensic-list' command.

    Args:
        client (PrismaCloudComputeClient): prisma-cloud-compute client.
        host_id (str): host ID.
        args (dict): prisma-cloud-compute-profile-container-forensic-list command arguments.

    Returns:
        Tuple[dict, str]: Context and table response.
    """
    # api request does not support offset only, but does support limit.
    offset = args.pop("offset")
    limit = args.get("limit", 20)
    # because the api supports only limit, it is necessary to add the requested offset to the limit be able to take the
    # correct offset:limit after the api call.
    args["limit"] = offset + args["limit"]

    host_forensics = get_api_filtered_response(
        client=client, url_suffix=f"/profiles/host/{host_id}/forensic", offset=offset, limit=limit, args=args
    )

    if host_forensics:
        context_output = {
            "HostID": host_id,
            "Forensics": host_forensics
        }

        return context_output, tableToMarkdown(
            name="Host forensics report", t=host_forensics, headers=["type", "app", "path", "command"], removeNull=True
        )
    return {}, tableToMarkdown(name="No results found", t=[])


@validate_limit_and_offset
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
    host_id = args.pop("id")
    update_query_params_names(names=[("incident_id", "incidentID"), ("event_time", "eventTime")], args=args)
    context, table = build_host_forensic_response(client=client, host_id=host_id, args=args)

    return CommandResults(
        outputs_prefix='PrismaCloudCompute.HostForensic',
        outputs=context if context else None,
        readable_output=table,
        outputs_key_field="HostID"
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
    version = client.api_request(method="GET", url_suffix="/version").upper()

    return CommandResults(
        outputs_prefix="PrismaCloudCompute.Console.Version",
        outputs=version,
        readable_output=tableToMarkdown(name="Console version", t={"Version": version}, headers=["Version"])
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
    feeds = capitalize_api_response(api_response=client.api_request(method='GET', url_suffix="/feeds/custom/ips"))

    if feeds:
        if "Modified" in feeds:
            feeds["Modified"] = parse_date_string_format(date_string=feeds.get("Modified", ""))  # type:ignore
        table = tableToMarkdown(name="IP Feeds", t=feeds, headers=["modified", "feed"])
    else:
        table = tableToMarkdown(name="No results found", t=[])

    return CommandResults(
        outputs_prefix="PrismaCloudCompute.CustomFeedIP",
        outputs=feeds,
        readable_output=table,
        outputs_key_field="Digest"
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
    current_ip_feeds = client.api_request(method="GET", url_suffix="/feeds/custom/ips").get("feed", [])
    new_ip_feeds = argToList(arg=args.pop("ip"))

    # remove duplicates, the api doesn't give error on duplicate IPs
    combined_feeds = list(set(current_ip_feeds + new_ip_feeds))

    client.api_request(
        url_suffix="/feeds/custom/ips",
        method='PUT',
        json_data={"feed": combined_feeds}
    )

    combined_feeds = capitalize_api_response(
        api_response=client.api_request(method='GET', url_suffix="/feeds/custom/ips").get("feed", [])
    )

    return CommandResults(
        readable_output=tableToMarkdown(name="IP Feeds", t={"Feeds": combined_feeds}, headers=["Feeds"])
    )


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

    available_commands_with_args = {
        'prisma-cloud-compute-profile-host-list': get_profile_host_list,
        'prisma-cloud-compute-profile-container-list': get_container_profile_list,
        'prisma-cloud-compute-profile-container-hosts-list': get_container_hosts_list,
        'prisma-cloud-compute-profile-container-forensic-list': get_profile_container_forensic_list,
        'prisma-cloud-compute-host-forensic-list': get_profile_host_forensic_list,
        'prisma-cloud-compute-custom-feeds-ip-add': add_custom_ip_feeds
    }

    available_commands_without_args = {
        'prisma-cloud-compute-console-version-info': get_console_version,
        'prisma-cloud-compute-custom-feeds-ip-list': get_custom_feeds_ip_list
    }

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
        elif requested_command in available_commands_with_args:
            return_results(results=available_commands_with_args[requested_command](client=client, args=demisto.args()))
        elif requested_command in available_commands_without_args:
            return_results(results=available_commands_without_args[requested_command](client=client))

    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {requested_command} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
