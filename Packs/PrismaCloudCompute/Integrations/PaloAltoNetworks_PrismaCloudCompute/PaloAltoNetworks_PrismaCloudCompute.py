import demistomock as demisto
from CommonServerPython import *

''' IMPORTS '''
import requests
import tempfile

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
    """
    def wrapper(*args, **kwargs):

        api_limit_call = 50

        command_args = kwargs.get('args')
        offset = arg_to_number(arg=command_args.get('offset'), arg_name='offset')
        if offset < 0:
            offset = 0
        command_args['offset'] = offset

        limit = arg_to_number(arg=command_args.get('limit'), arg_name='limit')
        if limit - offset > api_limit_call:
            limit = offset + api_limit_call
        command_args['limit'] = limit

        return func(*args, **kwargs)

    return wrapper


def get_api_info(
    client: PrismaCloudComputeClient, url_suffix: str, args: dict = None, method: str = 'GET'
):
    """
    Get api information from the PrismaCloudCompute client.

    Args:
        client (PrismaCloudComputeClient): prisma-cloud-compute client.
        method (str): the api method type. e.g.: 'GET,POST,PUT'
        url_suffix (str): url suffix of the base api url.
        args (dict): any command arguments if exist.

    Returns:
        list: api response.
    """
    return client.api_request(method=method, url_suffix=url_suffix, params=assign_params(**args))


def build_profile_host_table_response(full_response: List[dict]) -> str:
    """
    Build a table from the api response of the profile host
    list for the command 'prisma-cloud-compute-profile-host-list'

    Args:
        full_response (list[dict]): the api raw response.

    Returns:
        str: markdown table output for the apps and ssh events of a host.
    """
    apps_table = []
    ssh_events_table = []

    for response in full_response:
        for app in response.get('apps', []):
            apps_table.append(
                {
                    'HostId': response.get('_id'),
                    'AppName': app.get('name'),
                    'StartupProcess': app.get('startupProcess').get('path'),
                    'User': app.get('startupProcess').get('user'),
                    'LaunchTime': app.get('startupProcess').get('time'),
                }
            )
        for event in response.get('sshEvents'):
            ssh_events_table.append(
                {
                    'HostId': response.get('_id'),
                    'User': event.get('user'),
                    'Ip': event.get('ip'),
                    'ProcessPath': event.get('path'),
                    'Command': event.get('command'),
                    'Time': event.get('time'),
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
    full_response = get_api_info(client=client, args=args, url_suffix='/profiles/host')

    return CommandResults(
        outputs_prefix='prismaCloudCompute.profileHost',
        outputs_key_field='_id',
        outputs=full_response,
        readable_output=build_profile_host_table_response(full_response=full_response)
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

    available_commands = {
        'prisma-cloud-compute-profile-host-list': get_profile_host_list,
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
        elif requested_command in available_commands:
            return_results(results=available_commands[requested_command](client=client, args=demisto.args()))

    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {requested_command} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
