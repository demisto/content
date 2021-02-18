import demistomock as demisto
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]
from CommonServerUserPython import *  # noqa: E402 lgtm [py/polluting-import]

''' IMPORTS '''
import json
import urllib.parse
import httplib2
from oauth2client import service_account
from apiclient import discovery


class GoogleClient:
    """
    A Client class to wrap the google cloud api library.
    """

    def __init__(self, service_name: str, service_version: str, client_secret: str, scopes: list, proxy: bool,
                 insecure: bool, **kwargs):
        """
        :param service_name: The name of the service. You can find this and the service  here
         https://github.com/googleapis/google-api-python-client/blob/master/docs/dyn/index.md
        :param service_version:The version of the API.
        :param client_secret: A string of the credentials.json generated
        :param scopes: The scope needed for the project. Might be different per function.
        (i.e. ['https://www.googleapis.com/auth/cloud-platform'])
        :param proxy:
        :param insecure:
        :param kwargs:
        """
        self.project = kwargs.get('project', '')
        self.region = kwargs.get('region', '-')
        credentials = service_account.ServiceAccountCredentials.from_json_keyfile_dict(client_secret, scopes=scopes)
        if proxy or insecure:
            http_client = credentials.authorize(self.get_http_client_with_proxy(proxy, insecure))
            self.service = discovery.build(service_name, service_version, http=http_client)
        else:
            self.service = discovery.build(service_name, service_version, credentials=credentials)

    # disable-secrets-detection-start
    @staticmethod
    def get_http_client_with_proxy(proxy, insecure):
        """
        Create an http client with proxy with whom to use when using a proxy.
        :param proxy: Whether to use a proxy.
        :param insecure: Whether to disable ssl and use an insecure connection.
        :return:
        """
        if proxy:
            proxies = handle_proxy()
            https_proxy = proxies.get('https')
            http_proxy = proxies.get('http')
            proxy_conf = https_proxy if https_proxy else http_proxy
            # if no proxy_conf - ignore proxy
            if proxy_conf:
                if not proxy_conf.startswith('https') and not proxy_conf.startswith('http'):
                    proxy_conf = 'https://' + proxy_conf
                parsed_proxy = urllib.parse.urlparse(proxy_conf)
                proxy_info = httplib2.ProxyInfo(
                    proxy_type=httplib2.socks.PROXY_TYPE_HTTP,
                    proxy_host=parsed_proxy.hostname,
                    proxy_port=parsed_proxy.port,
                    proxy_user=parsed_proxy.username,
                    proxy_pass=parsed_proxy.password)
                return httplib2.Http(proxy_info=proxy_info, disable_ssl_certificate_validation=insecure)
        return httplib2.Http(disable_ssl_certificate_validation=insecure)

    # disable-secrets-detection-end

    def functions_list(self, region=None, project_id=None):
        if project_id:
            self.project = project_id
        if region:
            self.region = region
        parent = f'projects/{self.project}/locations/{self.region}'
        return self.service.projects().locations().functions().list(parent=parent).execute()

    def region_list(self, project_id):
        if project_id:
            self.project = project_id
        name = f'projects/{self.project}'
        return self.service.projects().locations().list(name=name).execute()

    def function_by_name(self, function_name, region=None, project_id=None):
        if project_id:
            self.project = project_id
        if region:
            self.region = region
        name = f'projects/{self.project}/locations/{self.region}/functions/{function_name}'
        return self.service.projects().locations().functions().get(name=name).execute()

    def execute_function(self, function_name: str, data: str, region, project_id):
        if project_id:
            self.project = project_id
        if region:
            self.region = region
        name = f'projects/{self.project}/locations/{self.region}/functions/{function_name}'
        body = {'data': data}
        return self.service.projects().locations().functions().call(name=name, body=body).execute()


'''COMMAND FUNCTIONS'''


def functions_list_command(client: GoogleClient, args: dict):
    region = client.region
    project_id = client.project
    res = client.functions_list(region, project_id)
    functions = res.get('functions', [])
    if not functions:
        return 'No functions found.', {}, {}
    keys = list(functions[0].keys())
    keys.remove('name')
    disp_region = 'All' if client.region == '-' else client.region
    hr = tableToMarkdown(f'Functions in project "{client.project}" and region "{disp_region}"',
                         functions, ['name'] + keys)
    ec = {'GoogleCloudFunctions.Function(val.name && val.name == obj.name)': functions}
    return hr, ec, res


def region_list_command(client: GoogleClient, args: dict):
    project_id = args.get('project_id')
    res = client.region_list(project_id)
    regions = res.get('locations', [])
    hr = tableToMarkdown(f'Regions in project "{client.project}"', regions, ['locationId', 'name', 'labels'])
    ec = {'GoogleCloudFunctions.Region(val.locationId && val.locationId == obj.locationId)': regions}
    return hr, ec, res


def get_function_by_name_command(client: GoogleClient, args: dict):
    function_name = args.get('function_name', '')
    project_id = args.get('project_id')
    region = args.get('region')
    res = client.function_by_name(function_name, region, project_id)
    keys = list(res.keys())
    keys.remove('name')
    hr = tableToMarkdown(f'Here are the details for {args.get("function_name")}:', res, ['name'] + keys)
    ec = {'GoogleCloudFunctions.Function(val.name && val.name == obj.name)': res}
    return hr, ec, res


def execute_function_command(client: GoogleClient, args: dict):
    project_id = args.get('project_id')
    region = args.get('region')
    function_name = args.get('function_name', '')
    parameters = format_parameters(args.get('parameters', ''))
    res = client.execute_function(function_name, parameters, region, project_id)
    hr = tableToMarkdown(f'Execution details for {args.get("function_name")}:', res)
    ec = {'GoogleCloudFunctions.Execution(val.executionId && val.executionId == obj.executionId)': res}
    return hr, ec, res


'''HELPER FUNCTIONS'''


@logger
def format_parameters(parameters: str) -> str:
    """
    Receives a key:value string and retuns a dictionary string ({"key":"value"}). In the process strips trailing and
    leading spaces.
    :param parameters: The key-value-list
    :return:
    """
    if not parameters:
        return '{}'
    pairs = []
    for item in parameters.split(','):
        try:
            key, value = item.split(':')
        except ValueError:
            raise ValueError(f"Got unexpected parameters {item}.")
        pairs.append((key.strip(), value.strip()))
    return json.dumps(dict(pairs))


def resolve_default_region(region: str):
    # when region is empty, set it to '-' meaning all regions
    # note : demisto.params().get('region','-') did not worked on Demisto
    if not region:
        # from Google API : If you want to list functions in all locations, use "-" in place of a location
        return "-"
    return region


def resolve_default_project_id(project: str, credentials_json: dict):
    if not project:
        # when project_id is empty, get it from credentials_json
        no_project_id_in_credentials = "project_id" not in credentials_json
        if no_project_id_in_credentials:
            # when not provided project id at all, return error
            return_error("Service account private key file contents does not have a project id")
        project = credentials_json["project_id"]
    return project


def main():
    credentials_json = json.loads(demisto.params().get('credentials_json', {}))
    project = demisto.params().get('project_id')
    project = resolve_default_project_id(project, credentials_json)
    region = demisto.params().get('region')
    region = resolve_default_region(region)
    proxy = demisto.params().get('proxy', False)
    insecure = demisto.params().get('insecure', False)
    scopes = ['https://www.googleapis.com/auth/cloud-platform']
    client = GoogleClient('cloudfunctions', 'v1', credentials_json, scopes, proxy, insecure, project=project,
                          region=region)

    commands = {
        'google-cloud-functions-list': functions_list_command,
        'google-cloud-function-regions-list': region_list_command,
        'google-cloud-function-get-by-name': get_function_by_name_command,
        'google-cloud-function-execute': execute_function_command,
    }

    '''EXECUTION CODE'''
    cmd_func = demisto.command()
    LOG(f'Command being called is {cmd_func}')
    try:
        if cmd_func == 'test-module':
            functions_list_command(client, {})
            demisto.results('ok')
        else:
            hr, outputs, raw = commands[cmd_func](client, demisto.args())
            return_outputs(hr, outputs, raw)

    except Exception as e:
        return_error(f"Failed to execute {cmd_func} command. Error: {e}")
        raise


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
