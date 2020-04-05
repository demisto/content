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
    def __init__(self, service_name, service_version, client_secret, proxy, **kwargs):
        self.project = kwargs.get('project', '')
        self.region = kwargs.get('region', '-')
        credentials = service_account.ServiceAccountCredentials.from_json_keyfile_dict(client_secret)
        if proxy:
            http_client = credentials.authorize(self.get_http_client_with_proxy())
            self.service = discovery.build(service_name, service_version, http=http_client)
        else:
            self.service = discovery.build(service_name, service_version, credentials=credentials)

    # disable-secrets-detection-start
    @staticmethod
    def get_http_client_with_proxy():
        proxies = handle_proxy()
        if not proxies or not proxies['https']:
            raise Exception('https proxy value is empty. Check Demisto server configuration')
        https_proxy = proxies['https']
        if not https_proxy.startswith('https') and not https_proxy.startswith('http'):
            https_proxy = 'https://' + https_proxy
        parsed_proxy = urllib.parse.urlparse(https_proxy)
        proxy_info = httplib2.ProxyInfo(
            proxy_type=httplib2.socks.PROXY_TYPE_HTTP,
            proxy_host=parsed_proxy.hostname,
            proxy_port=parsed_proxy.port,
            proxy_user=parsed_proxy.username,
            proxy_pass=parsed_proxy.password)
        return httplib2.Http(proxy_info=proxy_info)

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
    region = args.get('region')
    project_id = args.get('project_id')
    res = client.functions_list(region, project_id)
    functions = res.get('functions', [])
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


def format_parameters(parameters: str) -> str:
    final_s = ''
    for i in parameters.split(','):
        temp = i.strip()
        if len(temp.split(':')) != 2:
            raise ValueError(f"Key:Value pair {i} is not in the correct format.")
        key, value = temp.split(':')
        final_s += key.strip() + ':' + value.strip() + ','
    final_s = final_s[:-1]
    final_s = final_s.replace(',', '","')
    final_s = '{"' + final_s.replace(':', '":"') + '"}'
    return final_s


def main():
    credentials_json = json.loads(demisto.params().get('credentials_json', {}))
    project = demisto.params().get('project_id', '')
    proxy = demisto.params().get('proxy', False)
    region = demisto.params().get('region')
    client = GoogleClient('cloudfunctions', 'v1', credentials_json, proxy, project=project, region=region)
    commands = {
        'google-cloud-functions-list': functions_list_command,
        'google-cloud-function-regions-list': region_list_command,
        'google-cloud-function-get-by-name': get_function_by_name_command,
        'google-cloud-function-execute': execute_function_command
    }

    '''EXECUTION CODE'''
    cmd_func = demisto.command()
    LOG(f'Command being called is {cmd_func}')
    try:
        if cmd_func == 'test-module':
            region_list_command(client, {})
            demisto.results('ok')
            sys.exit(0)
        if not cmd_func:
            raise NotImplementedError(f'Command "{cmd_func}" is not implemented.')
        else:
            hr, outputs, raw = commands[cmd_func](client, demisto.args())
            return_outputs(hr, outputs, raw)

    except Exception as e:
        return_error(f"Failed to execute {cmd_func} command. Error: {e}")
        raise


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

# TODO Check Proxy
