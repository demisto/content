import io
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa
import urllib3
from typing import Any

urllib3.disable_warnings()

''' CONSTANTS '''
INTERVAL_FOR_POLLING = 30
TIMEOUT_FOR_POLLING = 600
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

''' CLIENT CLASS '''


class Client(BaseClient):
    def __init__(self, base_url, api_key, tsg_id, client_id, client_secret, verify=True, proxy=False, headers=None):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers=headers)
        self._api_key = api_key
        self._tsg_id = tsg_id
        self._client_id = client_id
        self._client_secret = client_secret
        self._access_token = {}

    def generate_access_token_request(self):
        integration_context = get_integration_context()
        tsg_access_token = f'{self._tsg_id}.access_token'
        tsg_expiry_time = f'{self._tsg_id}.expiry_time'
        previous_token = integration_context.get(tsg_access_token)
        previous_token_expiry_time = integration_context.get(tsg_expiry_time)

        if previous_token and previous_token_expiry_time > date_to_timestamp(datetime.now()):  # type: ignore
            return previous_token
        else:
            data = {
                'grant_type': 'client_credentials',
                'scope': f'tsg_id:{self._tsg_id}'
            }
            try:
                headers = {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Accept': 'application/json',
                }

                res = self._http_request(method='POST',
                                         full_url='https://auth.apps.paloaltonetworks.com/auth/v1/oauth2/access_token',
                                         auth=(self._client_id, self._client_secret),
                                         resp_type='response',
                                         headers=headers,
                                         data=data)
                try:
                    res = res.json()
                except ValueError as exception:
                    raise DemistoException(f'Failed to parse json object from response: {res.text}.\n'
                                           f'Error: {exception}')

                if access_token := res.get('access_token'):
                    expiry_time = date_to_timestamp(datetime.now(), date_format=DATE_FORMAT)
                    expiry_time += res.get('expires_in', 0) - 20
                    new_token = {
                        tsg_access_token: access_token,
                        tsg_expiry_time: expiry_time
                    }
                    # store received token and expiration time in the integration context
                    set_integration_context(new_token)
                    self._access_token = new_token.get(tsg_access_token)
                else:
                    raise DemistoException('Error occurred while creating an access token. Access token field has not'
                                           ' found in the response data. Please check the instance configuration.\n')
            except Exception as e:
                raise DemistoException(f'Error occurred while creating an access token. Please check the instance'
                                       f' configuration.\n\n{e}')

    def get_info_about_device_request(self):
        try:
            headers = {'Content-Type': 'application/xml'}
            params = assign_params(type='op', cmd='<show><system><info></info></system></show>', key=self._api_key)
            response = self._http_request('GET', '/api', params=params, headers=headers, resp_type='xml')
            formated_xml = adjust_xml_format(response.text, 'system')
            return formated_xml
        except DemistoException as e:
            raise DemistoException("Could not get info about device.")

    def get_config_file_request(self):
        headers = {'Content-Type': 'application/xml'}
        params = assign_params(type='config', action='show', key=self._api_key)
        response = self._http_request('GET', '/api', params=params, headers=headers, resp_type='xml')
        formated_xml = adjust_xml_format(response.text, 'config')
        return formated_xml

    def generate_bpa_report_request(self, requester_email, requester_name, system_info):
        body = {
            "requester-email": requester_email,
            "requester-name": requester_name,
            "serial": system_info.get('serial', None),
            "version": system_info.get('sw-version', None),
            "model": system_info.get('model', None),
            "family": system_info.get('family', None)
        }

        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Authorization': f'Bearer {self._access_token}'
        }
        res = self._http_request(method='POST',
                                 full_url='https://api.stratacloud.paloaltonetworks.com/aiops/bpa/v1/requests',
                                 headers=headers,
                                 json_data=body)
        upload_url = res.get('upload-url', None)
        report_id = res.get('id', None)
        if upload_url and report_id:
            return upload_url, report_id
        else:
            raise DemistoException('Response not in format, can not find uploaded-url or report id.')

    def config_file_to_report_request(self, upload_url, config_in_binary):
        headers = {
        'Content-Type': 'application/octet-stream',
        'Accept': '*/*',
        'Authorization': f'Bearer {self._access_token}'
        }
        res = self._http_request(method='PUT',
                            full_url=upload_url,
                            headers=headers,
                            data=config_in_binary,
                            empty_valid_codes=[200],
                            return_empty_response=True)
        return res
    
    def check_upload_status_request(self, report_id):
        headers = {
            'Accept': '*/*',
            'Authorization': f'Bearer {self._access_token}'
        }
        res = self._http_request(method='GET',
                    full_url=f'https://api.stratacloud.paloaltonetworks.com/aiops/bpa/v1/jobs/{report_id}',
                    headers=headers
                    )
        return res.get('status')
    
    def download_bpa_request(self, report_id):
        headers = {
            'Accept': 'application/json',
            'Authorization': f'Bearer {self._access_token}'
        }
        res = self._http_request(method='GET',
            full_url=f'https://api.stratacloud.paloaltonetworks.com/aiops/bpa/v1/reports/{report_id}',
            headers=headers
            )
        return res.get('download-url')
    
    def data_of_download_bpa_request(self, downloaded_BPA_url):
        headers = {
            'Authorization': f'Bearer {self._access_token}'
        }
        res = self._http_request(method='GET',
            full_url=downloaded_BPA_url,
            headers=headers
            )
        return res
    
''' HELPER FUNCTIONS '''

def adjust_xml_format(xml_string, new_root_tag):
    root = ET.fromstring(xml_string)
    sub_tags = root.find(f'.//{new_root_tag}')
    if sub_tags is not None:
        attributes = ' '.join([f'{k}="{v}"' for k, v in sub_tags.attrib.items()])
    new_xml = f"<{new_root_tag} {attributes}>"
    for child in sub_tags:
        new_xml += ET.tostring(child, encoding="unicode")
    new_xml += f"</{new_root_tag}>"
    return new_xml

def get_values_from_xml(xml_string, tags):
    try:
        result = []
        root = ET.fromstring(xml_string)
        for tag in tags:
            result.append(root.find(tag).text)
        return result
    except Exception:
        raise DemistoException("Could not find the required tags from the System file of the configured pan-os/panorama.")

def convert_config_to_bytes(config_file, origin_flag):
    if origin_flag == 'User':
        get_file_path_res = demisto.getFilePath(config_file)
        file_path = get_file_path_res.pop('path')
        file_bytes: bytes = b''
        with open(file_path, 'rb') as f:
            file_bytes = f.read()
        # print(f'{file_bytes=}')
        return file_bytes
    else:
        try:
            # Add tag to xml
            xml_header = '<?xml version="1.0"?>'
            result = f'{xml_header}\n {config_file}'
            # with open("output.xml", 'w') as binary_file:
            #     binary_file.write(result)
            # file_bytes: bytes = b''
            # with open("output.xml", 'rb') as binary_file:
            #     file_bytes = binary_file.read()
            sio_xml = io.StringIO(result)
            xml_in_bytes = sio_xml.read().encode()
            return xml_in_bytes
        except DemistoException as e:
            raise DemistoException(f"Cannot reformat config file with error : {e}")
    
def create_readable_output(response_json):
    dict_to_markdown = []
    headers = ['check_id', 'check_category', 'check_feature', 'check_message', 'check_name', 'check_passed', 'check_type',
               'check_severity']
    check_category_options =['device', 'service_health', 'objects', 'network', 'policies']
    # Get best_practices elements (warnings and notes)
    best_practices= response_json.get('best_practices',{})
    for category in check_category_options:
        category_objects = best_practices.get(category, None)
        for key, value in category_objects.items():
            if value:
                warnings = value[0].get('warnings')
                notes = value[0].get('notes')
                for warning in warnings:
                    warning['check_type'] = 'warning'
                    warning['check_feature'] = key
                    warning['check_category'] = category
                    dict_to_markdown.append(warning)
                for note in notes:
                    note['check_type'] = 'note'
                    note['check_feature'] = key
                    note['check_category'] = category
                    dict_to_markdown.append(note)

    markdown_table = tableToMarkdown('BPA results:', dict_to_markdown,
                           headers=headers, removeNull=True, headerTransform=string_to_table_header
                           )
    
    return markdown_table

''' COMMAND FUNCTIONS '''

def test_module(client: Client) -> str:
    message: str = ''
    try:
        client.generate_access_token_request()
    except DemistoException as e:
        if 'access token' in str(e) or 'Forbidden' in str(e) or 'Authorization' in str(e):
            raise DemistoException("Authorization Error: make sure your tsg_id, client_id, client_secret are correctly set.")
        else:
            raise e
    try:
        client.get_info_about_device_request()
        message = 'ok'
    except Exception as e:
        raise DemistoException ("Authorization Error: make sure your servel_url and API_key are correctly set.")
    return message


def generate_report_command(client: Client, args: dict[str, Any]):
    # Take args out
    config_file_from_user = args.get('entry_id')
    requester_email = args.get('requester_email')
    requester_name = args.get('requester_name')
    global INTERVAL_FOR_POLLING
    INTERVAL_FOR_POLLING = args.get('interval_in_seconds', None) or INTERVAL_FOR_POLLING
    global TIMEOUT_FOR_POLLING
    TIMEOUT_FOR_POLLING = args.get('timeout', None) or TIMEOUT_FOR_POLLING
    
    # Get info about device - system info
    system_info_xml = client.get_info_about_device_request()
    config_file = None
    # Get info configurations
    if not config_file_from_user:
        config_file = client.get_config_file_request()
    
    tags = ['family', 'model', 'serial', 'sw-version']
    xml_tags_values = get_values_from_xml(system_info_xml, tags)
    upload_url, report_id = client.generate_bpa_report_request(requester_email, requester_name, dict(zip(tags, xml_tags_values)))
    if config_file_from_user:
        config_in_binary = convert_config_to_bytes(config_file_from_user, 'User')
    elif config_file:
        config_in_binary = convert_config_to_bytes(config_file, 'Download')
    else:
        raise DemistoException("Can not uplaod a config file since it was not provided.")
    client.config_file_to_report_request(upload_url, config_in_binary)
    return_results(polling_until_upload_report_command({'report_id':report_id}, client))
    
@polling_function(
name="pan-aiops-polling-upload-report",
interval=INTERVAL_FOR_POLLING,
timeout=TIMEOUT_FOR_POLLING,
requires_polling_arg=False,
)
def polling_until_upload_report_command(args: dict[str, Any], client: Client) -> PollResult:
    report_id = args.get('report_id')
    upload_status = client.check_upload_status_request(report_id)
    if upload_status == 'COMPLETED_WITH_SUCCESS':
        downloaded_BPA_url = client.download_bpa_request(report_id)
        downloaded_BPA_json = client.data_of_download_bpa_request(downloaded_BPA_url)
        return PollResult(
                response = CommandResults(
                    readable_output=create_readable_output(downloaded_BPA_json)
            ),
            continue_to_poll=False,
        )
    elif upload_status == 'UPLOAD_INITIATED':
        results = CommandResults(readable_output="Polling job failed.")
        return PollResult(
            response=results,
            continue_to_poll=True,
            args_for_next_run={'report_id':report_id},
            partial_result=CommandResults(
                readable_output=f'The report with id {report_id} was sent successfully. Download in progress...'
                )
        )
    elif upload_status == 'COMPLETED_WITH_ERROR':
        return PollResult(
            response=CommandResults(
                readable_output=f'The report with id {report_id} could not be uploaded- finished with an error.'
                ),
            continue_to_poll=False,
        )
    else:
        results = CommandResults(readable_output="Polling job failed.")
        return PollResult(
            continue_to_poll=True,
            args_for_next_run={'report_id':report_id},
            response=results,
        )
''' MAIN FUNCTION '''

def main() -> None:
    command = demisto.command()
    args = demisto.args()
    params = demisto.params()
    verify_certificate = not params.get('insecure', False)
    base_url = params.get('url')
    api_key = params.get('credentials', {}).get('password')
    tsg_id = params.get('tsg_id')
    client_id = params.get('client_id')
    client_secret = params.get('client_secret', {}).get('password')
    proxy = params.get('proxy', False)

    demisto.debug(f'Command being called is {command}')
    
    try:
        client = Client(
            base_url=base_url,
            api_key=api_key,
            tsg_id=tsg_id,
            client_id=client_id,
            client_secret=client_secret,
            verify=verify_certificate,
            proxy=proxy)
          
        # Generate an access token for pan-OS/panorama
        client.generate_access_token_request()
        
        if command == 'test-module':
            return_results(test_module(client))
        elif command == 'pan-aiops-bpa-report-generate':
            return_results(generate_report_command(client, args))
        elif command == 'pan-aiops-polling-upload-report':
            return_results(polling_until_upload_report_command(args, client))
        else:
            raise NotImplementedError(f"command {command} is not implemented.")
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')

''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
