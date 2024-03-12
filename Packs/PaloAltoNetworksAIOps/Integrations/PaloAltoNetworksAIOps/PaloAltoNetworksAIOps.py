import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa
# import xml.etree.ElementTree as ET
import urllib3
from typing import Any

urllib3.disable_warnings()


''' CONSTANTS '''

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

        if previous_token and previous_token_expiry_time > date_to_timestamp(datetime.now()):
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
                    self._access_token = new_token

                else:
                    raise DemistoException('Error occurred while creating an access token. Access token field has not'
                                           ' found in the response data. Please check the instance configuration.\n')

            except Exception as e:
                raise DemistoException(f'Error occurred while creating an access token. Please check the instance'
                                       f' configuration.\n\n{e}')
    
    def get_info_about_device_request(self):
        headers = {'Content-Type': 'application/xml'}
        params = assign_params(type='op', cmd='<show><system><info></info></system></show>', key=self._api_key)
        response = self._http_request('GET', '/api', params=params, headers=headers, resp_type='xml')
        formated_xml = adjust_xml_format(response.text, 'system')
        return formated_xml
    
    def get_config_file_request(self):
        headers = {'Content-Type': 'application/xml'}
        params = assign_params(type='config', action='show', key=self._api_key)
        response = self._http_request('GET', '/api', params=params, headers=headers, resp_type='xml')
        formated_xml = adjust_xml_format(response.text, 'config')
        return formated_xml
        
    def generate_bpa_report_request(self, entry_id, requester_email, requester_name, interval_in_seconds, timeout, system_info):
        access_token = self._access_token.get('tsg_access_token')
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
                'Authorization': f'Bearer {access_token}'
                }
        res = self._http_request(method='POST',
                            full_url='https://api.stratacloud.paloaltonetworks.com/aiops/bpa/v1/requests',
                            auth=(self._client_id, self._client_secret),
                            resp_type='response',
                            headers=headers,
                            data=body)
        try:
            res = res.json()
        except ValueError as exception:
            raise DemistoException(f'Failed to parse json object from response: {res.text}.\n'
                                    f'Error: {exception}')
''' HELPER FUNCTIONS '''

def adjust_xml_format(xml_string, new_root_tag):#TODO
    root = ET.fromstring(xml_string)
    config_children = list(root.find('result').find(new_root_tag))
    new_xml_string = ''.join([ET.tostring(child, encoding='unicode') for child in config_children])
    return f'<{new_root_tag}>{new_xml_string}</{new_root_tag}>'

def get_values_from_xml(xml_string, tags):
    result = []
    root = ET.fromstring(xml_string)
    for tag in tags:
        result.append(root.find(tag).text)
    return result
    
''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    message: str = ''
    try:
        # TODO: ADD HERE some code to test connectivity and authentication to your service.
        # This  should validate all the inputs given in the integration configuration panel,
        # either manually or by using an API that uses them.
        message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):  # TODO: make sure you capture authentication errors
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message


# TODO: REMOVE the following dummy command function
def generate_report_command(client: Client, args: dict[str, Any]):
    client.generate_access_token_request()
    entry_id = args.get('entry_id')
    requester_email = args.get('requester_email')
    requester_name = args.get('requester_name')
    interval_in_seconds = args.get('interval_in_seconds')
    timeout = args.get('timeout')
    system_info_xml = client.get_info_about_device_request()
    if not entry_id:
        config_xml = client.get_config_file_request()
    tags = ['family', 'model', 'serial', 'sw-version']
    xml_tags_values = get_values_from_xml(system_info_xml, tags)
    client.generate_bpa_report_request(entry_id, requester_email, requester_name, interval_in_seconds, timeout, dict(zip(tags,
                                                                                                                         xml_tags_values)))
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

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        headers: dict = {}

        client = Client(
            base_url=base_url,
            api_key=api_key,
            tsg_id=tsg_id,
            client_id=client_id,
            client_secret=client_secret,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)

        generate_report_command(client, args)

        if command == 'test-module':
            result = test_module(client)
            return_results(result)

        elif command == 'pan-aiops-bpa-report-generate':
            return_results(generate_report_command(client, args))
        else:
            raise NotImplementedError(f"command {command} is not implemented.")

    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
