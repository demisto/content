import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''
import urllib3
import jwt
import base64
import hashlib
import time
import json

# Disable insecure warnings
urllib3.disable_warnings()
''' CLIENT CLASS'''

USDOAPIPATH = '/WebApp/api/SuspiciousObjects/UserDefinedSO'
PRODAGENTAPIPATH = '/WebApp/API/AgentResource/ProductAgents'


class Client(BaseClient):
    def __init__(self, base_url, api_key, app_id, verify, proxy):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self.base_url = base_url
        self.api_key = api_key
        self.application_id = app_id

    @staticmethod
    def __create_checksum(http_method, api_path, headers, request_body):
        string_to_hash = http_method.upper() + '|' + api_path.lower() + '|' + headers + '|' + request_body
        base64_string = base64.b64encode(hashlib.sha256(str.encode(string_to_hash)).digest()).decode('utf-8')
        return base64_string

    def __create_jwt_token(self, http_method, api_path, headers, request_body, iat=time.time(), algorithm='HS256',
                           version='V1', ):
        checksum = self.__create_checksum(http_method, api_path, headers, request_body)

        payload = {'appid': self.application_id,
                   'iat': iat,
                   'version': version,
                   'checksum': checksum}
        token = jwt.encode(payload, self.api_key, algorithm=algorithm).decode('utf-8')
        return token

    def usdo_list(self, list_type="", contentfilter=""):
        querystring = "?type=" + list_type + "&contentFilter=" + contentfilter
        headers = {
            'Authorization': 'Bearer ' + self.__create_jwt_token(http_method='GET', api_path=USDOAPIPATH + querystring,
                                                                 headers='', request_body='')}
        response = (
            self._http_request("GET", USDOAPIPATH, full_url=self.base_url + USDOAPIPATH + querystring, headers=headers))
        return response

    def usdo_delete(self, list_type="", content=""):
        querystring = "?type=" + list_type + "&content=" + content
        headers = {'Authorization': 'Bearer ' + self.__create_jwt_token(http_method='DELETE',
                                                                        api_path=USDOAPIPATH + querystring, headers='',
                                                                        request_body='')}
        response = (self._http_request("DELETE", USDOAPIPATH, full_url=self.base_url + USDOAPIPATH + querystring,
                                       headers=headers))
        return response

    def usdo_add(self, add_type=None, content=None, scan_action=None, notes='', expiration=''):
        if add_type and content and scan_action:
            req_body = {
                "param": {
                    "type": add_type,
                    "content": content,
                    "notes": notes,
                    "scan_action": scan_action,
                    "expiration_utc_date": expiration
                }
            }

            headers = {
                'Content-Type': 'application/json;charset=utf-8',
                'Authorization': 'Bearer ' + self.__create_jwt_token(http_method='PUT', api_path=USDOAPIPATH + '/',
                                                                     headers='', request_body=json.dumps(req_body))}
            response = (self._http_request("PUT", USDOAPIPATH + '/', full_url=self.base_url + USDOAPIPATH + '/',
                                           headers=headers, data=json.dumps(req_body)))

            return response

    def _prodagent_command(self, action, multi_match=False, entity_id="", ip_add="", mac_add="", host="", prod=""):
        act = action

        req_body = {
            "act": act,
            "allow_multiple_match": multi_match,
            "entity_id": entity_id,
            "ip_address": ip_add,
            "mac_address": mac_add,
            "host_name": host,
            "product": prod
        }

        headers = {
            'Content-Type': 'application/json;charset=utf-8',
            'Authorization': 'Bearer ' + self.__create_jwt_token(http_method='POST', api_path=PRODAGENTAPIPATH + '/',
                                                                 headers='', request_body=json.dumps(req_body))}
        response = (
            self._http_request("POST", PRODAGENTAPIPATH + '/', full_url=self.base_url + PRODAGENTAPIPATH + '/',
                               headers=headers,
                               data=json.dumps(req_body)))
        if response.get('result_code') != 1:
            err_msg = f'Operation failed - {response.get("result_description", "")}'
            raise ValueError(err_msg)
        return response

    def prodagent_isolate(self, multi_match=False, entity_id="", ip_add="", mac_add="", host="", prod=""):
        action = "cmd_isolate_agent"
        return self._prodagent_command(action, multi_match, entity_id, ip_add, mac_add, host, prod)

    def prodagent_restore(self, multi_match=False, entity_id="", ip_add="", mac_add="", host="", prod=""):
        action = "cmd_restore_isolated_agent"
        return self._prodagent_command(action, multi_match, entity_id, ip_add, mac_add, host, prod)


''' COMMANDS + REQUESTS FUNCTIONS '''


def test_module(client: Client, *_):
    """
    Performs basic get request to get item samples
    """
    client.usdo_list()
    return 'ok', None, None


def usdo_list_command(client: Client, args):
    list_type = args.get('type', '')
    content_filter = args.get('content_filter', '')

    response = client.usdo_list(list_type, content_filter)

    data = response.get('Data')

    return (tableToMarkdown("Apex USDO List", data),
            {"TrendMicroApex.USDO": data}, response)


def usdo_delete_command(client: Client, args):
    list_type = args.get('type', '')
    content = args.get('content', '')

    response = client.usdo_delete(list_type, content)

    return f'USDO {content} of type {list_type} was deleted successfully', None, response


def usdo_add_command(client: Client, args):
    add_type = args.get('type')
    content = args.get('content')
    scan_action = args.get('scan_action')

    response = client.usdo_add(add_type=add_type, content=content, scan_action=scan_action)

    return f'USDO {content} of type {add_type} was added successfully with scan action {scan_action}', None, response


def prodagent_isolate_command(client: Client, args):
    multi_match = args.get('multi_match', 'true') == 'true'
    entity_id = args.get('entity_id')
    ip = args.get('ip_address')
    mac = args.get('mac_address')
    host = args.get('host_name')
    product = args.get('product')

    if not any([entity_id, ip, mac, host, product]):
        raise ValueError('At least one of the following arguments must be provided: '
                         'entity_id, ip_address, mac_address, host_name, product')

    response = client.prodagent_isolate(multi_match=multi_match, entity_id=entity_id, ip_add=ip, mac_add=mac, host=host,
                                        prod=product)
    result_content = response.get('result_content', [])
    if result_content:
        return (tableToMarkdown("Apex ProductAgent Isolate", result_content),
                {"TrendMicroApex.ProductAgent": result_content}, response)
    else:
        return 'No agents were affected.', None, None


def prodagent_restore_command(client: Client, args):
    multi_match = args.get('multi_match', 'true') == 'true'
    entity_id = args.get('entity_id')
    ip = args.get('ip_address')
    mac = args.get('mac_address')
    host = args.get('host_name')
    product = args.get('product')

    if not any([entity_id, ip, mac, host, product]):
        raise ValueError('At least one of the following arguments must be provided: '
                         'entity_id, ip_address, mac_address, host_name, product')

    response = client.prodagent_restore(multi_match=multi_match, entity_id=entity_id, ip_add=ip, mac_add=mac, host=host,
                                        prod=product)
    result_content = response.get('result_content', [])
    if result_content:
        return (tableToMarkdown("Apex ProductAgent Restore", result_content),
                {"TrendMicroApex.ProductAgent": result_content}, response)
    else:
        return 'No agents were affected.', None, None


''' COMMANDS MANAGER / SWITCH PANEL '''


def main():
    """ GLOBALS/PARAMS """

    params = demisto.params()

    api_key = params.get('token')
    app_id = params.get('application_id')

    base_url = urljoin(params['url'], '')
    verify = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    client = Client(base_url, api_key, app_id, verify=verify, proxy=proxy)
    command = demisto.command()
    LOG(f'Command being called is {command}')

    commands = {
        'test-module': test_module,
        'trendmicro-apex-usdo-list': usdo_list_command,
        'trendmicro-apex-usdo-add': usdo_add_command,
        'trendmicro-apex-usdo-delete': usdo_delete_command,
        'trendmicro-apex-isolate': prodagent_isolate_command,
        'trendmicro-apex-restore': prodagent_restore_command
    }
    try:
        if command in commands:
            return_outputs(*commands[command](client, demisto.args()))  # type: ignore
    except ValueError as e:
        return_error(f'Error from TrendMicro Apex integration: {str(e)}', e)


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
