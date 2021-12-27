import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

''' IMPORTS '''
import json
from ipaddress import IPv4Address

import urllib3
from requests.auth import HTTPDigestAuth

# Disable insecure warnings
urllib3.disable_warnings()
# requests.packages.urllib3.disable_warnings()

''' CONSTANTS '''
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def __init__(self, server: str, verify: bool, proxy: bool, auth: tuple):
        """
        :param server:
        :param proxy:
        :param bearer:
        :param base_url:
        """
        self.base_headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json'}
        auth = HTTPDigestAuth(auth[0], auth[1])
        base_url = urljoin(server, '/api/sonicos')
        # base_url = urljoin(api_url, api_version)  # returns http://example.com/atpapi/v2
        # print(base_url)
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, auth=auth)
        self.server = server
        self.base_url = base_url
        self.verify = verify

    def http_request(self, method: str, url_suffix: str, params: Optional[Dict] = None,
                     data: Union[Dict, str] = None, additional_headers: Optional[Dict] = None,
                     timeout: Any = None, json_data: Any = None):
        headers = {**self.base_headers, **additional_headers} if additional_headers else self.base_headers
        # print(f"Making Request to {urljoin(self.base_url, url_suffix)}")
        # print(f"Providing Header: {headers}")
        if json_data:
            # print(f"Providing Json body: {json_data}")
            return self._http_request(
                method=method,
                url_suffix=url_suffix,
                params=params,
                json_data=data,
                headers=headers,
                timeout=timeout
            )
        else:
            # print(f"Providing Dict body: {data}")
            return self._http_request(
                method=method,
                url_suffix=url_suffix,
                params=params,
                data=data,
                headers=headers,
                timeout=timeout
            )

    def login(self):
        payload = json.dumps({"override": True})
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Accept-Encoding': 'application/json',
            'charset': 'UTF-8'
        }
        suffix = '/auth'
        # config_mode_path = ''
        return self.http_request(method='POST', url_suffix=suffix, additional_headers=headers,
                                 data=payload)

        # self.http_request(method='POST', url_suffix='/address-objects/ipv4', additional_headers=headers,
        #                   json_data=payload)

    def logout(self):
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Accept-Encoding': 'application/json',
            'charset': 'UTF-8'
        }
        suffix = '/auth'
        return self.http_request(method='DELETE', url_suffix=suffix, additional_headers=headers,
                                 data=None)

    def commit_config(self):
        payload = None
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Accept-Encoding': 'application/json',
            'charset': 'UTF-8'
        }
        suffix = '/config/pending'
        return self.http_request(method='POST', url_suffix=suffix, additional_headers=headers,
                                 data=payload)

    def add_ipv4_objects(self, add_object):
        payload = json.dumps(add_object)
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Accept-Encoding': 'application/json',
            'charset': 'UTF-8'
        }
        self.login()
        req = self.http_request(method='POST', url_suffix='/address-objects/ipv4', additional_headers=headers,
                                data=payload)
        return req

    def get_ipv4_objects(self):
        self.login()
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Accept-Encoding': 'application/json',
            'charset': 'UTF-8'
        }
        req = self.http_request(method='GET', url_suffix='/address-objects/ipv4', additional_headers=headers,
                                data=None)
        return req


'''Helper Functions'''


def make_command_results(outputs=None, readable='Empty', raw_output=None, context='DerivcoCerts', key=''):
    if outputs is None:
        outputs = []
    if raw_output is None:
        raw_output = {}
    results = CommandResults(
        outputs_prefix=context,
        outputs=outputs,
        outputs_key_field=key,
        readable_output=readable,
        raw_response=json.dumps(raw_output),
        ignore_auto_extract=True
    )
    return results


def list_to_md(the_list, t_name=None, as_result=False):
    t = {}
    if isinstance(the_list, list):
        t = tableToMarkdown(t=the_list, headers=(the_list[0].keys()),
                            headerTransform=string_to_table_header, name=t_name)
    elif isinstance(the_list, Dict):
        t = tableToMarkdown(t=the_list, headers=(the_list.keys()),
                            headerTransform=string_to_table_header, name=t_name)
    if as_result:
        t = {'ContentsFormat': formats['markdown'], 'Type': entryTypes['note'], 'Contents': t}
    return t


def prepare_dict(the_dict):
    if isinstance(the_dict, Dict):
        return {string_to_context_key(k): v for k, v in the_dict.items()}
    if isinstance(the_dict, list):
        return [prepare_dict(a_dict) for a_dict in the_dict]


def is_ip_multicast(the_ip):
    # low = IPv4Address('224.0.0.0')
    # high = IPv4Address('239.255.255.255')

    test = IPv4Address(str(the_ip).strip())

    if test.is_multicast:
        # print(f'{str(the_ip).strip()} is Multicast')
        return True
    else:
        # print(f'{str(the_ip).strip()} is Unicast')
        if test > IPv4Address('240.0.0.0'):
            return 'invalid'
        return False


def process_objects(obj):
    obj_list = []
    if isinstance(obj, str):
        obj = json.loads(obj)
    if isinstance(obj, Dict):
        obj = [obj]
    for ob in obj:
        # print(obj)
        if str(ob.get('Type')).upper() == 'IP':
            if is_ip_multicast(ob.get('Value')):
                # print('Skipping')
                continue
            if is_ip_multicast(ob.get('Value')) == 'invalid':
                # print('Skipping')
                continue
            else:
                zone = 'WAN'
            add_obj = {
                "ipv4": {
                    "name": ob.get('Name'),
                    "zone": zone,
                    "host": {
                        "ip": ob.get('Value')
                    }
                }
            }
            obj_list.append(add_obj)

    obj_struct = {"address_objects": obj_list}
    return obj_struct


# noinspection DuplicatedCode
def extract_ipv4_objects(ip_objects):
    # print('Start Extraction')
    obj_list = []
    # print(json.dumps(ip_objects.get('address_objects')))
    if isinstance(ip_objects, str):
        ip_objects = json.loads(ip_objects)
        # print(type(ip_objects))
    ip_objects = ip_objects.get('address_objects')
    for obj in ip_objects:
        # print(obj)
        obj = obj.get('ipv4')
        obj_name = obj.get('name')
        # print(f"Type Host: {type(obj.get('host'))}")
        obj_host = obj.get('host')
        if not obj_host:
            continue
        else:
            obj_ip = obj_host.get('ip')
        obj_uuid = obj.get('uuid')
        obj_zone = obj.get('zone')
        new_obj = {'Name': obj_name, 'Value': obj_ip, 'UUID': obj_uuid, 'Zone': obj_zone}
        obj_list.append(new_obj)
    return obj_list


'''Command Functions'''


def add_objects_command(sonic_client: Client, args: Dict):
    obj = args.get('ObjectPairs')
    objects_to_add = process_objects(obj=obj)
    req = sonic_client.add_ipv4_objects(add_object=objects_to_add)
    sonic_client.commit_config()
    # print(comm)
    if str(req.get('status').get('success')).lower() == 'true':
        sonic_client.commit_config()
    sonic_client.logout()
    # print(objects_to_add)
    if len(objects_to_add) <= 0:
        command_results = f'No Objects To Add from {objects_to_add}'
        return command_results
    readable = list_to_md(objects_to_add.get('address_objects')[:10], t_name='Objects Added (Showing 10)')
    if isinstance(obj, Dict):
        obj = [obj]
    command_results = make_command_results(outputs=obj, readable=readable, raw_output=objects_to_add,
                                           context='SonicWall.AddedObjects', key='Value')
    return command_results


def get_address_objects_command(sonic_client: Client, args: Dict):
    req = sonic_client.get_ipv4_objects()
    # print(req)
    ipv4_objects = extract_ipv4_objects(req)
    # print(ipv4_objects)
    sonic_client.logout()
    if req:
        readable = list_to_md(ipv4_objects[:10], t_name='IPV4 Objects (Showing 10)')
        command_results = make_command_results(outputs=ipv4_objects, readable=readable, raw_output=req,
                                               context='SonicWall.IPV4Objects', key='Value')
        return command_results


def test_module(client):
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.

    Args:
        client: HelloWorld client

    Returns:
        'ok' if test passed, anything else will fail the test.
    """

    result = client.login()
    if 'True' == str(result['status']['success']):
        return 'ok'
    else:
        return f"Test failed because \n {result['status']['info']}"


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    username = demisto.params().get('credentials').get('identifier')
    password = demisto.params().get('credentials').get('password')

    # get the service API url
    base_url = demisto.params()['url']
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)
    LOG(f'Command being called is {demisto.command()}')
    try:
        client = Client(
            server=base_url,
            verify=verify_certificate,
            auth=(username, password),
            proxy=proxy)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            demisto.results(result)
        elif demisto.command() == 'sonicwall-add-ipv4-objects':
            args = demisto.args()
            res = add_objects_command(sonic_client=client, args=args)
            return_results(res)
        elif demisto.command() == 'sonicwall-get-ipv4-objects':
            args = {}
            res = get_address_objects_command(sonic_client=client, args=args)
            return_results(res)

    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
