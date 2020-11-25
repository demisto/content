from typing import Dict, Union

import demistomock as demisto
from CommonServerPython import *

''' IMPORTS '''

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()


class Client(BaseClient):
    """
    Client to use in the Cisco Umbrella Enforcement integration. Overrides BaseClient
    """

    def __init__(self, base_url, verify, proxy, api_key):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, ok_codes=(200, 202))
        self.api_key = api_key

    def get_domains_list(self, suffix: Optional[str] = '', request: Optional[str] = ''):
        if request:
            res = self._http_request('GET', full_url=request)
        else:
            res = self._http_request('GET', f"domains?customerKey={self.api_key}&{suffix}")
        return res

    def delete_domains(self, domain_name: str, domain_id: str):
        res = ''
        if domain_id:
            res = self._http_request('DELETE', f"domains/{domain_id}?customerKey={self.api_key}")
        if domain_name:
            res = self._http_request('DELETE', f"domains?customerKey={self.api_key}&where[name]={domain_name}")
        return res

    def add_event_to_domain(self, event: dict):
        return self._http_request('POST', f"events?customerKey={self.api_key}", json_data=event)


def domains_list_suffix(page: Optional[str] = '', limit: Optional[str] = '', request: Optional[str] = '') -> str:
    suffix = ''
    if request:
        suffix = request
    if page:
        suffix += f'page={page}&'
    if limit:
        suffix += f'limit={limit}&'
    return suffix


def create_domain_list(client: Client, response: Dict[str, Union[dict, list]]) -> list:
    full_domains_list = []
    while response:
        response_data = response.get('data', [])
        for domain in response_data:
            full_domains_list.append(domain.get('name'))
        response_next_page = response.get('meta', {}).get('next', '')
        response = client.get_domains_list(response_next_page) if response_next_page else {}
    return full_domains_list


def domains_list_command(client: Client, args: dict) -> CommandResults:
    page = args.get('page')
    limit = args.get('limit')
    suffix = domains_list_suffix(page=page, limit=limit)
    response = client.get_domains_list(suffix=suffix)
    domains_list = create_domain_list(client, response)
    readable_output = f'## {domains_list}'
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='CiscoUmbrellaEnforcement.Domains',
        outputs_key_field='',
        outputs=domains_list
    )


def domain_event_add_command(client: Client, args: dict) -> str:
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    alert_time = args.get('alert_time')
    device_id = args.get('device_id')
    dst_domain = args.get('dst_domain')
    dst_url = args.get('dst_url')
    device_version = args.get('device_version')

    # checkStatus = client.get_domains_list()
    # if checkStatus == "NotExist":
    #     status = True
    #
    # if checkStatus == "NotExist":

    new_event = {
        "alertTime": alert_time,
        "deviceId": device_id,
        "deviceVersion": device_version,
        "dstDomain": dst_domain,
        "dstUrl": dst_url,
        "eventTime": alert_time,
        "protocolVersion": "1.0a",
        "providerName": "Security Platform"
    }

    response = client.add_event_to_domain(new_event)
    r_code = response.status_code
    if int(r_code) == 202:
        ActionResult = "New event was added successfully."
    else:
        ActionResult = "New event's addition failed."
    return ActionResult


def domain_delete_command(client: Client, args: dict) -> str:
    domain_name = args.get('name', '')
    domain_id = args.get('id', '')
    if not domain_name and not domain_id:
        raise DemistoException(
            'Both domain name and domain id do not exist, Please supply one of them in order to set the domain to '
            'delete command')
    response = client.delete_domains(domain_id=domain_id, domain_name=domain_name)
    if int(response.status_code) == 204:
        message = f"{domain_name if domain_name else domain_id} Domain was removed from blacklist"
    else:
        message = f"{domain_name if domain_name else domain_id} Domain not in the blacklist or Error"
    return message


def test_module(client: Client) -> str:
    response = client.get_domains_list(domains_list_suffix())
    if int(response.status_code) != 200:
        raise DemistoException('test failed')
    return 'ok'


def main():
    params = demisto.params()
    base_url = f"{params.get('url')}/1.0/"
    api_key = params.get('api_key')
    verify = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    command = demisto.command()

    commands = {
        'umbrella-domain-event-add': domain_event_add_command,
        'umbrella-domains-list': domains_list_command,
        'umbrella-domain-delete': domain_delete_command,
    }

    try:
        client = Client(base_url=base_url, api_key=api_key, verify=verify, proxy=proxy)

        if command == 'test-module':
            return_results(test_module(client))

        elif command in commands:
            return_results(commands[command](client, demisto.args()))

        else:
            raise NotImplementedError(f'Command "{command}" is not implemented.')

    except Exception as e:
        return_error(str(e))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
