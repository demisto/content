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
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self.api_key = api_key

    def get_domains_list(self, suffix: Optional[str], request: Optional[str]):
        if request:
            res = self._http_request('GET', full_url=request)
        else:
            res = self._http_request('GET', f"domains?customerKey={self.api_key}&{suffix}")
        return res

    def delete_domains(self, domain_name, domain_id):
        res = ''
        if domain_id:
            res = self._http_request('DELETE', f"domains/{domain_id}?customerKey={self.api_key}")
        if domain_name:
            res = self._http_request('DELETE', f"domains?customerKey={self.api_key}&where[name]={domain_name}")
        return res

    def add_event_to_domain(self, event):
        return self._http_request('POST', f"events?customerKey={self.api_key}", json_data=event)


def domains_list_suffix(page, limit, request):
    suffix = ''
    if request:
        suffix = request
    if page:
        suffix += f'page={page}&'
    if limit:
        suffix += f'limit={limit}&'
    return suffix


def create_domain_list(client, response):
    full_domains_list = []
    while response:
        response_data = response["data"]
        for domain in response_data:
            full_domains_list.append(domain.get('name'))
        response_next_page = response["meta"]["next"]
        response = client.get_domains_list(response_next_page) if response_next_page else {}
    return full_domains_list


def domains_list_command(client, args):
    page = args.get('page')
    limit = args.get('limit')
    suffix = domains_list_suffix(page=page, limit=limit)
    response = client.get_domains_list(suffix=suffix)
    return create_domain_list(response)


def domain_event_add_command(client, args):
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    alert_time = args.get('alert_time')
    device_id = args.get('device_id')
    dst_domain = args.get('dst_domain')
    dst_url = args.get('dst_url')
    checkStatus = client.get_domains_list()
    if checkStatus == "NotExist":
        status = True

    if checkStatus == "NotExist":

        new_event = {
            "alertTime": alert_time,
            "deviceId": device_id,
            "deviceVersion": "13.7a",  #?????
            "dstDomain": dst_domain,
            "dstUrl": dst_url,
            "eventTime": alert_time,
            "protocolVersion": "1.0a",
            "providerName": "Security Platform"
        }

        response = client.add_event_to_domain(new_event)
        r_code = response.status_code
        if int(r_code) == 202:
            ActionResult = "Success"
            status = True
        else:
            ActionResult = "Failed"
            status = False

        # print("Result :", r2_j)
        # print("Response Code :", r_code)

        human_readable_data = {
            'Domain': str(domain),
            'Action Result Code': r_code,
            'Response :': r2_j['id'],
            'ActionResult': ActionResult
        }

        outputs = {
            'OpenDNSblockDomain': {
                'Domain': str(domain),
                'Action Result Code': r_code,
                'Response :': r2_j['id'],
                'ActionResult': ActionResult
            }
        }

        headers = ['Domain', 'Action Result Code', 'Response', 'ActionResult']
        human_readable = tableToMarkdown('OpenDNSblockDomain info', human_readable_data, headers=headers,
                                         removeNull=True)
        return_outputs(human_readable, outputs, r2_j)
        return status
    else:
        human_readable_data = {
            'Domain': str(domain),
            'Action Result Code': "Already Blocked",
            'Response :': "Already Blocked",
            'ActionResult': "Already Blocked"
        }

        outputs = {
            'OpenDNSblockDomain': {
                'Domain': str(domain),
                'Action Result Code': "Already Blocked",
                'Response :': "Already Blocked",
                'ActionResult': "Already Blocked"
            }
        }

        headers = ['Domain', 'Action Result Code', 'Response', 'ActionResult']
        human_readable = tableToMarkdown('OpenDNSblockDomain info', human_readable_data, headers=headers,
                                         removeNull=True)
        return_outputs(human_readable, outputs)
        return True


def domain_delete_command(client, args):
    domain_name = args.get('name')
    domain_id = args.get('id')
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


def test_module(client):
    try:
        response = client.get_domains_list()
        r_code = response.status_code
        if int(r_code) == 200:
            status = 'ok'
        else:
            status = 'Error'
    except Exception as e:
        LOG(e)
        return_error(e.message)
    return 'ok'


def main():
    params = demisto.params()
    base_url = params.get('url')
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
        client = Client(base_url=base_url, api_key=api_key, verify=verify, proxy=proxy, ok_codes)

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
