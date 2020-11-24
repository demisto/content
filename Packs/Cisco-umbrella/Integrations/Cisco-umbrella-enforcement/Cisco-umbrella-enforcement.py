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

    def get_domains_list(self, request: Optional[str]):
        if request:
            res = self._http_request('GET', full_url=request)
        else:
            res = self._http_request('GET', f"domains?customerKey={self.api_key}")
        return res

    def delete_domains(self, domain):
        return self._http_request('POST', f"domains?customerKey={self.api_key}&where[name]={domain}")

    def add_event_to_domain(self, event):
        return self._http_request('POST', f"events?customerKey={self.api_key}", json_data=event)


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
    response = client.get_domains_list()
    return create_domain_list(response)


def domain_event_add_command(client, args):
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    domain = args.get('domain')
    checkStatus = client.get_domains_list()
    if checkStatus == "NotExist":
        status = True

    if checkStatus == "NotExist":

        myobj = {
            "alertTime": "2020-01-13T11:14:26.0Z",
            "deviceId": "ba6a59f4-e692-4724-ba36-c28132c761de",
            "deviceVersion": "13.7a",
            "dstDomain": str(domain),
            "dstUrl": "http://" + str(domain) + "/a-bad-url",
            "eventTime": "2020-01-13T13:30:26.0Z",
            "protocolVersion": "1.0a",
            "providerName": "Security Platform"
        }

        r2 = requests.post(myEventsrequest, json=myobj, verify=False)
        r2_j = r2.json()
        r_code = r2.status_code
        # r_code ==>
        # 202 Accepted—Everything worked as expected.
        # 400 Bad Request—Likely missing a required parameter or malformed JSON. Please check the syntax on your query.
        # 403 Unauthorized—Request had Authorization header but token was missing or invalid. Please ensure your API token is valid.
        # 404 Not Found—The requested item doesn't exist, check the syntax of your query or ensure the IP and/or domain are valid. If deleting a domain, ensure the id is correct.
        # 500, 502, 503, 504 Server errors—Something went wrong on our end.
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
    domain = args.get('domain')
    response = client.delete_domain(domain)
    if int(response.status_code) == 204:
        message = f"{domain} Domain was removed from blacklist"
    else:
        message = f"{domain} Not in the blacklist or Error"
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
