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
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, ok_codes=(200, 202, 204))
        self.api_key = api_key

    def get_domains_list(self, suffix: Optional[str] = '', request: Optional[str] = ''):
        if request:
            res = self._http_request('GET', full_url=request)
        else:
            res = self._http_request('GET', url_suffix=f"domains?customerKey={self.api_key}&{suffix}")
        return res

    def delete_domains(self, domain_name: str, domain_id: str):
        res = ''
        try:
            if domain_id:
                res = self._http_request('DELETE', f"domains/{domain_id}?customerKey={self.api_key}",
                                         return_empty_response=True)
            if domain_name:
                res = self._http_request('DELETE', f"domains?customerKey={self.api_key}&where[name]={domain_name}",
                                         return_empty_response=True)
        except Exception as e:
            if e.res.status_code == 400:
                raise DemistoException('Domain for delete command does not exist, Please insert an existing domain '
                                       'name or id.')
            if e.res.status_code ==401

        return res

    def add_event_to_domain(self, event: dict):
        return self._http_request('POST', f"events?customerKey={self.api_key}", json_data=event,
                                  return_empty_response=True)


def prepare_suffix(page: Optional[str] = '', limit: Optional[str] = '', request: Optional[str] = '') -> str:
    """
    Create the relevant suffix for the domains command,
     Either there is a complete request that should be sent or page and limit arguments.
    :param page: The number of the requested page for domains command.
    :param limit: The limit of the queries to return from the domains command.
    :param request: Full request to send to API, Used when running the domains list command and there is a large number
                    of queries which are then returned with paging and have a next page request built already.
    :return: (str) with the suffix.
    """
    suffix = ''
    if request:
        suffix = request
    if page:
        suffix += f'page={page}&'
    if limit:
        suffix += f'limit={limit}&'
    return suffix


def create_domain_list(client: Client, response: dict) -> list:
    """
    :param client: Cisco Umbrella Client for the api request.
    :param response: the first response of the domains api call.
    :return: list of all of the domains from the api.
    """
    full_domains_list = []
    while response:
        response_data = response.get('data', [])
        for domain in response_data:
            full_domains_list.append(domain.get('name'))
        response_next_page = response.get('meta', {}).get('next', '')
        response = client.get_domains_list(response_next_page) if response_next_page else {}
    return full_domains_list


def domains_list_command(client: Client, args: dict) -> CommandResults:
    """
    :param client: Cisco Umbrella Client for the api request.
    :param args: args from the user for the command.
    """
    page = args.get('page', '')
    limit = args.get('limit', '')
    suffix = prepare_suffix(page=page, limit=limit)
    response = client.get_domains_list(suffix=suffix)
    domains_list = create_domain_list(client, response)
    domains_list = domains_list[:int(limit)]
    readable_output = tableToMarkdown(t=domains_list, name='List of Domains', headers=['Domain'])
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='CiscoUmbrellaEnforcement.Domains',
        outputs_key_field='Domains',
        outputs=domains_list
    )


def domain_event_add_command(client: Client, args: dict) -> str:
    """
    :param client: Cisco Umbrella Client for the api request.
    :param args: args from the user for the command.
    :returns (str) confirmation or error regarding adding a new domain.
    """
    alert_time = args.get('alert_time')
    device_id = args.get('device_id')
    dst_domain = args.get('destination_domain')
    dst_url = args.get('destination_url')
    device_version = args.get('device_version')

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
    if response.get('id'):
        action_result = f"New event was added successfully, The id is {str(response.get('id'))}."
    else:
        action_result = "New event's addition failed."
    return action_result


def domain_delete_command(client: Client, args: dict) -> str:
    """
    :param client: Cisco Umbrella Client for the api request.
    :param args: args from the user for the command.
    :returns (str) confirmation or error regarding deleting a domain.
    """
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
    """
    :param client: Cisco Umbrella Client for the api request.
    :return: 'ok' if there is a connection with the api and exception otherwise.
    """
    client.get_domains_list(prepare_suffix())
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
