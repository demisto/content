import demistomock as demisto
from CommonServerPython import *

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()


class Client(BaseClient):
    """
    Client to use in the Cisco Umbrella Enforcement integration. Overrides BaseClient
    """

    def __init__(self, base_url, verify, proxy, api_key):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, ok_codes=(200, 202, 204))
        self.api_key = api_key

    def get_domains_list(self, page: str = '', limit: str = '') -> list:
        domains_list: list = []
        response = self.get_domain_request(
            f'{self._base_url}domains?customerKey={self.api_key}&{prepare_suffix(page=page, limit=limit)}')
        limit = int(limit)
        while response and len(domains_list) < limit:
            response_data = response.get('data', [])
            for domain in response_data:
                domain.pop('lastSeenAt')
                domain['IsDeleted'] = False
                domains_list.append(domain)
            response_next_page = response.get('meta', {}).get('next', '')
            if response_next_page:
                response = self.get_domain_request(response_next_page)
            else:
                break
        return domains_list

    def get_domain_request(self, request: str):
        return self._http_request('GET', url_suffix='', full_url=request)

    def delete_domains(self, domain_name: str, domain_id: str):
        url_suffix = f"domains/{domain_id}?customerKey={self.api_key}" if domain_id \
            else f"domains?customerKey={self.api_key}&where[name]={domain_name}"
        return self._http_request('DELETE', url_suffix,
                                  return_empty_response=True)

    def add_event_to_domain(self, event: dict):
        return self._http_request('POST', f"events?customerKey={self.api_key}", json_data=event,
                                  return_empty_response=True)


def prepare_suffix(page: Optional[str] = '', limit: Optional[str] = '') -> str:
    """
    Create the relevant suffix for the domains command,
     Either there is a complete request that should be sent or page and limit arguments.
    :param page: The number of the requested page for domains command.
    :param limit: The limit of the queries to return from the domains command.
    :return: (str) with the suffix.
    """
    suffix = ''
    if page:
        suffix += f'page={page}&'
    if limit:
        suffix += f'limit={limit}&'
    return suffix


def domains_list_command(client: Client, args: dict) -> CommandResults:
    """
    :param client: Cisco Umbrella Client for the api request.
    :param args: args from the user for the command.
    """
    page = args.get('page', '')
    limit = args.get('limit', '')
    response = client.get_domains_list(page=page, limit=limit)
    readable_output = tableToMarkdown(t=response, name='List of Domains', headers=['id', 'name'])
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='UmbrellaEnforcement.Domains',
        outputs_key_field='id',
        outputs=response
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
    destination_ip = args.get('destination_ip')
    event_severity = args.get('event_severity')
    event_type = args.get('event_type')
    event_description = args.get('event_description')
    file_name = args.get('file_name')
    file_hash = args.get('file_hash')
    source = args.get('source')

    new_event = {
        "alertTime": alert_time,
        "deviceId": device_id,
        "deviceVersion": device_version,
        "dstDomain": dst_domain,
        "dstUrl": dst_url,
        "eventTime": alert_time,
        "protocolVersion": "1.0a",
        "providerName": "Security Platform",
        "dstIP": destination_ip,
        "eventSeverity": event_severity,
        "eventType": event_type,
        "eventDescription": event_description,
        "fileName": file_name,
        "fileHash": file_hash,
        "src": source
    }

    response: dict = client.add_event_to_domain(new_event)
    if id := str(response.get('id')):
        action_result = f"New event was added successfully, The Event id is {id}."
    else:
        action_result = "New event's addition failed."
    return action_result


def domain_delete_command(client: Client, args: dict) -> CommandResults:
    """
    :param client: Cisco Umbrella Client for the api request.
    :param args: args from the user for the command.
    :returns (str) confirmation or error regarding deleting a domain.
    """
    response = {}
    domain_name = args.get('name', '')
    domain_id = args.get('id', '')
    if not domain_name and not domain_id:
        raise DemistoException(
            'Both domain name and domain id do not exist, Please supply one of them in order to set the domain to '
            'delete command')
    try:
        response = client.delete_domains(domain_id=domain_id, domain_name=domain_name)
    except Exception as e:
        # When deleting a domain by id and the id does not exist.
        if any(exp in str(e) for exp in ["Domain not in domain list", "Not Found"]):
            return CommandResults(
                readable_output='The domain was not found in the list, Please insert an existing domain name or id.'
            )
    if domain_name:
        curr_context = demisto.dt(demisto.context(), f'UmbrellaEnforcement.Domains(val.name == "{domain_name}")')
    else:
        curr_context = demisto.dt(demisto.context(), f'UmbrellaEnforcement.Domains(val.id == "{domain_id}")')

    if curr_context:
        if isinstance(curr_context, list):
            curr_context = curr_context[0]
        curr_context['IsDeleted'] = True
    if response and int(response.status_code) == 204:  # type: ignore
        message = f"{domain_name if domain_name else domain_id} domain was removed from blacklist"
    else:
        # When deleting a domain by name, if name does not exist the returned code is 200 but the response is empty.
        message = f"{domain_name if domain_name else domain_id} domain not in the blacklist or Error"
    return CommandResults(
        readable_output=message,
        outputs_prefix='UmbrellaEnforcement.Domains',
        outputs_key_field='id',
        outputs=curr_context
    )


def test_module(client: Client) -> str:
    """
    :param client: Cisco Umbrella Client for the api request.
    :return: 'ok' if there is a connection with the api and exception otherwise.
    """
    client.get_domains_list(limit='1', page='1')
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
