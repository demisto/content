import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

''' IMPORTS '''


import base64
import json
import traceback

''' CLIENT CLASS '''


class Client(BaseClient):
    def __init__(self, base_url, *args, **kwarg):
        super().__init__(base_url, *args, **kwarg)

    def get_destination_lists(self, organizationId):
        uri = f'{organizationId}/destinationlists'
        return self._http_request('GET', uri)

    def get_destinations(self, organizationId, destinationListId, params=None):
        uri = f'/{organizationId}/destinationlists/{destinationListId}/destinations'
        return self._http_request('GET', uri, params=params)

    def add_domain(self, organizationId, destinationListId, data):
        uri = f'{organizationId}/destinationlists/{destinationListId}/destinations'
        return self._http_request('POST', uri, data=data)

    def remove_domain(self, organizationId, destinationListId, data):
        # https://docs.umbrella.com/umbrella-api/reference#delete_v1-organizations-organizationid-destinationlists-destinationlistid-destinations-remove
        uri = f'{organizationId}/destinationlists/{destinationListId}/destinations/remove'
        return self._http_request('DELETE', uri, data=data)


''' HELPER FUNCTIONS '''


def get_first_page_of_destinations(client, organizationId, destinationListId):
    page_limit = 100
    page = 1
    r = client.get_destinations(organizationId, destinationListId, params={'page': page, 'limit': page_limit})

    return page_limit, page, r


def get_destination_domains(client, organizationId, destinationListId):
    page_limit, page, r = get_first_page_of_destinations(client, organizationId, destinationListId)

    destination_domains = []
    while r.get('meta').get('total') <= page_limit:
        if r.get('meta').get('total') == 0:
            # currently, r.meta.total continually returns 100 until the last page, where it will return a value <= 100
            # and will never return 0. but if it does, then it's likely the API changed
            uri = f'/{organizationId}/destinationlists/{destinationListId}/destinations'
            demisto.info(f'Unexpected "total" value of 0 returned from Umbrella {uri} API call')
            break
        destination_domains += r.get('data')
        page += 1
        r = client.get_destinations(organizationId, destinationListId, params={'page': page, 'limit': page_limit})

    return destination_domains


def get_destination_domain(client, organizationId, destinationListId, domain):
    demisto.debug(f'domain: {domain}')
    page_limit, page, r = get_first_page_of_destinations(client, organizationId, destinationListId)

    destination_domain = None
    while r.get('meta').get('total') <= page_limit and not destination_domain:
        if r.get('meta').get('total') == 0:
            # currently, r.meta.total continually returns 100 until the last page, where it will return a value <= 100
            # and will never return 0. but if it does, then it's likely the API changed
            uri = f'/{organizationId}/destinationlists/{destinationListId}/destinations'
            demisto.info(f'Unexpected "total" value of 0 returned from Umbrella {uri} API call')
            break
        for d in r.get('data'):
            if d.get('destination') == domain:
                destination_domain = d
                break
        page += 1
        r = client.get_destinations(organizationId, destinationListId, params={'page': page, 'limit': page_limit})

    return destination_domain


def search_destination_domains(client, organizationId, destinationListId, domains):
    demisto.debug(f'domains: {domains}')
    page_limit, page, r = get_first_page_of_destinations(client, organizationId, destinationListId)

    destination_domains = []
    while r.get('meta').get('total') <= page_limit:
        if r.get('meta').get('total') == 0:
            # currently, r.meta.total continually returns 100 until the last page, where it will return a value <= 100
            # and will never return 0. but if it does, then it's likely the API changed
            uri = f'/{organizationId}/destinationlists/{destinationListId}/destinations'
            demisto.info(f'Unexpected "total" value of 0 returned from Umbrella {uri} API call')
            break
        destination_domains += r.get('data')
        page += 1
        r = client.get_destinations(organizationId, destinationListId, params={'page': page, 'limit': page_limit})

    destination_domains_found = []
    for domain in domains:
        if domain in demisto.dt(destination_domains, 'destination'):
            destination_domains_found += [d for d in destination_domains if d.get('destination') == domain]
            demisto.debug(f'destination_domains_found: {destination_domains_found}')

    return destination_domains_found


''' COMMAND FUNCTIONS '''


def test_module(client: Client, **args) -> str:
    organizationId = args.get('orgId')

    if not organizationId:
        return "organizationId not provided"

    uri = f'/{organizationId}/destinationlists'

    client._http_request('GET', uri)

    return "ok"


def get_destination_lists_command(client: Client, **args) -> CommandResults:
    r = client.get_destination_lists(args.get('orgId'))

    data = []
    for destination_list in r['data']:
        data.append(
            {
                'name': destination_list['name'],
                'id': destination_list['id']
            }
        )

    return CommandResults(
        outputs_prefix="Umbrella.DestinationLists",
        outputs_key_field="id",
        outputs=data
    )


def add_domain_command(client: Client, **args) -> str:
    destinations = argToList(args.get('domains'))
    comment = args.get('comment')

    # max allowable limit of destinations to send in one request is 500
    limit = 500
    if len(destinations) > limit:
        destinations_remaining = destinations
        while destinations_remaining:
            demisto.debug(f'length of destinations_remaining: {len(destinations_remaining)}')
            destinations_limited = destinations_remaining[0:limit]
            payload = json.dumps([{'destination': destination, 'comment': comment} for destination in destinations_limited])
            r = client.add_domain(args.get('orgId'), args.get('destId'), data=payload)
            # TODO: if one request fails, then return the successful, failed and remaining requests
            destinations_remaining = destinations_remaining[limit:]
    else:
        payload = json.dumps([{'destination': destination, 'comment': comment} for destination in destinations])
        r = client.add_domain(args.get('orgId'), args.get('destId'), data=payload)

    return f'Domain {", ".join(destinations)} successfully added to list {r["data"]["name"]}'


def remove_domain_command(client: Client, **args) -> str:
    destinations = argToList(args.get('domainIds'))
    payload = "[" + ", ".join(destinations) + "]"

    r = client.remove_domain(args.get('orgId'), args.get('destId'), data=payload)

    return f'Domain {", ".join(destinations)} successfully removed from list {r["data"]["name"]}'


def get_destination_domains_command(client: Client, **args) -> CommandResults:
    destination_domains = get_destination_domains(client, args.get('orgId'), args.get('destId'))

    return CommandResults(
        outputs_prefix="Umbrella.Destinations",
        outputs_key_field="id",
        outputs=destination_domains,
        readable_output=tableToMarkdown('Domains in Destination List', destination_domains)
    )


def get_destination_domain_command(client: Client, **args) -> CommandResults:
    destination_domain = get_destination_domain(client, args.get('orgId'), args.get('destId'), args.get('domain'))

    return CommandResults(
        outputs_prefix="Umbrella.Destinations",
        outputs_key_field="id",
        outputs=destination_domain,
        readable_output=tableToMarkdown('Domain in Destination List', destination_domain)
    )


def search_destination_domains_command(client: Client, **args) -> CommandResults:
    domains = argToList(args.get('domains'))
    destination_domains = search_destination_domains(client, args.get('orgId'), args.get('destId'), domains)

    return CommandResults(
        outputs_prefix="Umbrella.Destinations",
        outputs_key_field="id",
        outputs=destination_domains,
        readable_output=tableToMarkdown('Domains in Destination List', destination_domains)
    )


def main():
    # If an arg supplying an orgId is provided, will override the one found in params
    args = {**demisto.params(), **demisto.args()}

    base_url = 'https://management.api.umbrella.com/v1/organizations'
    api_key = base64.b64encode(f'{demisto.getParam("apiKey")}:{demisto.getParam("apiSecret")}'.encode("ascii"))
    verify = not args.get('insecure', False)
    proxy = args.get('proxy', False)

    headers = {
        'Accept': "application/json",
        'Content-Type': "application/json",
        'Authorization': f'Basic {api_key.decode("ascii")}'
    }

    try:
        client = Client(
            base_url,
            verify=verify,
            headers=headers,
            proxy=proxy
        )

        commands = {
            'umbrella-get-destination-lists': get_destination_lists_command,
            'umbrella-add-domain': add_domain_command,
            'umbrella-remove-domain': remove_domain_command,
            'umbrella-get-destination-domains': get_destination_domains_command,
            'umbrella-get-destination-domain': get_destination_domain_command,
            'umbrella-search-destination-domains': search_destination_domains_command,
            'test-module': test_module
        }

        command = demisto.command()
        if command in commands:
            return_results(commands[command](client, **args))
        else:
            return_error(f'Command {command} is not available in this integration')

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
