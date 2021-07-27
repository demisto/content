import base64
import json

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


class Client(BaseClient):
    def __init__(self, base_url, *args, **kwarg):
        super().__init__(base_url, *args, **kwarg)

    def get_destinations(self, organizationId, destinationListId):
        uri = f'/{organizationId}/destinationlists/{destinationListId}/destinations'
        return self._http_request('GET', uri)


def test_module(client: Client, **args) -> str:
    organizationId = args.get('orgId')

    if not organizationId:
        return "organizationId not provided"

    uri = f'/{organizationId}/destinationlists'

    client._http_request('GET', uri)

    return "ok"


def get_destination_lists(client: Client, **args) -> CommandResults:
    organizationId = args.get('orgId')
    uri = f'{organizationId}/destinationlists'

    r = client._http_request('GET', uri)

    data = []
    for destination_list in r['data']:
        data.append(
            {
                'name': destination_list['name'],
                'id': destination_list['id']
            }
        )
    results = CommandResults(
        outputs_prefix="Umbrella.DestinationLists",
        outputs_key_field="id",
        outputs=data
    )

    return results


def add_domain(client: Client, **args) -> str:
    organizationId = args.get('orgId')
    destinationListId = args.get('destId')
    uri = f'{organizationId}/destinationlists/{destinationListId}/destinations'

    destinations = argToList(args.get('domains'))
    comment = args.get('comment')
    payload = [{'destination': destination, 'comment': comment} for destination in destinations]

    payload = json.dumps(payload)

    r = client._http_request('POST', uri, data=payload)

    return f'Domain {", ".join(destinations)} successfully added to list {r["data"]["name"]}'


def remove_domain(client: Client, **args) -> str:
    # https://docs.umbrella.com/umbrella-api/reference#delete_v1-organizations-organizationid-destinationlists-destinationlistid-destinations-remove
    organizationId = args.get('orgId')
    destinationListId = args.get('destId')
    uri = f'{organizationId}/destinationlists/{destinationListId}/destinations/remove'

    destinations = argToList(args.get('domainIds'))
    payload = "[" + ", ".join(destinations) + "]"

    r = client._http_request('DELETE', uri, data=payload)

    return f'Domain {", ".join(destinations)} successfully removed from list {r["data"]["name"]}'


def get_destination_domains(client: Client, **args) -> CommandResults:
    r = client.get_destinations(args.get('orgId'), args.get('destId'))

    results = CommandResults(
        outputs_prefix="Umbrella.Destinations",
        outputs_key_field="id",
        outputs=r.get('data'),
        readable_output=tableToMarkdown('Domains in Destination List', r.get('data'))
    )

    return results


def get_destination_domain(client: Client, **args) -> CommandResults:
    r = client.get_destinations(args.get('orgId'), args.get('destId'))

    destination_domain = None
    for destination in r.get('data'):
        if destination.get('destination') == args['domain']:
            destination_domain = destination

    results = CommandResults(
        outputs_prefix="Umbrella.Destinations",
        outputs_key_field="id",
        outputs=destination_domain,
        readable_output=tableToMarkdown('Domain in Destination List', destination_domain)
    )

    return results


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

    client = Client(
        base_url,
        verify=verify,
        headers=headers,
        proxy=proxy
    )

    commands = {
        'umbrella-get-destination-lists': get_destination_lists,
        'umbrella-add-domain': add_domain,
        'umbrella-remove-domain': remove_domain,
        'umbrella-get-destination-domains': get_destination_domains,
        'umbrella-get-destination-domain': get_destination_domain,
        'test-module': test_module
    }

    command = demisto.command()
    if command in commands:
        return_results(commands[command](client, **args))
    else:
        return_error(f'Command {command} is not available in this integration')


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
