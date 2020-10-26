import base64
import json

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


class Client(BaseClient):
    def __init__(self, base_url, *args, **kwarg):
        super().__init__(base_url, *args, **kwarg)


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

    data = {x['name']: x['id'] for x in r['data']}
    results = CommandResults(
        outputs_prefix="Umbrella.DestinationLists", outputs_key_field="", outputs=data
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


def get_destination_domains(client: Client, **args) -> CommandResults:
    organizationId = args.get('orgId')
    destinationListId = args.get('destId')
    uri = f'/{organizationId}/destinationlists/{destinationListId}/destinations'

    r = client._http_request('GET', uri)

    for x in r.get('data'):
        x['Destination List'] = destinationListId

    results = CommandResults(
        outputs_prefix="Umbrella.Destinations", outputs_key_field="data.id", outputs=r,
        readable_output=tableToMarkdown('Domains in Destination List', r.get('data'))
    )

    return results


def main():
    # If an arg supplying an orgId is provided, will override the one found in params
    args = {**demisto.params(), **demisto.args()}

    base_url = 'https://management.api.umbrella.com/v1/organizations'
    api_key = base64.b64encode(f'{demisto.getParam("apiKey")}:{demisto.getParam("apiSecret")}'.encode("ascii"))
    verify = args.get('Verify SSL')

    headers = {
        'accept': "application/json",
        'content-type': "application/json",
        'Authorization': f'Basic {api_key.decode("ascii")}'
    }

    client = Client(
        base_url,
        verify=verify,
        headers=headers
    )

    commands = {
        'umbrella-get-destination-lists': get_destination_lists,
        'umbrella-add-domain': add_domain,
        'umbrella-get-destination-domains': get_destination_domains,
        'test-module': test_module
    }

    command = demisto.command()
    if command in commands:
        return_results(commands[command](client, **args))
    else:
        return_error(f'Command {command} is not available in this integration')


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
