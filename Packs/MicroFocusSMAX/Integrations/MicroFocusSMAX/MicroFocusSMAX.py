
import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import requests
import traceback
from typing import Dict, Any

requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member


''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'

''' CLIENT CLASS '''


class Client(BaseClient):

    def __init__(self, base_url: str, token: object, tenant_id: str, use_ssl: bool, use_proxy: bool, **kwargs):
        super().__init__(base_url, verify=use_ssl, proxy=use_proxy, **kwargs)
        self.headers = {'Cookie': f'SMAX_AUTH_TOKEN={token}'}
        self.tenant_id = tenant_id

    def get_entity(self, entity_type, entity_id, entity_fields):
        url_suffix = f'rest/{self.tenant_id}/ems/{entity_type}/{entity_id}'
        params = {"layout": entity_fields}
        response = self._http_request(method='GET', url_suffix=url_suffix,
                                      headers=self.headers, params=params)
        return response

    def query_entities(self, entity_type, query_filter, entity_fields, order_by, size, skip):
        url_suffix = f'rest/{self.tenant_id}/ems/{entity_type}'
        params = {
            "layout": entity_fields,
            "meta": "TotalCount,Count"
        }
        if query_filter:
            params.update({"filter": query_filter})
        if order_by:
            params.update({"order": order_by})
        if size:
            params.update({"size": size})
        if skip:
            params.update({"skip": skip})
        response = self._http_request(method='GET', url_suffix=url_suffix,
                                      headers=self.headers, params=params)
        return response


''' HELPER FUNCTIONS '''


def login(server: str, tenant:  str, username: str, password: str, verify_certificate: bool):
    response = requests.post(f'{server}/auth/authentication-endpoint/authenticate/token?TENANTID={tenant}',
                             verify=verify_certificate,
                             json={'Login': username, 'Password': password})
    token = response.text
    if not token:
        raise DemistoException(f'Authorization Error: please check your credentials. \n\nError:\n{response}')
    return token


''' COMMAND FUNCTIONS '''


def test_module(client: Client, username) -> str:
    try:
        client.query_entities(entity_type="Person", query_filter=f"Name startswith ('{username}')", order_by=None,
                              entity_fields="Id", size=None, skip=None)
    except DemistoException as exception:
        if 'Authorization Required' in str(exception) or 'Authentication failed' in str(exception):
            return_error(f'Authorization Error: please check your credentials.\n\nError:\n{exception}')

        if 'HTTPSConnectionPool' in str(exception):
            return_error(f'Connection Error: please check your server ip address.\n\nError: {exception}')
        raise
    return 'ok'


def fetch_incidents_command(client: Client, username) -> str:
    try:
        client.query_entities(entity_type="Person", query_filter=f"Name startswith ('{username}')", order_by=None,
                              entity_fields="Id", size=None, skip=None)
    except DemistoException as exception:
        if 'Authorization Required' in str(exception) or 'Authentication failed' in str(exception):
            return_error(f'Authorization Error: please check your credentials.\n\nError:\n{exception}')

        if 'HTTPSConnectionPool' in str(exception):
            return_error(f'Connection Error: please check your server ip address.\n\nError: {exception}')
        raise
    return 'ok'

def get_entity_command(client: Client, args: Dict[str, Any]) -> CommandResults:

    entity_type = args.get('entity_type', None)
    entity_id = args.get('entity_id', None)
    entity_fields = args.get('entity_fields', None)

    readable_entity = {}

    if not (entity_type and entity_id):
        raise ValueError('Entity Type and ID are not specified')

    if entity_fields:
        entity_fields = 'Name,Id,' + entity_fields
    else:
        entity_fields = 'Name,Id'

    result = client.get_entity(entity_type=entity_type, entity_id=entity_id, entity_fields=entity_fields)

    entity = result.get('entities')[0]

    readable_entity['Type'] = entity.get('entity_type')
    readable_entity.update(entity.get('properties'))

    readable_output = tableToMarkdown('Entity Details:', readable_entity)

    return CommandResults(
        outputs_prefix='MicroFocus.SMAX.Entities',
        outputs_key_field='properties.Id',
        readable_output=readable_output,
        outputs=entity,
    )


def query_entities_command(client: Client, args: Dict[str, Any]):

    entity_type = args.get('entity_type', None)
    entity_fields = args.get('entity_fields', None)
    query_filter = args.get('query_filter', None)
    order_by = args.get('order_by', None)
    size = args.get('size', None)
    skip = args.get('skip', None)

    readable_entities = []

    if not entity_type:
        raise ValueError('Entity Type is not specified')

    if entity_fields:
        entity_fields = 'Name,Id,' + entity_fields
    else:
        entity_fields = 'Name,Id'

    result = client.query_entities(entity_type=entity_type, entity_fields=entity_fields, query_filter=query_filter,
                                   order_by=order_by, size=size, skip=skip)

    for entity in result.get('entities'):
        readable_entity = {'Type': entity.get('entity_type')}
        readable_entity.update(entity.get('properties'))
        readable_entities.append(readable_entity)

    count_readable_output = tableToMarkdown('Result Total Count:', {
        "Query Time": result.get("meta")["query_time"],
        "Total Count": result.get("meta")["total_count"]
    })

    results_readable_output = tableToMarkdown('Result Details:', readable_entities)

    return [
        CommandResults(
            outputs_prefix='MicroFocus.SMAX.Query',
            outputs_key_field='query_time',
            readable_output=count_readable_output,
            outputs=result.get('meta'),
        ),
        CommandResults(
            outputs_prefix='MicroFocus.SMAX.Entities',
            outputs_key_field='properties.Id',
            readable_output=results_readable_output,
            outputs=result.get('entities'),
        )
    ]



''' MAIN FUNCTION '''


def main() -> None:
    args = demisto.args()
    params = demisto.params()
    base_url = params.get('url')
    tenant_id = params.get('tenant_id')
    verify_certificate = not params.get('insecure', False)
    proxy = not params.get('insecure', False)
    username = params.get('credentials', {}).get('identifier')
    password = params.get('credentials', {}).get('password')

    handle_proxy()

    token = login(base_url, tenant_id, username, password, verify_certificate)

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        client = Client(
            base_url=base_url,
            token=token,
            tenant_id=tenant_id,
            use_ssl=verify_certificate,
            use_proxy=proxy
        )

        if demisto.command() == 'test-module':
            result = test_module(client, username)
            return_results(result)

        if demisto.command() == 'fetch-incidents':
            fetch_incidents_command(client, args)

        elif demisto.command() == 'microfocus-smax-get-entity':
            return_results(get_entity_command(client, args))

        elif demisto.command() == 'microfocus-smax-query-entities':
            return_results(query_entities_command(client, args))

    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
