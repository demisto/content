from CommonServerPython import *

import requests
import traceback
from typing import Any
import urllib3

urllib3.disable_warnings()  # pylint: disable=no-member


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

    def bulk_action(self, action_type, entities):
        if type(entities) is str:
            entities = json.loads(entities)
        url_suffix = f'rest/{self.tenant_id}/ems/bulk'
        payload = {
            "entities": entities,
            "operation": action_type
        }
        response = self._http_request(method='POST', url_suffix=url_suffix,
                                      headers=self.headers, json_data=payload)
        return response


''' HELPER FUNCTIONS '''


def login(server: str, tenant: str, username: str, password: str, verify_certificate: bool):
    response = requests.post(f'{server}/auth/authentication-endpoint/authenticate/token?TENANTID={tenant}',
                             verify=verify_certificate, json={'Login': username, 'Password': password})
    token = response.text
    if not token:
        raise DemistoException(f'Authorization Error: please check your credentials. \n\nError:\n{response}')
    return token


def validate_fetch_params(fetch_limit, fetch_start):
    try:
        fetch_limit = int(fetch_limit)
    except Exception as e:
        raise DemistoException(f'Fetch limit has to be a number, Error Details: {e}')
    if not fetch_limit or fetch_limit > 200:
        raise DemistoException('Fetch limit has to be in a range between 1 and 200')

    try:
        fetch_start = int(fetch_start)
    except Exception as e:
        raise DemistoException(f'Fetch start has to be a number, Error Details: {e}')
    if not fetch_start:
        raise DemistoException('Fetch start is not specified')


''' COMMAND FUNCTIONS '''


def test_module(client: Client, username, fetch_limit, fetch_start) -> str:
    client.query_entities(entity_type="Person", query_filter=f"Name startswith ('{username}')", order_by=None,
                          entity_fields="Id", size=None, skip=None)
    validate_fetch_params(fetch_limit=fetch_limit, fetch_start=fetch_start)
    return 'ok'


def fetch_incidents_command(client: Client, object_to_fetch="Incident", fetch_query_filter=None, fetch_fields=None,
                            fetch_limit='100', fetch_start='1'):
    incidents = []
    validate_fetch_params(fetch_limit=fetch_limit, fetch_start=fetch_start)
    if fetch_fields:
        fetch_fields = 'DisplayLabel,Id,EmsCreationTime' + fetch_fields
    else:
        fetch_fields = 'DisplayLabel,Id,EmsCreationTime'

    last_run = demisto.getLastRun()
    if last_run and 'start_time' in last_run:
        start_time = last_run.get('start_time') + 1
    else:
        start_time = round((datetime.now() - timedelta(days=int(fetch_start))).timestamp() * 1000)
    if fetch_query_filter:
        fetch_query_filter = f'EmsCreationTime btw ({start_time},{round(datetime.now().timestamp() * 1000)})'\
                             + fetch_query_filter
    else:
        fetch_query_filter = f'EmsCreationTime btw ({start_time},{round(datetime.now().timestamp() * 1000)})'

    results = client.query_entities(entity_type=object_to_fetch, query_filter=fetch_query_filter,
                                    order_by="Id desc", entity_fields=fetch_fields,
                                    size=fetch_limit, skip=None)
    for entity in results.get('entities'):
        properties = entity.get('properties')
        created_at_epoch = int(properties.get('EmsCreationTime'))
        created_at_date = datetime.fromtimestamp(round(created_at_epoch / 1000), timezone.utc)
        entity_id = properties.get('Id')
        raw_json = {'Type': entity.get('entity_type')}
        raw_json.update(properties)
        inc = {
            'name': f'SMAX {object_to_fetch}: {entity_id}',
            'occurred': created_at_date.isoformat(),
            'rawJSON': json.dumps(raw_json)
        }
        incidents.append(inc)
        if created_at_epoch > start_time:
            start_time = created_at_epoch
    incidents.reverse()
    demisto.setLastRun({'start_time': start_time})
    demisto.incidents(incidents)


def get_entity_command(client: Client, args: dict[str, Any]) -> CommandResults:

    entity_type = args.get('entity_type', None)
    entity_id = args.get('entity_id', None)
    entity_fields = args.get('entity_fields', None)

    readable_entity = {}

    if not (entity_type and entity_id):
        raise ValueError('Entity Type and ID are not specified')

    if entity_fields:
        entity_fields = 'DisplayLabel,Id,' + entity_fields
    else:
        entity_fields = 'DisplayLabel,Id'

    result = client.get_entity(entity_type=entity_type, entity_id=entity_id, entity_fields=entity_fields)

    if result.get('entities'):

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
    else:
        return CommandResults(
            readable_output="The entity is not found"
        )


def query_entities_command(client: Client, args: dict[str, Any]):

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

    results = client.query_entities(entity_type=entity_type, entity_fields=entity_fields, query_filter=query_filter,
                                    order_by=order_by, size=size, skip=skip)
    if results.get('entities'):
        for entity in results.get('entities'):
            readable_entity = {'Type': entity.get('entity_type')}
            readable_entity.update(entity.get('properties'))
            readable_entities.append(readable_entity)
        meta_data = results.get("meta")
        count_readable_output = tableToMarkdown('Result Total Count:', {
            "Query Time": meta_data.get("query_time"),
            "Total Count": meta_data.get("total_count")
        })

        results_readable_output = tableToMarkdown('Result Details:', readable_entities)

        return [
            CommandResults(
                outputs_prefix='MicroFocus.SMAX.Query',
                outputs_key_field='query_time',
                readable_output=count_readable_output,
                outputs=results.get('meta'),
            ),
            CommandResults(
                outputs_prefix='MicroFocus.SMAX.Entities',
                outputs_key_field='properties.Id',
                readable_output=results_readable_output,
                outputs=results.get('entities'),
            )
        ]
    else:
        return CommandResults(
            readable_output="No entities found"
        )


def create_entities_command(client: Client, args: dict[str, Any]) -> CommandResults:

    entities = args.get('entities', None)

    readable_entities = []
    context_entities = []

    if not entities:
        raise ValueError('Entities are not specified')

    result = client.bulk_action(action_type="CREATE", entities=entities)
    bulk_results = result.get('entity_result_list')
    for entity in bulk_results:
        entity_object = entity.get('entity')
        completion_status = entity.get('completion_status')
        context_entity = {"completion_status": completion_status}
        context_entity.update(entity_object)
        context_entities.append(context_entity)
        readable_entity = {
            'Type': entity_object.get('entity_type'),
            'CompletionStatus': completion_status
        }
        readable_entity.update(entity_object.get('properties'))
        readable_entities.append(readable_entity)

    results_readable_output = tableToMarkdown('Entities Creation Details:', readable_entities)

    return CommandResults(
        outputs_prefix='MicroFocus.SMAX.Entities',
        outputs_key_field='properties.Id',
        readable_output=results_readable_output,
        outputs=context_entities,
    )


def update_entities_command(client: Client, args: dict[str, Any]) -> CommandResults:

    entities = args.get('entities', None)

    readable_entities = []
    context_entities = []

    if not entities:
        raise ValueError('Entities are not specified')

    result = client.bulk_action(action_type="UPDATE", entities=entities)
    bulk_results = result.get('entity_result_list')
    for entity in bulk_results:
        entity_object = entity.get('entity')
        completion_status = entity.get('completion_status')
        context_entity = {"completion_status": completion_status}
        context_entity.update(entity_object)
        context_entities.append(context_entity)
        readable_entity = {
            'Type': entity_object.get('entity_type'),
            'CompletionStatus': completion_status
        }
        readable_entity.update(entity_object.get('properties'))
        readable_entities.append(readable_entity)

    results_readable_output = tableToMarkdown('Entities Update Details:', readable_entities)

    return CommandResults(
        outputs_prefix='MicroFocus.SMAX.Entities',
        outputs_key_field='properties.Id',
        readable_output=results_readable_output,
        outputs=context_entities,
    )


def create_incident_command(client: Client, args: dict[str, Any]) -> CommandResults:

    readable_entities = []
    context_entities = []

    incident_name = args.get('incident_name')
    incident_description = args.get('incident_description')
    impacted_service = args.get('impacted_service')
    requested_by = args.get('requested_by', None)
    incident_urgency = args.get('incident_urgency', None)
    impact_scope = args.get('impact_scope', None)
    service_desk_group = args.get('service_desk_group', None)
    other_properities = args.get('other_properities', None)

    incident_properities = {
        "DisplayLabel": incident_name,
        "Description": incident_description,
        "RegisteredForActualService": impacted_service
    }

    if requested_by:
        incident_properities["RequestedByPerson"] = requested_by
    if incident_urgency:
        incident_properities["Urgency"] = incident_urgency
    if impact_scope:
        incident_properities["ImpactScope"] = impact_scope
    if service_desk_group:
        incident_properities["ServiceDeskGroup"] = service_desk_group
    if other_properities:
        incident_properities.update(json.loads(other_properities))

    incident_object = {
        "entity_type": "Incident",
        "properties": incident_properities
    }

    result = client.bulk_action(action_type="CREATE", entities=[incident_object])
    bulk_results = result.get('entity_result_list')
    for entity in bulk_results:
        entity_object = entity.get('entity')
        completion_status = entity.get('completion_status')
        context_entity = {"completion_status": completion_status}
        context_entity.update(entity_object)
        context_entities.append(context_entity)
        readable_entity = {
            'Type': entity_object.get('entity_type'),
            'CompletionStatus': completion_status
        }
        readable_entity.update(entity_object.get('properties'))
        readable_entities.append(readable_entity)

    results_readable_output = tableToMarkdown('Incident Creation Results:', readable_entities)

    return CommandResults(
        outputs_prefix='MicroFocus.SMAX.Entities',
        outputs_key_field='properties.Id',
        readable_output=results_readable_output,
        outputs=context_entities,
    )


def update_incident_command(client: Client, args: dict[str, Any]) -> CommandResults:

    readable_entities = []
    context_entities = []

    incident_id = args.get('incident_id')
    incident_description = args.get('incident_description', None)
    incident_urgency = args.get('incident_urgency', None)
    incident_scope = args.get('incident_scope', None)
    incident_status = args.get('incident_status', None)
    incident_closure_category = args.get('incident_closure_category', None)
    incident_completion_code = args.get('incident_completion_code', None)
    incident_solution = args.get('incident_solution', None)
    other_properities = args.get('other_properities', None)

    incident_properities = {
        "Id": incident_id
    }

    if incident_description:
        incident_properities["Description"] = incident_description
    if incident_urgency:
        incident_properities["Urgency"] = incident_urgency
    if incident_scope:
        incident_properities["ImpactScope"] = incident_scope
    if incident_status:
        incident_properities["Status"] = incident_status
    if incident_closure_category:
        incident_properities["ClosureCategory"] = incident_closure_category
    if incident_completion_code:
        incident_properities["CompletionCode"] = incident_completion_code
    if incident_solution:
        incident_properities["Solution"] = incident_solution
    if other_properities:
        incident_properities.update(json.loads(other_properities))

    request_object = {
        "entity_type": "Incident",
        "properties": incident_properities
    }

    result = client.bulk_action(action_type="UPDATE", entities=[request_object])
    bulk_results = result.get('entity_result_list')
    for entity in bulk_results:
        entity_object = entity.get('entity')
        completion_status = entity.get('completion_status')
        context_entity = {"completion_status": completion_status}
        context_entity.update(entity_object)
        context_entities.append(context_entity)
        readable_entity = {
            'Type': entity_object.get('entity_type'),
            'CompletionStatus': completion_status
        }
        readable_entity.update(entity_object.get('properties'))
        readable_entities.append(readable_entity)

    results_readable_output = tableToMarkdown('Incident Update Results:', readable_entities)

    return CommandResults(
        outputs_prefix='MicroFocus.SMAX.Entities',
        outputs_key_field='properties.Id',
        readable_output=results_readable_output,
        outputs=context_entities,
    )


def create_request_command(client: Client, args: dict[str, Any]) -> CommandResults:

    readable_entities = []
    context_entities = []

    request_name = args.get('request_name')
    request_description = args.get('request_description')
    requested_by = args.get('requested_by')
    requested_for = args.get('requested_for')
    request_urgency = args.get('request_urgency', None)
    impact_scope = args.get('impact_scope', None)
    other_properities = args.get('other_properities', None)

    request_properities = {
        "DisplayLabel": request_name,
        "Description": request_description,
        "RequestedByPerson": requested_by,
        "RequestedForPerson": requested_for
    }

    if request_urgency:
        request_properities["Urgency"] = request_urgency
    if impact_scope:
        request_properities["ImpactScope"] = impact_scope
    if other_properities:
        request_properities.update(json.loads(other_properities))

    request_object = {
        "entity_type": "Request",
        "properties": request_properities
    }

    result = client.bulk_action(action_type="CREATE", entities=[request_object])
    bulk_results = result.get('entity_result_list')
    for entity in bulk_results:
        entity_object = entity.get('entity')
        completion_status = entity.get('completion_status')
        context_entity = {"completion_status": completion_status}
        context_entity.update(entity_object)
        context_entities.append(context_entity)
        readable_entity = {
            'Type': entity_object.get('entity_type'),
            'CompletionStatus': completion_status
        }
        readable_entity.update(entity_object.get('properties'))
        readable_entities.append(readable_entity)

    results_readable_output = tableToMarkdown('Request Creation Results:', readable_entities)

    return CommandResults(
        outputs_prefix='MicroFocus.SMAX.Entities',
        outputs_key_field='properties.Id',
        readable_output=results_readable_output,
        outputs=context_entities,
    )


def update_request_command(client: Client, args: dict[str, Any]) -> CommandResults:

    readable_entities = []
    context_entities = []

    request_id = args.get('request_id')
    request_description = args.get('request_description', None)
    request_urgency = args.get('request_urgency', None)
    impact_scope = args.get('impact_scope', None)
    request_status = args.get('request_status', None)
    request_note = args.get('request_note', None)
    other_properities = args.get('other_properities', None)

    request_properities = {
        "Id": request_id
    }

    if request_description:
        request_properities["Description"] = request_description
    if request_urgency:
        request_properities["Urgency"] = request_urgency
    if impact_scope:
        request_properities["ImpactScope"] = impact_scope
    if request_status:
        request_properities["Status"] = request_status
    if request_note:
        request_properities["ClosureCategory"] = request_note
    if other_properities:
        request_properities.update(json.loads(other_properities))

    request_object = {
        "entity_type": "Request",
        "properties": request_properities
    }

    result = client.bulk_action(action_type="UPDATE", entities=[request_object])
    bulk_results = result.get('entity_result_list')
    for entity in bulk_results:
        entity_object = entity.get('entity')
        completion_status = entity.get('completion_status')
        context_entity = {"completion_status": completion_status}
        context_entity.update(entity_object)
        context_entities.append(context_entity)
        readable_entity = {
            'Type': entity_object.get('entity_type'),
            'CompletionStatus': completion_status
        }
        readable_entity.update(entity_object.get('properties'))
        readable_entities.append(readable_entity)

    results_readable_output = tableToMarkdown('Request Update Results:', readable_entities)

    return CommandResults(
        outputs_prefix='MicroFocus.SMAX.Entities',
        outputs_key_field='properties.Id',
        readable_output=results_readable_output,
        outputs=context_entities,
    )


''' MAIN FUNCTION '''


def main() -> None:
    args = demisto.args()
    params = demisto.params()
    base_url = params.get('url')
    tenant_id = params.get('tenant_id')
    object_to_fetch = params.get('object_to_fetch')
    fetch_query_filter = params.get('fetch_query_filter')
    fetch_fields = params.get('fetch_fields')
    fetch_start = params.get('fetch_start')
    fetch_limit = params.get('fetch_limit')
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
            result = test_module(client, username, fetch_start=fetch_start, fetch_limit=fetch_limit)
            return_results(result)

        if demisto.command() == 'fetch-incidents':
            fetch_incidents_command(client, object_to_fetch=object_to_fetch, fetch_query_filter=fetch_query_filter,
                                    fetch_fields=fetch_fields, fetch_limit=fetch_limit, fetch_start=fetch_start)

        elif demisto.command() == 'microfocus-smax-get-entity':
            return_results(get_entity_command(client, args))

        elif demisto.command() == 'microfocus-smax-query-entities':
            return_results(query_entities_command(client, args))

        elif demisto.command() == 'microfocus-smax-create-entities':
            return_results(create_entities_command(client, args))

        elif demisto.command() == 'microfocus-smax-update-entities':
            return_results(update_entities_command(client, args))

        elif demisto.command() == 'microfocus-smax-create-incident':
            return_results(create_incident_command(client, args))

        elif demisto.command() == 'microfocus-smax-update-incident':
            return_results(update_incident_command(client, args))

        elif demisto.command() == 'microfocus-smax-create-request':
            return_results(create_request_command(client, args))

        elif demisto.command() == 'microfocus-smax-update-request':
            return_results(update_request_command(client, args))

    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
