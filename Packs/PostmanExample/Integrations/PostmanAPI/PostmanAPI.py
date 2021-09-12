import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


class Client(BaseClient):
    def __init__(self, server_url, verify, proxy, headers, auth):
        super().__init__(base_url=server_url, verify=verify, proxy=proxy, headers=headers, auth=auth)

    def all_collections_request(self):
        headers = self._headers

        response = self._http_request('GET', 'collections', headers=headers)

        return response

    def single_collection_request(self, collection_uid):
        headers = self._headers

        response = self._http_request('GET', f'collections/{collection_uid}', headers=headers)

        return response

    def create_collection_request(self, name, description, schema, url, method, key, value, mode, raw):
        data = {"collection": {"info": {"description": description, "name": name, "schema": schema}, "item": [{"item": [{"name": name, "request": {"body": {
            "mode": mode, "raw": raw}, "description": description, "header": [{"key": key, "value": value}], "method": method, "url": url}}], "name": name}]}}
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request('POST', 'collections', json_data=data, headers=headers)

        return response

    def update_collection_request(self, collection_uid, name, description, _postman_id, schema, url, method, key, value, mode, raw):
        data = {"collection": {"info": {"_postman_id": _postman_id, "description": description, "name": name, "schema": schema}, "item": [{"item": [{"name": name, "request": {
            "body": {"mode": mode, "raw": raw}, "description": description, "header": [{"key": key, "value": value}], "method": method, "url": url}}], "name": name}]}}
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request('PUT', f'collections/{collection_uid}', json_data=data, headers=headers)

        return response

    def delete_collection_request(self, collection_uid):
        headers = self._headers

        response = self._http_request('DELETE', f'collections/{collection_uid}', headers=headers)

        return response

    def create_a_fork_request(self, collection_uid, workspace, label):
        params = assign_params(workspace=workspace)
        data = {"label": label}
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request(
            'POST', f'collections/fork/{collection_uid}', params=params, json_data=data, headers=headers)

        return response

    def merge_a_fork_request(self, strategy, source, destination):
        data = {"destination": destination, "source": source, "strategy": strategy}
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request('POST', 'collections/merge', json_data=data, headers=headers)

        return response

    def all_environments_request(self):
        headers = self._headers

        response = self._http_request('GET', 'environments', headers=headers)

        return response

    def single_environment_request(self, environment_uid):
        headers = self._headers

        response = self._http_request('GET', f'environments/{environment_uid}', headers=headers)

        return response

    def create_environment_request(self, name, key, value):
        data = {"environment": {"name": name, "values": [{"key": key, "value": value}]}}
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request('POST', 'environments', json_data=data, headers=headers)

        return response

    def update_environment_request(self, environment_uid, name, key, value):
        data = {"environment": {"name": name, "values": [{"key": key, "value": value}]}}
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request('PUT', f'environments/{environment_uid}', json_data=data, headers=headers)

        return response

    def delete_environment_request(self, environment_uid):
        headers = self._headers

        response = self._http_request('DELETE', f'environments/{environment_uid}', headers=headers)

        return response

    def all_mocks_request(self):
        headers = self._headers

        response = self._http_request('GET', 'mocks', headers=headers)

        return response

    def single_mock_request(self, mock_uid):
        headers = self._headers

        response = self._http_request('GET', f'mocks/{mock_uid}', headers=headers)

        return response

    def create_mock_request(self, collection, environment):
        data = {"mock": {"collection": collection, "environment": environment}}
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request('POST', 'mocks', json_data=data, headers=headers)

        return response

    def update_mock_request(self, mock_uid, name, environment, description, private, versiontag):
        data = {"mock": {"description": description, "environment": environment,
                         "name": name, "private": private, "versionTag": versiontag}}
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request('PUT', f'mocks/{mock_uid}', json_data=data, headers=headers)

        return response

    def delete_mock_request(self, mock_uid):
        headers = self._headers

        response = self._http_request('DELETE', f'mocks/{mock_uid}', headers=headers)

        return response

    def publish_mock_request(self, mock_uid):
        headers = self._headers

        response = self._http_request('POST', f'mocks/{mock_uid}/publish', headers=headers)

        return response

    def unpublish_mock_request(self, mock_uid):
        headers = self._headers

        response = self._http_request('DELETE', f'mocks/{mock_uid}/unpublish', headers=headers)

        return response

    def all_monitors_request(self):
        headers = self._headers

        response = self._http_request('GET', 'monitors', headers=headers)

        return response

    def single_monitor_request(self, monitor_uid):
        headers = self._headers

        response = self._http_request('GET', f'monitors/{monitor_uid}', headers=headers)

        return response

    def create_monitor_request(self, name, cron, timezone, collection, environment):
        data = {"monitor": {"collection": collection, "environment": environment,
                            "name": name, "schedule": {"cron": cron, "timezone": timezone}}}
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request('POST', 'monitors', json_data=data, headers=headers)

        return response

    def update_monitor_request(self, monitor_uid, name, cron, timezone):
        data = {"monitor": {"name": name, "schedule": {"cron": cron, "timezone": timezone}}}
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request('PUT', f'monitors/{monitor_uid}', json_data=data, headers=headers)

        return response

    def delete_monitor_request(self, monitor_uid):
        headers = self._headers

        response = self._http_request('DELETE', f'monitors/{monitor_uid}', headers=headers)

        return response

    def run_a_monitor_request(self, monitor_uid):
        headers = self._headers

        response = self._http_request('POST', f'monitors/{monitor_uid}/run', headers=headers)

        return response

    def all_workspaces_request(self):
        headers = self._headers

        response = self._http_request('GET', 'workspaces', headers=headers)

        return response

    def single_workspace_request(self, workspace_id):
        headers = self._headers

        response = self._http_request('GET', f'workspaces/{workspace_id}', headers=headers)

        return response

    def create_workspace_request(self, name, type_, description, id_, uid):
        data = {"workspace": {"collections": [{"id": id_, "name": name, "uid": uid}], "description": description, "environments": [
            {"id": id_, "name": name, "uid": uid}], "mocks": [{"id": id_}], "monitors": [{"id": id_}], "name": name, "type": type_}}
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request('POST', 'workspaces', json_data=data, headers=headers)

        return response

    def update_workspace_request(self, workspace_id, name, description, id_, uid):
        data = {"workspace": {"collections": [{"id": id_, "name": name, "uid": uid}], "description": description, "environments": [
            {"id": id_, "name": name, "uid": uid}], "mocks": [{"id": id_}], "monitors": [{"id": id_}], "name": name}}
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request('PUT', f'workspaces/{workspace_id}', json_data=data, headers=headers)

        return response

    def delete_workspace_request(self, workspace_id):
        headers = self._headers

        response = self._http_request('DELETE', f'workspaces/{workspace_id}', headers=headers)

        return response

    def api_key_owner_request(self):
        headers = self._headers

        response = self._http_request('GET', 'me', headers=headers)

        return response

    def import_external_api_specification_request(self, type_, openapi, version, title, name, url, summary, operationid, in_, description, required, format_):
        data = {"input": {"info": {"license": {"name": name}, "title": title, "version": version}, "openapi": openapi, "paths": {"/pets": {"get": {"operationId": operationid, "parameters": [{"description": description, "in": in_, "name": name, "required": required, "schema": {"format": format_, "type": type_}}], "responses": {
            "default": {"content": {"application/json": {"schema": {"properties": {"code": {"format": format_, "type": type_}, "message": {"type": type_}}, "required": required}}}, "description": description}}, "summary": summary}}}, "servers": [{"url": url}]}, "type": type_}
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request('POST', 'import/openapi', json_data=data, headers=headers)

        return response

    def import_exported_data_request(self):
        headers = self._headers
        headers['Content-Type'] = 'multipart/form-data'

        response = self._http_request('POST', 'import/exported', headers=headers)

        return response

    def create_api_version_request(self, apiid, name, id_, schema, monitor, mock, documentation):
        data = {"version": {"name": name, "source": {"id": id, "relations": {
            "documentation": documentation, "mock": mock, "monitor": monitor}, "schema": schema}}}
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request('POST', f'apis/{apiid}/versions', json_data=data, headers=headers)

        return response

    def update_an_api_version_request(self, apiid, apiversionid, name):
        data = {"version": {"name": name}}
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request('PUT', f'apis/{apiid}/versions/{apiversionid}', json_data=data, headers=headers)

        return response

    def delete_an_api_version_request(self, apiid, apiversionid):
        headers = self._headers

        response = self._http_request('DELETE', f'apis/{apiid}/versions/{apiversionid}', headers=headers)

        return response

    def get_an_api_version_request(self, apiid, apiversionid):
        headers = self._headers

        response = self._http_request('GET', f'apis/{apiid}/versions/{apiversionid}', headers=headers)

        return response

    def get_all_api_versions_request(self, apiid):
        headers = self._headers

        response = self._http_request('GET', f'apis/{apiid}/versions', headers=headers)

        return response

    def create_schema_request(self, apiid, apiversionid, language, schema, type_):
        data = {"schema": {"language": language, "schema": schema, "type": type}}
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request(
            'POST', f'apis/{apiid}/versions/{apiversionid}/schemas', json_data=data, headers=headers)

        return response

    def update_schema_request(self, apiid, apiversionid, schemaid, language, schema, type_):
        data = {"schema": {"language": language, "schema": schema, "type": type}}
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request(
            'PUT', f'apis/{apiid}/versions/{apiversionid}/schemas/{schemaid}', json_data=data, headers=headers)

        return response

    def get_schema_request(self, apiid, apiversionid, schemaid):
        headers = self._headers

        response = self._http_request(
            'GET', f'apis/{apiid}/versions/{apiversionid}/schemas/{schemaid}', headers=headers)

        return response

    def create_collection_from_schema_request(self, apiid, apiversionid, schemaid, workspace, name, type_):
        params = assign_params(workspace=workspace)
        data = {"name": name, "relations": [{"type": type}]}
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request(
            'POST', f'apis/{apiid}/versions/{apiversionid}/schemas/{schemaid}/collections', params=params, json_data=data, headers=headers)

        return response

    def get_linked_relations_request(self, apiid, apiversionid):
        headers = self._headers

        response = self._http_request('GET', f'apis/{apiid}/versions/{apiversionid}/relations', headers=headers)

        return response

    def get_documentation_relations_request(self, apiid, apiversionid):
        headers = self._headers

        response = self._http_request('GET', f'apis/{apiid}/versions/{apiversionid}/documentation', headers=headers)

        return response

    def get_environment_relations_request(self, apiid, apiversionid):
        headers = self._headers

        response = self._http_request('GET', f'apis/{apiid}/versions/{apiversionid}/environment', headers=headers)

        return response

    def get_test_suite_relations_request(self, apiid, apiversionid):
        headers = self._headers

        response = self._http_request('GET', f'apis/{apiid}/versions/{apiversionid}/testsuite', headers=headers)

        return response

    def get_contract_test_relations_request(self, apiid, apiversionid):
        headers = self._headers

        response = self._http_request('GET', f'apis/{apiid}/versions/{apiversionid}/contracttest', headers=headers)

        return response

    def get_integration_test_relations_request(self, apiid, apiversionid):
        headers = self._headers

        response = self._http_request('GET', f'apis/{apiid}/versions/{apiversionid}/integrationtest', headers=headers)

        return response

    def get_monitor_relations_request(self, apiid, apiversionid):
        headers = self._headers

        response = self._http_request('GET', f'apis/{apiid}/versions/{apiversionid}/monitor', headers=headers)

        return response

    def create_relations_request(self, apiid, apiversionid, contracttest, testsuite, documentation, mock):
        data = {"contracttest": contracttest, "documentation": documentation, "mock": mock, "testsuite": testsuite}
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request(
            'POST', f'apis/{apiid}/versions/{apiversionid}/relations', json_data=data, headers=headers)

        return response

    def sync_relations_with_schema_request(self, apiid, apiversionid, entitytype, entityid):
        headers = self._headers

        response = self._http_request(
            'PUT', f'apis/{apiid}/versions/{apiversionid}/{entitytype}/{entityid}/syncWithSchema', headers=headers)

        return response

    def create_api_request(self, workspace, name, summary, description):
        params = assign_params(workspace=workspace)
        data = {"api": {"description": description, "name": name, "summary": summary}}
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request('POST', 'apis', params=params, json_data=data, headers=headers)

        return response

    def update_an_api_request(self, apiid, name, description):
        data = {"api": {"description": description, "name": name}}
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request('PUT', f'apis/{apiid}', json_data=data, headers=headers)

        return response

    def delete_an_api_request(self, apiid):
        headers = self._headers

        response = self._http_request('DELETE', f'apis/{apiid}', headers=headers)

        return response

    def get_all_apis_request(self, workspace, since, until, createdby, updatedby, ispublic, name, summary, description, sort, direction):
        params = assign_params(workspace=workspace, since=since, until=until, createdBy=createdby, updatedBy=updatedby,
                               isPublic=ispublic, name=name, summary=summary, description=description, sort=sort, direction=direction)
        headers = self._headers

        response = self._http_request('GET', 'apis', params=params, headers=headers)

        return response

    def single_api_request(self, apiid):
        headers = self._headers

        response = self._http_request('GET', f'apis/{apiid}', headers=headers)

        return response

    def create_webhook_request(self, workspace, name, collection):
        params = assign_params(workspace=workspace)
        data = {"webhook": {"collection": collection, "name": name}}
        headers = self._headers

        response = self._http_request('POST', 'webhooks', params=params, json_data=data, headers=headers)

        return response

    def fetch_user_resource_request(self, id_):
        headers = self._headers

        response = self._http_request('GET', f'scim/v2/Users/{id_}', headers=headers)

        return response

    def fetch_all_user_resource_request(self, startindex, count, filter_):
        params = assign_params(startIndex=startindex, count=count, filter=filter_)
        headers = self._headers

        response = self._http_request('GET', 'scim/v2/Users', params=params, headers=headers)

        return response

    def create_user_request(self, schemas, username, givenname, familyname, externalid, locale, active):
        data = {"active": active, "externalId": externalid, "locale": locale, "name": {
            "familyName": familyname, "givenName": givenname}, "schemas": schemas, "userName": username}
        headers = self._headers

        response = self._http_request('POST', 'scim/v2/Users', json_data=data, headers=headers)

        return response

    def update_user_information_request(self, id_, schemas, username, givenname, familyname, externalid, locale, active):
        data = {"active": active, "externalId": externalid, "locale": locale, "name": {
            "familyName": familyname, "givenName": givenname}, "schemas": schemas, "userName": username}
        headers = self._headers

        response = self._http_request('PUT', f'scim/v2/Users/{id_}', json_data=data, headers=headers)

        return response

    def update_team_user_information_request(self, id_, schemas, op, active):
        data = {"Operations": [{"op": op, "value": {"active": active}}], "schemas": schemas}
        headers = self._headers

        response = self._http_request('PATCH', f'scim/v2/Users/{id_}', json_data=data, headers=headers)

        return response

    def service_provider_config_request(self):
        headers = self._headers

        response = self._http_request('GET', 'scim/v2/ServiceProviderConfig', headers=headers)

        return response

    def get_resourcetypes_request(self):
        headers = self._headers

        response = self._http_request('GET', 'scim/v2/ResourceTypes', headers=headers)

        return response


def all_collections_command(client: Client, args: Dict[str, Any]) -> CommandResults:

    response = client.all_collections_request()
    command_results = CommandResults(
        outputs_prefix='PostmanAPI.AllCollections',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def single_collection_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    collection_uid = args.get('collection_uid')

    response = client.single_collection_request(collection_uid)
    command_results = CommandResults(
        outputs_prefix='PostmanAPI.SingleCollection',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def create_collection_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    name = args.get('name')
    description = args.get('description')
    schema = args.get('schema')
    name = args.get('name')
    name = args.get('name')
    url = args.get('url')
    method = args.get('method')
    key = args.get('key')
    value = args.get('value')
    mode = args.get('mode')
    raw = args.get('raw')
    description = args.get('description')
    url = args.get('url')
    method = args.get('method')
    description = args.get('description')

    response = client.create_collection_request(
        name, description, schema, url, method, key, value, mode, raw)
    command_results = CommandResults(
        outputs_prefix='PostmanAPI.CreateCollection',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def update_collection_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    collection_uid = args.get('collection_uid')
    name = args.get('name')
    description = args.get('description')
    _postman_id = args.get('_postman_id')
    schema = args.get('schema')
    url = args.get('url')
    method = args.get('method')
    key = args.get('key')
    value = args.get('value')
    mode = args.get('mode')
    raw = args.get('raw')

    response = client.update_collection_request(collection_uid, name, description, _postman_id,
                                                schema, url, method, key, value, mode, raw)
    command_results = CommandResults(
        outputs_prefix='PostmanAPI.UpdateCollection',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def delete_collection_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    collection_uid = args.get('collection_uid')

    response = client.delete_collection_request(collection_uid)
    command_results = CommandResults(
        outputs_prefix='PostmanAPI.DeleteCollection',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def create_a_fork_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    collection_uid = args.get('collection_uid')
    workspace = args.get('workspace')
    label = args.get('label')

    response = client.create_a_fork_request(collection_uid, workspace, label)
    command_results = CommandResults(
        outputs_prefix='PostmanAPI.CreateAFork',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def merge_a_fork_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    strategy = args.get('strategy')
    source = args.get('source')
    destination = args.get('destination')

    response = client.merge_a_fork_request(strategy, source, destination)
    command_results = CommandResults(
        outputs_prefix='PostmanAPI.MergeAFork',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def all_environments_command(client: Client, args: Dict[str, Any]) -> CommandResults:

    response = client.all_environments_request()
    command_results = CommandResults(
        outputs_prefix='PostmanAPI.AllEnvironments',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def single_environment_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    environment_uid = args.get('environment_uid')

    response = client.single_environment_request(environment_uid)
    command_results = CommandResults(
        outputs_prefix='PostmanAPI.SingleEnvironment',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def create_environment_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    name = args.get('name')
    key = args.get('key')
    value = args.get('value')

    response = client.create_environment_request(name, key, value)
    command_results = CommandResults(
        outputs_prefix='PostmanAPI.CreateEnvironment',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def update_environment_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    environment_uid = args.get('environment_uid')
    name = args.get('name')
    key = args.get('key')
    value = args.get('value')

    response = client.update_environment_request(environment_uid, name, key, value)
    command_results = CommandResults(
        outputs_prefix='PostmanAPI.UpdateEnvironment',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def delete_environment_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    environment_uid = args.get('environment_uid')

    response = client.delete_environment_request(environment_uid)
    command_results = CommandResults(
        outputs_prefix='PostmanAPI.DeleteEnvironment',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def all_mocks_command(client: Client, args: Dict[str, Any]) -> CommandResults:

    response = client.all_mocks_request()
    command_results = CommandResults(
        outputs_prefix='PostmanAPI.AllMocks',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def single_mock_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    mock_uid = args.get('mock_uid')

    response = client.single_mock_request(mock_uid)
    command_results = CommandResults(
        outputs_prefix='PostmanAPI.SingleMock',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def create_mock_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    collection = args.get('collection')
    environment = args.get('environment')

    response = client.create_mock_request(collection, environment)
    command_results = CommandResults(
        outputs_prefix='PostmanAPI.CreateMock',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def update_mock_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    mock_uid = args.get('mock_uid')
    name = args.get('name')
    environment = args.get('environment')
    description = args.get('description')
    private = args.get('private')
    versiontag = args.get('versiontag')

    response = client.update_mock_request(mock_uid, name, environment, description, private, versiontag)
    command_results = CommandResults(
        outputs_prefix='PostmanAPI.UpdateMock',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def delete_mock_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    mock_uid = args.get('mock_uid')

    response = client.delete_mock_request(mock_uid)
    command_results = CommandResults(
        outputs_prefix='PostmanAPI.DeleteMock',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def publish_mock_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    mock_uid = args.get('mock_uid')

    response = client.publish_mock_request(mock_uid)
    command_results = CommandResults(
        outputs_prefix='PostmanAPI.PublishMock',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def unpublish_mock_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    mock_uid = args.get('mock_uid')

    response = client.unpublish_mock_request(mock_uid)
    command_results = CommandResults(
        outputs_prefix='PostmanAPI.UnpublishMock',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def all_monitors_command(client: Client, args: Dict[str, Any]) -> CommandResults:

    response = client.all_monitors_request()
    command_results = CommandResults(
        outputs_prefix='PostmanAPI.AllMonitors',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def single_monitor_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    monitor_uid = args.get('monitor_uid')

    response = client.single_monitor_request(monitor_uid)
    command_results = CommandResults(
        outputs_prefix='PostmanAPI.SingleMonitor',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def create_monitor_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    name = args.get('name')
    cron = args.get('cron')
    timezone = args.get('timezone')
    collection = args.get('collection')
    environment = args.get('environment')

    response = client.create_monitor_request(name, cron, timezone, collection, environment)
    command_results = CommandResults(
        outputs_prefix='PostmanAPI.CreateMonitor',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def update_monitor_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    monitor_uid = args.get('monitor_uid')
    name = args.get('name')
    cron = args.get('cron')
    timezone = args.get('timezone')

    response = client.update_monitor_request(monitor_uid, name, cron, timezone)
    command_results = CommandResults(
        outputs_prefix='PostmanAPI.UpdateMonitor',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def delete_monitor_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    monitor_uid = args.get('monitor_uid')

    response = client.delete_monitor_request(monitor_uid)
    command_results = CommandResults(
        outputs_prefix='PostmanAPI.DeleteMonitor',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def run_a_monitor_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    monitor_uid = args.get('monitor_uid')

    response = client.run_a_monitor_request(monitor_uid)
    command_results = CommandResults(
        outputs_prefix='PostmanAPI.RunAMonitor',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def all_workspaces_command(client: Client, args: Dict[str, Any]) -> CommandResults:

    response = client.all_workspaces_request()
    command_results = CommandResults(
        outputs_prefix='PostmanAPI.AllWorkspaces',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def single_workspace_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    workspace_id = args.get('workspace_id')

    response = client.single_workspace_request(workspace_id)
    command_results = CommandResults(
        outputs_prefix='PostmanAPI.SingleWorkspace',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def create_workspace_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    name = args.get('name')
    type_ = args.get('type')
    description = args.get('description')
    id_ = args.get('id')
    uid = args.get('uid')

    response = client.create_workspace_request(name, type_, description, id_, uid)
    command_results = CommandResults(
        outputs_prefix='PostmanAPI.CreateWorkspace',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def update_workspace_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    workspace_id = args.get('workspace_id')
    name = args.get('name')
    description = args.get('description')
    id_ = args.get('id')
    uid = args.get('uid')

    response = client.update_workspace_request(
        workspace_id, name, description, id_, uid)
    command_results = CommandResults(
        outputs_prefix='PostmanAPI.UpdateWorkspace',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def delete_workspace_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    workspace_id = args.get('workspace_id')

    response = client.delete_workspace_request(workspace_id)
    command_results = CommandResults(
        outputs_prefix='PostmanAPI.DeleteWorkspace',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def api_key_owner_command(client: Client, args: Dict[str, Any]) -> CommandResults:

    response = client.api_key_owner_request()
    command_results = CommandResults(
        outputs_prefix='PostmanAPI.ApiKeyOwner',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def import_external_api_specification_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    type_ = args.get('type')
    openapi = args.get('openapi')
    version = args.get('version')
    title = args.get('title')
    name = args.get('name')
    url = args.get('url')
    summary = args.get('summary')
    operationid = args.get('operationid')
    in_ = args.get('in')
    description = args.get('description')
    required = args.get('required')
    format_ = args.get('format')

    response = client.import_external_api_specification_request(
        type_, openapi, version, title, name, url, summary, operationid, in_, description, required, format_)
    command_results = CommandResults(
        outputs_prefix='PostmanAPI.ImportExternalApiSpecification',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def import_exported_data_command(client: Client, args: Dict[str, Any]) -> CommandResults:

    response = client.import_exported_data_request()
    command_results = CommandResults(
        outputs_prefix='PostmanAPI.ImportExportedData',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def create_api_version_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    apiid = args.get('apiid')
    name = args.get('name')
    id_ = args.get('id')
    schema = args.get('schema')
    monitor = args.get('monitor')
    mock = args.get('mock')
    documentation = args.get('documentation')

    response = client.create_api_version_request(apiid, name, id_, schema, monitor, mock, documentation)
    command_results = CommandResults(
        outputs_prefix='PostmanAPI.CreateApiVersion',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def update_an_api_version_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    apiid = args.get('apiid')
    apiversionid = args.get('apiversionid')
    name = args.get('name')

    response = client.update_an_api_version_request(apiid, apiversionid, name)
    command_results = CommandResults(
        outputs_prefix='PostmanAPI.UpdateAnApiVersion',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def delete_an_api_version_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    apiid = args.get('apiid')
    apiversionid = args.get('apiversionid')

    response = client.delete_an_api_version_request(apiid, apiversionid)
    command_results = CommandResults(
        outputs_prefix='PostmanAPI.DeleteAnApiVersion',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_an_api_version_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    apiid = args.get('apiid')
    apiversionid = args.get('apiversionid')

    response = client.get_an_api_version_request(apiid, apiversionid)
    command_results = CommandResults(
        outputs_prefix='PostmanAPI.GetAnApiVersion',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_all_api_versions_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    apiid = args.get('apiid')

    response = client.get_all_api_versions_request(apiid)
    command_results = CommandResults(
        outputs_prefix='PostmanAPI.GetAllApiVersions',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def create_schema_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    apiid = args.get('apiid')
    apiversionid = args.get('apiversionid')
    language = args.get('language')
    schema = args.get('schema')
    type_ = args.get('type')

    response = client.create_schema_request(apiid, apiversionid, language, schema, type_)
    command_results = CommandResults(
        outputs_prefix='PostmanAPI.CreateSchema',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def update_schema_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    apiid = args.get('apiid')
    apiversionid = args.get('apiversionid')
    schemaid = args.get('schemaid')
    language = args.get('language')
    schema = args.get('schema')
    type_ = args.get('type')

    response = client.update_schema_request(apiid, apiversionid, schemaid, language, schema, type_)
    command_results = CommandResults(
        outputs_prefix='PostmanAPI.UpdateSchema',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_schema_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    apiid = args.get('apiid')
    apiversionid = args.get('apiversionid')
    schemaid = args.get('schemaid')

    response = client.get_schema_request(apiid, apiversionid, schemaid)
    command_results = CommandResults(
        outputs_prefix='PostmanAPI.GetSchema',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def create_collection_from_schema_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    apiid = args.get('apiid')
    apiversionid = args.get('apiversionid')
    schemaid = args.get('schemaid')
    workspace = args.get('workspace')
    name = args.get('name')
    type_ = args.get('type')

    response = client.create_collection_from_schema_request(apiid, apiversionid, schemaid, workspace, name, type_)
    command_results = CommandResults(
        outputs_prefix='PostmanAPI.CreateCollectionFromSchema',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_linked_relations_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    apiid = args.get('apiid')
    apiversionid = args.get('apiversionid')

    response = client.get_linked_relations_request(apiid, apiversionid)
    command_results = CommandResults(
        outputs_prefix='PostmanAPI.GetLinkedRelations',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_documentation_relations_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    apiid = args.get('apiid')
    apiversionid = args.get('apiversionid')

    response = client.get_documentation_relations_request(apiid, apiversionid)
    command_results = CommandResults(
        outputs_prefix='PostmanAPI.GetDocumentationRelations',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_environment_relations_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    apiid = args.get('apiid')
    apiversionid = args.get('apiversionid')

    response = client.get_environment_relations_request(apiid, apiversionid)
    command_results = CommandResults(
        outputs_prefix='PostmanAPI.GetEnvironmentRelations',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_test_suite_relations_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    apiid = args.get('apiid')
    apiversionid = args.get('apiversionid')

    response = client.get_test_suite_relations_request(apiid, apiversionid)
    command_results = CommandResults(
        outputs_prefix='PostmanAPI.GetTestSuiteRelations',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_contract_test_relations_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    apiid = args.get('apiid')
    apiversionid = args.get('apiversionid')

    response = client.get_contract_test_relations_request(apiid, apiversionid)
    command_results = CommandResults(
        outputs_prefix='PostmanAPI.GetContractTestRelations',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_integration_test_relations_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    apiid = args.get('apiid')
    apiversionid = args.get('apiversionid')

    response = client.get_integration_test_relations_request(apiid, apiversionid)
    command_results = CommandResults(
        outputs_prefix='PostmanAPI.GetIntegrationTestRelations',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_monitor_relations_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    apiid = args.get('apiid')
    apiversionid = args.get('apiversionid')

    response = client.get_monitor_relations_request(apiid, apiversionid)
    command_results = CommandResults(
        outputs_prefix='PostmanAPI.GetMonitorRelations',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def create_relations_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    apiid = args.get('apiid')
    apiversionid = args.get('apiversionid')
    contracttest = args.get('contracttest')
    testsuite = args.get('testsuite')
    documentation = args.get('documentation')
    mock = args.get('mock')

    response = client.create_relations_request(apiid, apiversionid, contracttest, testsuite, documentation, mock)
    command_results = CommandResults(
        outputs_prefix='PostmanAPI.CreateRelations',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def sync_relations_with_schema_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    apiid = args.get('apiid')
    apiversionid = args.get('apiversionid')
    entitytype = args.get('entitytype')
    entityid = args.get('entityid')

    response = client.sync_relations_with_schema_request(apiid, apiversionid, entitytype, entityid)
    command_results = CommandResults(
        outputs_prefix='PostmanAPI.SyncRelationsWithSchema',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def create_api_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    workspace = args.get('workspace')
    name = args.get('name')
    summary = args.get('summary')
    description = args.get('description')

    response = client.create_api_request(workspace, name, summary, description)
    command_results = CommandResults(
        outputs_prefix='PostmanAPI.CreateApi',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def update_an_api_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    apiid = args.get('apiid')
    name = args.get('name')
    description = args.get('description')

    response = client.update_an_api_request(apiid, name, description)
    command_results = CommandResults(
        outputs_prefix='PostmanAPI.UpdateAnApi',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def delete_an_api_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    apiid = args.get('apiid')

    response = client.delete_an_api_request(apiid)
    command_results = CommandResults(
        outputs_prefix='PostmanAPI.DeleteAnApi',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_all_apis_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    workspace = args.get('workspace')
    since = args.get('since')
    until = args.get('until')
    createdby = args.get('createdby')
    updatedby = args.get('updatedby')
    ispublic = args.get('ispublic')
    name = args.get('name')
    summary = args.get('summary')
    description = args.get('description')
    sort = args.get('sort')
    direction = args.get('direction')

    response = client.get_all_apis_request(workspace, since, until, createdby,
                                           updatedby, ispublic, name, summary, description, sort, direction)
    command_results = CommandResults(
        outputs_prefix='PostmanAPI.GetAllApis',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def single_api_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    apiid = args.get('apiid')

    response = client.single_api_request(apiid)
    command_results = CommandResults(
        outputs_prefix='PostmanAPI.SingleApi',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def create_webhook_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    workspace = args.get('workspace')
    name = args.get('name')
    collection = args.get('collection')

    response = client.create_webhook_request(workspace, name, collection)
    command_results = CommandResults(
        outputs_prefix='PostmanAPI.CreateWebhook',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def fetch_user_resource_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    id_ = args.get('id')

    response = client.fetch_user_resource_request(id_)
    command_results = CommandResults(
        outputs_prefix='PostmanAPI.FetchUserResource',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def fetch_all_user_resource_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    startindex = args.get('startindex')
    count = args.get('count')
    filter_ = args.get('filter')

    response = client.fetch_all_user_resource_request(startindex, count, filter_)
    command_results = CommandResults(
        outputs_prefix='PostmanAPI.FetchAllUserResource',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def create_user_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    schemas = args.get('schemas')
    username = args.get('username')
    givenname = args.get('givenname')
    familyname = args.get('familyname')
    externalid = args.get('externalid')
    locale = args.get('locale')
    active = args.get('active')

    response = client.create_user_request(schemas, username, givenname, familyname, externalid, locale, active)
    command_results = CommandResults(
        outputs_prefix='PostmanAPI.CreateUser',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def update_user_information_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    id_ = args.get('id')
    schemas = args.get('schemas')
    username = args.get('username')
    givenname = args.get('givenname')
    familyname = args.get('familyname')
    externalid = args.get('externalid')
    locale = args.get('locale')
    active = args.get('active')

    response = client.update_user_information_request(
        id_, schemas, username, givenname, familyname, externalid, locale, active)
    command_results = CommandResults(
        outputs_prefix='PostmanAPI.UpdateUserInformation',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def update_team_user_information_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    id_ = args.get('id')
    schemas = args.get('schemas')
    op = args.get('op')
    active = args.get('active')

    response = client.update_team_user_information_request(id_, schemas, op, active)
    command_results = CommandResults(
        outputs_prefix='PostmanAPI.UpdateTeamUserInformation',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def service_provider_config_command(client: Client, args: Dict[str, Any]) -> CommandResults:

    response = client.service_provider_config_request()
    command_results = CommandResults(
        outputs_prefix='PostmanAPI.ServiceProviderConfig',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_resourcetypes_command(client: Client, args: Dict[str, Any]) -> CommandResults:

    response = client.get_resourcetypes_request()
    command_results = CommandResults(
        outputs_prefix='PostmanAPI.GetResourcetypes',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def test_module(client: Client) -> None:
    # Test functions here
    return_results('ok')


def main() -> None:

    params: Dict[str, Any] = demisto.params()
    args: Dict[str, Any] = demisto.args()
    url = params.get('url')
    verify_certificate: bool = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    headers = {}
    headers['X-API-Key'] = params['api_key']

    command = demisto.command()
    demisto.debug(f'Command being called is {command}')

    try:
        requests.packages.urllib3.disable_warnings()
        client: Client = Client(urljoin(url, ''), verify_certificate, proxy, headers=headers, auth=None)

        commands = {
            'postmanapi-all-collections': all_collections_command,
            'postmanapi-single-collection': single_collection_command,
            'postmanapi-create-collection': create_collection_command,
            'postmanapi-update-collection': update_collection_command,
            'postmanapi-delete-collection': delete_collection_command,
            'postmanapi-create-a-fork': create_a_fork_command,
            'postmanapi-merge-a-fork': merge_a_fork_command,
            'postmanapi-all-environments': all_environments_command,
            'postmanapi-single-environment': single_environment_command,
            'postmanapi-create-environment': create_environment_command,
            'postmanapi-update-environment': update_environment_command,
            'postmanapi-delete-environment': delete_environment_command,
            'postmanapi-all-mocks': all_mocks_command,
            'postmanapi-single-mock': single_mock_command,
            'postmanapi-create-mock': create_mock_command,
            'postmanapi-update-mock': update_mock_command,
            'postmanapi-delete-mock': delete_mock_command,
            'postmanapi-publish-mock': publish_mock_command,
            'postmanapi-unpublish-mock': unpublish_mock_command,
            'postmanapi-all-monitors': all_monitors_command,
            'postmanapi-single-monitor': single_monitor_command,
            'postmanapi-create-monitor': create_monitor_command,
            'postmanapi-update-monitor': update_monitor_command,
            'postmanapi-delete-monitor': delete_monitor_command,
            'postmanapi-run-a-monitor': run_a_monitor_command,
            'postmanapi-all-workspaces': all_workspaces_command,
            'postmanapi-single-workspace': single_workspace_command,
            'postmanapi-create-workspace': create_workspace_command,
            'postmanapi-update-workspace': update_workspace_command,
            'postmanapi-delete-workspace': delete_workspace_command,
            'postmanapi-api-key-owner': api_key_owner_command,
            'postmanapi-import-external-api-specification': import_external_api_specification_command,
            'postmanapi-import-exported-data': import_exported_data_command,
            'postmanapi-create-api-version': create_api_version_command,
            'postmanapi-update-an-api-version': update_an_api_version_command,
            'postmanapi-delete-an-api-version': delete_an_api_version_command,
            'postmanapi-get-an-api-version': get_an_api_version_command,
            'postmanapi-get-all-api-versions': get_all_api_versions_command,
            'postmanapi-create-schema': create_schema_command,
            'postmanapi-update-schema': update_schema_command,
            'postmanapi-get-schema': get_schema_command,
            'postmanapi-create-collection-from-schema': create_collection_from_schema_command,
            'postmanapi-get-linked-relations': get_linked_relations_command,
            'postmanapi-get-documentation-relations': get_documentation_relations_command,
            'postmanapi-get-environment-relations': get_environment_relations_command,
            'postmanapi-get-test-suite-relations': get_test_suite_relations_command,
            'postmanapi-get-contract-test-relations': get_contract_test_relations_command,
            'postmanapi-get-integration-test-relations': get_integration_test_relations_command,
            'postmanapi-get-monitor-relations': get_monitor_relations_command,
            'postmanapi-create-relations': create_relations_command,
            'postmanapi-sync-relations-with-schema': sync_relations_with_schema_command,
            'postmanapi-create-api': create_api_command,
            'postmanapi-update-an-api': update_an_api_command,
            'postmanapi-delete-an-api': delete_an_api_command,
            'postmanapi-get-all-apis': get_all_apis_command,
            'postmanapi-single-api': single_api_command,
            'postmanapi-create-webhook': create_webhook_command,
            'postmanapi-fetch-user-resource': fetch_user_resource_command,
            'postmanapi-fetch-all-user-resource': fetch_all_user_resource_command,
            'postmanapi-create-user': create_user_command,
            'postmanapi-update-team-user-information': update_team_user_information_command,
            'postmanapi-update-user-information': update_user_information_command,
            'postmanapi-service-provider-config': service_provider_config_command,
            'postmanapi-get-resourcetypes': get_resourcetypes_command,
        }

        if command == 'test-module':
            test_module(client)
        elif command in commands:
            return_results(commands[command](client, args))
        else:
            raise NotImplementedError(f'{command} command is not implemented.')

    except Exception as e:
        return_error(str(e))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
