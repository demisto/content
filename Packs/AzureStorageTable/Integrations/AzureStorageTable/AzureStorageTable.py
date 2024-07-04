import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import copy
import urllib3
from requests import Response

DATE_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'
account_sas_token = ""
storage_account_name = ""


class Client:
    """
    API Client
    """

    def __init__(self, server_url, verify, proxy, account_sas_token, storage_account_name,
                 api_version, managed_identities_client_id: Optional[str] = None):
        self.ms_client = MicrosoftStorageClient(server_url, verify, proxy, account_sas_token, storage_account_name,
                                                api_version,
                                                managed_identities_client_id)

    def create_table_request(self, table_name: str) -> dict:
        """
        Creates a new table in a storage account.

        Args:
            table_name (str): Table name.

        Returns:
            dict: API response from Azure.

        """
        headers = {'Content-Type': 'application/json',
                   'Accept': 'application/json;odata=nometadata'}

        data = {"TableName": table_name}

        response = self.ms_client.http_request(method='POST', url_suffix='Tables', headers=headers, resp_type="json",
                                               json_data=data)

        return response

    def delete_table_request(self, table_name: str) -> Response:
        """
        Delete the specified table and any data it contains.

        Args:
            table_name (str): Table name.

        Returns:
            Response: API response from Azure.

        """
        url_suffix = f'Tables(\'{table_name}\')'

        response = self.ms_client.http_request(method='DELETE', url_suffix=url_suffix, return_empty_response=True)

        return response

    def query_tables_request(self, limit: str = None, query_filter: str = None, next_table: str = None) -> Response:
        """
        List tables under the specified account.

        Args:
            limit (str): Retrieve top n tables.
            query_filter (str): Query expression.
            next_table (str): Identifies the portion of the list to be returned.

        Returns:
            Response: API response from Azure.

        """
        headers = {'Accept': 'application/json;odata=nometadata'}

        params = remove_empty_elements({"$top": limit, "$filter": query_filter, "NextTableName": next_table})

        response = self.ms_client.http_request(method='GET', url_suffix='Tables', headers=headers, params=params,
                                               return_empty_response=True)

        return response

    def insert_entity_request(self, table_name: str, entity_fields: dict) -> dict:
        """
        Insert a new entity into a table.

        Args:
            table_name (str): Table name.
            entity_fields (dict): Entity fields data.

        Returns:
            dict: API response from Azure.

        """
        headers = {'Content-Type': 'application/json',
                   'Accept': 'application/json;odata=nometadata'}

        response = self.ms_client.http_request(method='POST', url_suffix=f'{table_name}', headers=headers,
                                               resp_type="json", json_data=entity_fields)

        return response

    def update_entity_request(self, table_name: str, partition_key: str, row_key: str, entity_fields: dict) -> Response:
        """
        Update an existing entity in a table.

        Args:
            table_name (str): Table name.
            partition_key (str): Unique identifier for the partition within a given table.
            row_key (str): Unique identifier for an entity within a given partition.
            entity_fields (dict): Entity fields data.

        Returns:
            Response: API response from Azure.

        """

        headers = {'Content-Type': 'application/json'}

        url_suffix = f'{table_name}(PartitionKey=\'{partition_key}\',RowKey=\'{row_key}\')'

        response = self.ms_client.http_request(method='MERGE', url_suffix=url_suffix,
                                               headers=headers, return_empty_response=True, json_data=entity_fields)

        return response

    def replace_entity_request(self, table_name: str, partition_key: str, row_key: str,
                               entity_fields: dict) -> Response:
        """
        Replace an existing entity in a table.

        Args:
            table_name (str): Table name.
            partition_key (str): Unique identifier for the partition within a given table.
            row_key (str): Unique identifier for an entity within a given partition.
            entity_fields (dict): Entity fields data.

        Returns:
            Response: API response from Azure.

        """
        headers = {'Content-Type': 'application/json'}

        url_suffix = f'{table_name}(PartitionKey=\'{partition_key}\',RowKey=\'{row_key}\')'

        response = self.ms_client.http_request(method='PUT', url_suffix=url_suffix,
                                               headers=headers, return_empty_response=True, json_data=entity_fields)

        return response

    def query_entity_request(self, table_name: str, partition_key: str = None, row_key: str = None,
                             query_filter: str = None, select: str = None, limit: str = None,
                             next_partition_key: str = None, next_row_key: str = None) -> Response:
        """
        Query entities in a table.

        Args:
            table_name (str): Table name.
            partition_key (str): Unique identifier for the partition within a given table.
            row_key (str): Unique identifier for an entity within a given partition.
            query_filter (str): Query expression.
            select (str): Entity properties to return.
            limit (str): Retrieve top n entities.
            next_partition_key (str): Identifies the portion of the list to be returned.
            next_row_key (str): Identifies the portion of the list to be returned.

        Returns:
            Response: API response from Azure.

        """
        headers = {'Accept': 'application/json;odata=nometadata'}

        params = remove_empty_elements({"$filter": query_filter,
                                        "$select": select,
                                        "$top": limit,
                                        "NextPartitionKey": next_partition_key,
                                        "NextRowKey": next_row_key})

        url_suffix = f'{table_name}(PartitionKey=\'{partition_key}\',RowKey=\'{row_key}\')' if partition_key \
            else f'{table_name}()'

        response = self.ms_client.http_request(method='GET', url_suffix=url_suffix,
                                               params=params, headers=headers, return_empty_response=True)

        return response

    def delete_entity_request(self, table_name: str, partition_key: str, row_key: str) -> Response:
        """
        Delete an existing entity in a table

        Args:
            table_name (str): Table name.
            partition_key (str): Unique identifier for the partition within a given table.
            row_key (str): Unique identifier for an entity within a given partition.

        Returns:
            Response: API response from Azure.

        """
        headers = {"If-Match": "*"}

        url_suffix = f'{table_name}(PartitionKey=\'{partition_key}\',RowKey=\'{row_key}\')'

        response = self.ms_client.http_request(method='DELETE', url_suffix=url_suffix, headers=headers,
                                               return_empty_response=True)

        return response


def create_table_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Creates a new table in a storage account.

    Args:
        client (Client): Azure Table Storage API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    table_name = args['table_name']

    table_name_regex = "^[A-Za-z][A-Za-z0-9]{2,62}$"
    # Rules for naming tables can be found here:
    # https://docs.microsoft.com/en-us/rest/api/storageservices/understanding-the-table-service-data-model

    if not re.search(table_name_regex, table_name):
        raise Exception('The specified table name is invalid.')

    response = client.create_table_request(table_name)
    outputs = {"name": response.get("TableName")}

    command_results = CommandResults(
        readable_output=f'Table {table_name} successfully created.',
        outputs_prefix='AzureStorageTable.Table',
        outputs_key_field='name',
        outputs=outputs,
        raw_response=response
    )

    return command_results


def delete_table_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Delete the specified table and any data it contains.

    Args:
        client (Client): Azure Table Storage API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    table_name = args['table_name']

    client.delete_table_request(table_name)
    command_results = CommandResults(
        readable_output=f'Table {table_name} successfully deleted.'
    )

    return command_results


def query_tables_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    List tables under the specified account.

    Args:
        client (Client): Azure Table Storage API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    limit = args.get('limit') or '50'
    query_filter = args.get('filter')
    page = arg_to_number(args.get('page') or '1')
    next_table = None

    readable_message = f'Tables List:\n Current page size: {limit}\n Showing page {page} out others that may exist'

    if page > 1:  # type: ignore
        offset = int(limit) * (page - 1)  # type: ignore
        response = client.query_tables_request(str(offset), query_filter)

        response_headers = response.headers
        next_table = response_headers.get('x-ms-continuation-NextTableName')

        if not next_table:
            return CommandResults(
                readable_output=readable_message,
                outputs_prefix='AzureStorageTable.Table',
                outputs=[],
                raw_response=[]
            )

    raw_response = client.query_tables_request(limit, query_filter, next_table).json()

    outputs = []
    for table in raw_response.get("value"):
        outputs.append({"name": table.get("TableName")})

    readable_output = tableToMarkdown(
        readable_message,
        outputs,
        headerTransform=pascalToSpace
    )
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='AzureStorageTable.Table',
        outputs_key_field='name',
        outputs=outputs,
        raw_response=raw_response
    )

    return command_results


def convert_dict_time_format(data: dict, keys: list):
    """
    Convert dictionary data values time format.
    Args:
        data (dict): Data.
        keys (list): Keys list to convert

    """
    for key in keys:
        if data.get(key):
            str_time = data.get(key)[:-2] + 'Z'  # type: ignore
            iso_time = FormatIso8601(datetime.strptime(str_time, DATE_FORMAT))
            data[key] = iso_time


def insert_entity_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Insert a new entity into a table.

    Args:
        client (Client): Azure Table Storage API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    table_name = args['table_name']
    partition_key = args['partition_key']
    row_key = args['row_key']
    entity_fields = args['entity_fields']

    try:
        entity_fields = json.loads(entity_fields)
    except ValueError:
        raise ValueError('Failed to parse entity_fields argument. Please provide valid JSON format entity data.')

    entity_fields['PartitionKey'] = partition_key
    entity_fields['RowKey'] = row_key

    response = client.insert_entity_request(table_name, entity_fields)

    outputs = {"name": table_name, "Entity": [copy.deepcopy(response)]}

    convert_dict_time_format(outputs.get('Entity')[0], ['Timestamp'])  # type: ignore

    readable_output = tableToMarkdown(
        f'Entity Fields for {table_name} Table:',
        outputs.get('Entity'),
        headerTransform=pascalToSpace
    )

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='AzureStorageTable.Table',
        outputs_key_field='name',
        outputs=outputs,
        raw_response=response
    )

    return command_results


def replace_entity_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Replace an existing entity in a table.
    The Replace Entity operation replace the entire entity and can be used to remove properties.

    Args:
        client (Client): Azure Table Storage API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    table_name = args['table_name']
    partition_key = args['partition_key']
    row_key = args['row_key']
    entity_fields = args['entity_fields']

    try:
        entity_fields = json.loads(entity_fields)
    except ValueError:
        raise ValueError('Failed to parse entity_fields argument. Please provide valid JSON format entity data.')

    client.replace_entity_request(table_name, partition_key, row_key, entity_fields)
    command_results = CommandResults(
        readable_output=f'Entity in {table_name} table successfully replaced.'
    )

    return command_results


def update_entity_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Update an existing entity in a table.
    This operation does not replace the existing entity.

    Args:
        client (Client): Azure Table Storage API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """

    table_name = args['table_name']
    partition_key = args['partition_key']
    row_key = args['row_key']
    entity_fields = args['entity_fields']

    try:
        entity_fields = json.loads(entity_fields)
    except ValueError:
        raise ValueError('Failed to parse entity_fields argument. Please provide valid JSON format entity data.')

    client.update_entity_request(table_name, partition_key, row_key, entity_fields)
    command_results = CommandResults(
        readable_output=f'Entity in {table_name} table successfully updated.'
    )

    return command_results


def create_query_entity_output(table_name: str, raw_response: dict, is_entity_query: bool) -> dict:
    """
    Create query_entity_command outputs.
    Args:
        table_name (str): Command table name.
        raw_response (str): API response from Azure.
        is_entity_query (bool): Indicates to path to the response data.

    Returns:
        dict: Command response.

    """
    outputs = {"name": table_name}
    response_copy = copy.deepcopy(raw_response)

    if is_entity_query:
        outputs["Entity"] = [response_copy]  # type: ignore
    else:
        outputs["Entity"] = response_copy.get('value')  # type: ignore

    for entity in outputs.get("Entity"):  # type: ignore
        convert_dict_time_format(entity, ['Timestamp'])  # type: ignore

    return outputs


def query_entity_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Query entities in a table.

    Args:
        client (Client): Azure Table Storage API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    table_name = args['table_name']
    partition_key = args.get('partition_key')
    row_key = args.get('row_key')
    query_filter = args.get('filter')
    select = args.get('select')
    limit = None if partition_key else args.get('limit') or '50'
    page = None if partition_key else arg_to_number(args.get('page') or '1')
    next_partition_key = None
    next_row_key = None

    if (partition_key and not row_key) or (row_key and not partition_key):
        raise Exception('Please provide both \'partition_key\' and \'row_key\' arguments, or no one of them.')

    readable_message = f'Entity Fields for {table_name} table:\n Current page size: {limit or 50}\n ' \
                       f'Showing page {page or 1} out others that may exist'

    if page and page > 1:
        offset = int(limit) * (page - 1)  # type: ignore
        response = client.query_entity_request(table_name, partition_key, row_key, query_filter, select, str(offset))

        response_headers = response.headers
        next_partition_key = response_headers.get('x-ms-continuation-NextPartitionKey')
        next_row_key = response_headers.get('x-ms-continuation-NextRowKey')

        if not next_partition_key:
            return CommandResults(
                readable_output=readable_message,
                outputs_prefix='AzureStorageTable.Table',
                outputs=[],
                raw_response=[]
            )

    raw_response = client.query_entity_request(table_name, partition_key, row_key, query_filter, select, limit,
                                               next_partition_key, next_row_key).json()

    outputs = create_query_entity_output(table_name, raw_response, is_entity_query=partition_key is not None)

    readable_output = tableToMarkdown(
        readable_message,
        outputs.get("Entity"),
        headerTransform=pascalToSpace
    )

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='AzureStorageTable.Table',
        outputs_key_field='name',
        outputs=outputs,
        raw_response=raw_response
    )

    return command_results


def delete_entity_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Delete an existing entity in a table

    Args:
        client (Client): Azure Table Storage API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    Returns:

    """
    table_name = args['table_name']
    partition_key = args['partition_key']
    row_key = args['row_key']

    client.delete_entity_request(table_name, partition_key, row_key)
    command_results = CommandResults(
        readable_output=f'Entity in {table_name} table successfully deleted.'
    )

    return command_results


def test_module(client: Client) -> None:
    """
    Tests API connectivity and authentication.

    Args:
        client (Client): Azure Table API client.
    Returns:
        str : 'ok' if test passed, anything else will fail the test.
    """
    try:
        client.query_tables_request()
    except Exception as exception:
        if 'ResourceNotFound' in str(exception):
            return return_results('Authorization Error: make sure API Credentials are correctly set')

        if 'Error Type' in str(exception) or not client.ms_client._storage_account_name:
            return return_results(
                'Verify that the storage account name is correct and that you have access to the server from your host.')

        raise exception

    return_results('ok')
    return None


def main() -> None:
    """
    Main function
    """
    params: Dict[str, Any] = demisto.params()
    args: Dict[str, Any] = demisto.args()
    verify_certificate: bool = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    global account_sas_token
    global storage_account_name
    account_sas_token = params.get('credentials', {}).get('password')
    storage_account_name = params['credentials']['identifier']
    api_version = "2020-10-02"
    base_url = f'https://{storage_account_name}.table.core.windows.net/'
    managed_identities_client_id = get_azure_managed_identities_client_id(params)

    command = demisto.command()
    demisto.debug(f'Command being called is {command}')

    try:
        urllib3.disable_warnings()
        client: Client = Client(base_url, verify_certificate, proxy, account_sas_token, storage_account_name,
                                api_version, managed_identities_client_id)

        commands = {
            'azure-storage-table-create': create_table_command,
            'azure-storage-table-delete': delete_table_command,
            'azure-storage-table-query': query_tables_command,
            'azure-storage-table-entity-insert': insert_entity_command,
            'azure-storage-table-entity-update': update_entity_command,
            'azure-storage-table-entity-query': query_entity_command,
            'azure-storage-table-entity-delete': delete_entity_command,
            'azure-storage-table-entity-replace': replace_entity_command,
        }

        if command == 'test-module':
            test_module(client)
        elif command in commands:
            return_results(commands[command](client, args))
        else:
            raise NotImplementedError(f'{command} command is not implemented.')

    except Exception as e:
        return_error(str(e))


from MicrosoftAzureStorageApiModule import *  # noqa: E402

if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
