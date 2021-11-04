# type: ignore
# Disable insecure warnings
from CommonServerPython import *

''' IMPORTS '''
import uuid
from typing import Dict, List
import requests
from azure.kusto.data.response import KustoResponseDataSet, KustoResponseDataSetV1
from datetime import datetime

''' CONSTANTS '''
MANAGEMENT_URL_SUFFIX = "/v1/rest/mgmt"
DEFAULT_PAGE_NUMBER = '1'
DEFAULT_PAGE_SIZE = '50'
DATE_TIME_FORMAT = '%Y-%m-%dT%H:%M:%S'


class DataExplorerClient:
    """
        Azure Data Explorer API Client.
    """

    def __init__(self, cluster_url: str, client_id: str, client_activity_prefix: str, verify: bool, proxy: bool):
        self.cluster_url = cluster_url
        self.host = cluster_url.split("https://")[1]
        self.scope = f'{cluster_url}/user_impersonation offline_access user.read'
        self.client_activity_prefix = client_activity_prefix
        self.ms_client = MicrosoftClient(
            self_deployed=True,
            auth_id=client_id,
            token_retrieval_url='https://login.microsoftonline.com/organizations/oauth2/v2.0/token',
            grant_type=DEVICE_CODE,
            base_url=cluster_url,
            verify=verify,
            proxy=proxy,
            scope=self.scope
        )

    def http_request(self, method, url_suffix: str = None, full_url: str = None, params: dict = None, headers=None,
                     data=None, timeout: int = 20):
        if headers is None:
            headers = {}
        if data is None:
            data = {}
        headers.update({
            'Accept': 'application/json',
            'Expect': '100-Continue',
            'Content-Type': 'application/json; charset=utf-8',
            'Host': self.host,
            'Connection': 'Keep-Alive',
        })

        res = self.ms_client.http_request(method=method,
                                          url_suffix=url_suffix,
                                          full_url=full_url,
                                          headers=headers,
                                          json_data=data,
                                          params=params,
                                          resp_type='response',
                                          timeout=timeout)
        if res.status_code in (200, 204) and not res.text:
            return res

        res_json = res.json()

        if res.status_code in (400, 401, 403, 404, 409):
            code = res_json.get('error', {}).get('code', 'Error')
            error_msg = res_json.get('error', {}).get('message', res_json)
            raise ValueError(
                f'[{code} {res.status_code}] {error_msg}'
            )

        return res_json

    def search_query_execute_request(self, database_name: str, query: str,
                                     server_timeout: int, client_activity_id: str) -> Dict[str, Any]:
        """
            Execute a KQL query against the given database inside the specified cluster.
            The query's client activity ID is a combination of the user's
            client_activity_prefix parameter and a random UUID.
        Args:
            database_name (str): The name of the database to execute the query on.
            query (str): The KQL query to execute against the database.
            server_timeout: Query execution timeout on server side.
            client_activity_id (str): A unique ID for query execution.
        Returns:
            Dict[str,Any]: API response from Azure.
        """
        data = {
            "db": database_name,
            "csl": query,
            "properties": {
                "Options": {
                    "servertimeout": f"{server_timeout}m"
                }
            }
        }

        headers = {
            "x-ms-client-request-id": client_activity_id
        }

        response = self.http_request(
            "POST", url_suffix="/v1/rest/query", data=data, headers=headers)
        return response

    def search_queries_list_request(self, database_name: str,
                                    client_activity_id: str) -> Dict[str, Any]:

        """
            List search queries that have reached a final state on the given database.
            When the client_activity_id argument is provided, the request will retrieve information
            regarding specific search query.

        Args:
            database_name (str): The name of the database to see the completed queries.
            client_activity_id (str):  client-specified identity of the request.

        Returns:
            Dict[str, Any]: API response from Azure.
        """
        mgmt_query = f".show queries | where ClientActivityId=='{client_activity_id}'" if client_activity_id \
            else ".show queries | sort by StartedOn"
        data = {
            "db": database_name,
            "csl": mgmt_query
        }
        response = self.http_request(
            "POST", url_suffix=MANAGEMENT_URL_SUFFIX, data=data)
        return response

    def running_search_queries_list_request(self, database_name: str, client_activity_id: str) -> \
            Dict[str, Any]:
        """
            List currently running search queries on the given database.
            When client_activity_id argument is set, the request will retrieve information
            regarding specific running search query.

        Args:
            database_name (str): The name of the database to see the running queries.
            client_activity_id (str): Client-specified identity of the request.

        Returns:
            Dict[str, Any]: API response from Azure.
        """
        mgmt_query = f".show running queries | where ClientActivityId=='{client_activity_id}'" if client_activity_id \
            else ".show running queries | sort by StartedOn"

        data = {
            "db": database_name,
            "csl": mgmt_query
        }
        response = self.http_request(
            "POST", url_suffix=MANAGEMENT_URL_SUFFIX, data=data)
        return response

    def running_search_query_delete_request(self, database_name: str, client_activity_id: str,
                                            reason: str) -> Dict[str, Any]:
        """
        Starts a best-effort attempt to cancel a specific running search query
        on the given database.

        Args:
            database_name (str): The name of the database to see the completed queries on.
            client_activity_id (str):  Client specified identity of the request.
            reason (str): The reason for the cancellation.
        Returns:
            Dict[str, Any]: API response from Azure.
        """
        cancel_running_query = f".cancel query '{client_activity_id}'"

        if reason:
            cancel_running_query += f" with ( reason = '{reason}' )"
        data = {
            "db": database_name,
            "csl": cancel_running_query
        }

        response = self.http_request("POST", url_suffix=MANAGEMENT_URL_SUFFIX, data=data)
        return response


def search_query_execute_command(client: DataExplorerClient, args: Dict[str, Any]) -> CommandResults:
    """
    Execute search query command.
    Args:
        client (DataExplorerClient): Azure Data Explorer API client.
        args (Dict[str, Any]): Command arguments from XSOAR.
    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.

    """
    query = str(args['query'])
    database_name = str(args['database_name'])
    timeout = arg_to_number(args.get('timeout', '5'))
    if timeout < 1 or timeout > 60:
        raise ValueError("Timeout argument should be a number between 1 to 60.")

    client_activity_id = f"{client.client_activity_prefix};{uuid.uuid4()}"
    response = client.search_query_execute_request(database_name, query, timeout, client_activity_id)
    response_kusto_dataset = KustoResponseDataSetV1(response)
    primary_results = convert_kusto_response_to_dict(response_kusto_dataset)
    outputs = {
        'Query': query,
        'ClientActivityID': client_activity_id,
        'PrimaryResults': primary_results
    }
    readable_output = tableToMarkdown(
        f'Results of executing search query with client activity ID: {client_activity_id}',
        primary_results, headerTransform=pascalToSpace)
    command_results = CommandResults(
        outputs_prefix='AzureDataExplorer.SearchQueryResults',
        outputs_key_field='ClientActivityID',
        outputs=outputs,
        raw_response=response,
        readable_output=readable_output
    )

    return command_results


def search_queries_list_command(client: DataExplorerClient, args: Dict[str, Any]) -> CommandResults:
    """
    List completed search queries command.
    Args:
        client (DataExplorerClient): Azure Data Explorer API client.
        args (Dict[str, Any]): Command arguments from XSOAR.
    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.

    """

    database_name = str(args['database_name'])
    page = arg_to_number(args.get('page', DEFAULT_PAGE_NUMBER))
    limit = arg_to_number(args.get('limit', DEFAULT_PAGE_SIZE))
    client_activity_id = str(args.get('client_activity_id', ''))
    response = client.search_queries_list_request(
        database_name, client_activity_id)

    response_kusto_dataset = KustoResponseDataSetV1(response)
    total_rows = response_kusto_dataset.primary_results[0].rows_count
    total_pages = total_rows // limit + 1
    readable_header = build_header_for_list_commands('List of Completed Search Queries',
                                                     total_rows, total_pages, page, limit)
    outputs = convert_kusto_response_to_dict(response_kusto_dataset, page, limit)
    readable_output = tableToMarkdown(readable_header,
                                      outputs,
                                      headers=['ClientActivityId', 'User', 'Text',
                                               'Database', 'StartedOn',
                                               'LastUpdatedOn',
                                               'State'],
                                      headerTransform=pascalToSpace)

    command_results = CommandResults(
        outputs_prefix='AzureDataExplorer.SearchQuery',
        outputs_key_field='ClientActivityId',
        outputs=outputs,
        raw_response=response,
        readable_output=readable_output
    )

    return command_results


def running_search_queries_list_command(client: DataExplorerClient, args: Dict[str, Any]) -> CommandResults:
    """
    List currently running search queries command.
    Args:
        client (DataExplorerClient): Azure Data Explorer API client.
        args (Dict[str, Any]): Command arguments from XSOAR.
    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.

    """
    database_name = str(args['database_name'])
    page = arg_to_number(args.get('page', DEFAULT_PAGE_NUMBER))
    limit = arg_to_number(args.get('limit', DEFAULT_PAGE_SIZE))
    client_activity_id = str(args.get('client_activity_id', ''))

    response = client.running_search_queries_list_request(
        database_name, client_activity_id)

    response_kusto_dataset = KustoResponseDataSetV1(response)
    total_rows = response_kusto_dataset.primary_results[0].rows_count
    total_pages = total_rows // limit + 1
    outputs = convert_kusto_response_to_dict(response_kusto_dataset, page, limit)
    readable_header = build_header_for_list_commands('List of Currently running Search Queries',
                                                     total_rows, total_pages, page, limit)
    readable_output = tableToMarkdown(readable_header,
                                      outputs,
                                      headers=['ClientActivityId', 'User', 'Text',
                                               'Database', 'StartedOn',
                                               'LastUpdatedOn',
                                               'State'],
                                      headerTransform=pascalToSpace)
    command_results = CommandResults(
        outputs_prefix='AzureDataExplorer.RunningSearchQuery',
        outputs_key_field='ClientActivityId',
        outputs=outputs,
        raw_response=response,
        readable_output=readable_output
    )

    return command_results


def running_search_query_cancel_command(client: DataExplorerClient, args: Dict[str, Any]) -> \
        CommandResults:
    """
    Cancel currently running search query command.
    Args:
        client (DataExplorerClient): Azure Data Explorer API client.
        args (Dict[str, Any]): Command arguments from XSOAR.
    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.

    """
    client_activity_id = str(args['client_activity_id'])
    database_name = str(args['database_name'])
    reason = str(args.get('reason'))
    response = client.running_search_query_delete_request(
        database_name, client_activity_id, reason)

    response_kusto_dataset = KustoResponseDataSetV1(response)

    outputs = convert_kusto_response_to_dict(response_kusto_dataset)
    readable_output = tableToMarkdown(f'Canceled Search Query {client_activity_id}',
                                      outputs,
                                      headers=[
                                          'ClientRequestId', 'ReasonPhrase',
                                          'RunningQueryCanceled'],
                                      headerTransform=pascalToSpace)
    command_results = CommandResults(
        outputs_prefix='AzureDataExplorer.CanceledSearchQuery',
        outputs_key_field='ClientRequestId',
        outputs=outputs,
        raw_response=response,
        readable_output=readable_output
    )

    return command_results


''' INTEGRATION HELPER METHODS '''


def convert_datetime_fields(raw_data: List[dict]) -> List[dict]:
    """
    Converting datetime fields of the response from the API call
    to str type (in order to make the response json-serializable).

    Args:
        raw_data (List[dict]): Response from API call to azure.

    Returns:
         List[dict]: JSON serializable response from API.
    """
    for row in raw_data:
        for key, value in row.items():
            if isinstance(value, datetime):
                row[key] = value.strftime(DATE_TIME_FORMAT)
            if isinstance(value, timedelta):
                row[key] = str(value)
    return raw_data


def convert_kusto_response_to_dict(kusto_response: KustoResponseDataSet, page: int = None,
                                   limit: int = None) -> List[dict]:
    """
    Converting KustoResponseDataSet object to dict type.

    Args:
        kusto_response (KustoResponseDataSet): The response from API call.
        page (int): First index to retrieve from.
        limit (int): Limit on the number of the results to return.

    Returns:
        Dict[str, Any]: Converted response.
    """
    raw_data = kusto_response.primary_results[0].to_dict()['data']
    if page and limit:
        from_index = min((page - 1) * limit, len(raw_data))
        to_index = min(from_index + limit, len(raw_data))
        relevant_raw_data = raw_data[from_index:to_index]
    else:
        relevant_raw_data = raw_data
    serialized_data: List[dict] = convert_datetime_fields(relevant_raw_data)
    return serialized_data


def build_header_for_list_commands(base_header: str, rows_count: int, total_pages: int,
                                   page: int, limit: int) -> str:
    """
    Retrieve the header of the readable output for list commands.

    Args:
        base_header (str): The header prefix.
        rows_count (int): The number of rows in the output.
        total_pages (int): Total number of pages.
        page (int): Client's page number argument.
        limit (int): Client's limit argument.
    Returns:
        Dict[str, Any]: Header for readable output of the command.
    """
    if rows_count > 0:
        base_header += f' \nShowing page {page} out of {total_pages} total pages.' \
                       f' Current page size: {limit}.'

    return base_header


''' AUTHORIZATION METHODS '''


def start_auth(client: DataExplorerClient) -> CommandResults:
    """
    Start the authorization process.

    Args:
        client (DataExplorerClient): Azure Data Explorer API client.

    Returns:
        CommandResults: authentication guidelines.
    """
    result = client.ms_client.start_auth('!azure-data-explorer-auth-complete')
    return CommandResults(readable_output=result)


def complete_auth(client: DataExplorerClient) -> str:
    """
    Start the authorization process.

    Args:
        client (DataExplorerClient): Azure Data Explorer API client.

    Returns:
          str: Message about completing the authorization process successfully.
    """
    client.ms_client.get_access_token()
    return 'Authorization completed successfully.'


def reset_auth() -> str:
    """
    Start the authorization process.
    Returns:
          str: Message about resetting the authorization process.
    """
    set_integration_context({})
    return 'Authorization was reset successfully. Run **!azure-data-explorer-auth-start** to start the authentication \
    process.'


def test_connection(client: DataExplorerClient) -> str:
    """
    Test the connection with Azure Data Explorer service.

    Args:
        client (DataExplorerClient): Azure Data Explorer API client.

    Returns:
          str: Message about successfully connected to the Azure Data Explorer.
    """
    client.ms_client.get_access_token()
    return 'Success!'


def main() -> None:
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params: Dict[str, Any] = demisto.params()
    args: Dict[str, Any] = demisto.args()
    cluster_url = params['cluster_url']
    client_id = params['client_id']
    client_activity_prefix = params.get('client_activity_prefix')
    verify_certificate: bool = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    command = demisto.command()
    demisto.debug(f'Command being called is {command}')

    try:
        requests.packages.urllib3.disable_warnings()
        client: DataExplorerClient = DataExplorerClient(cluster_url, client_id, client_activity_prefix,
                                                        verify_certificate,
                                                        proxy)

        commands = {
            'azure-data-explorer-search-query-execute': search_query_execute_command,
            'azure-data-explorer-search-query-list': search_queries_list_command,
            'azure-data-explorer-running-search-query-list': running_search_queries_list_command,
            'azure-data-explorer-running-search-query-cancel': running_search_query_cancel_command,
        }

        if command == 'test-module':
            return_results(
                'The test module is not functional,'
                ' run the azure-data-explorer-auth-start command instead.')
        elif command == 'azure-data-explorer-auth-start':
            return_results(start_auth(client))
        elif command == 'azure-data-explorer-auth-complete':
            return_results(complete_auth(client))
        elif command == 'azure-data-explorer-auth-reset':
            return_results(reset_auth())
        elif command == 'azure-data-explorer-auth-test':
            return_results(test_connection(client))
        elif command in commands:
            return_results(commands[command](client, args))

        else:
            raise NotImplementedError(f'{command} command is not implemented.')

    except Exception as e:
        if "OneApiErrors" in str(e):
            return_error("The execution of search query failed"
                         " due a client cancel request.")
        else:
            return_error(str(e))


from MicrosoftApiModule import *  # noqa: E402

if __name__ == "__builtin__" or __name__ == "builtins":
    main()
