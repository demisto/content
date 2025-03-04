from CommonServerPython import *

""" IMPORTS """
import uuid
from decimal import Decimal
import requests
from azure.kusto.data.response import KustoResponseDataSet, KustoResponseDataSetV1
from datetime import datetime
from MicrosoftApiModule import *  # noqa: E402

""" CONSTANTS """
DEFAULT_PAGE_NUMBER = "1"
DEFAULT_LIMIT = "50"
DATE_TIME_FORMAT = "%Y-%m-%dT%H:%M:%S"
REQUEST_BASE_TIMEOUT = 20
GRANT_BY_CONNECTION = {
    "Device Code": DEVICE_CODE,
    "Authorization Code": AUTHORIZATION_CODE,
    "Client Credentials": CLIENT_CREDENTIALS,
}


class DataExplorerClient:
    """
    Azure Data Explorer API Client.
    """

    def __init__(
        self,
        cluster_url: str,
        client_id: str,
        client_activity_prefix: str,
        verify: bool,
        proxy: bool,
        connection_type: str,
        tenant_id: str = None,
        enc_key: str = None,
        auth_code: str = None,
        redirect_uri: str = None,
    ):
        if "@" in client_id:  # for use in test-playbook
            client_id, refresh_token = client_id.split("@")
            integration_context = get_integration_context()
            integration_context.update(current_refresh_token=refresh_token)
            set_integration_context(integration_context)

        if not cluster_url.startswith("https://"):
            raise ValueError("Cluster URL parameter must contain " "'https://' as prefix (e.g. https://help.kusto.windows.net).")

        self.cluster_url = cluster_url
        self.host = cluster_url.split("https://")[1]

        self.scope = (
            f"{cluster_url}/user_impersonation offline_access user.read"
            if "Device Code" in connection_type
            else f"{cluster_url}/.default"
        )
        self.client_activity_prefix = client_activity_prefix
        client_args = assign_params(
            self_deployed=True,
            auth_id=client_id,
            token_retrieval_url="https://login.microsoftonline.com/organizations/oauth2/v2.0/token"
            if "Device Code" in connection_type
            else None,
            grant_type=GRANT_BY_CONNECTION[connection_type],
            base_url=cluster_url,
            verify=verify,
            proxy=proxy,
            scope=self.scope,
            tenant_id=tenant_id,
            enc_key=enc_key,
            auth_code=auth_code,
            redirect_uri=redirect_uri,
            command_prefix="azure-data-explorer",
        )
        self.ms_client = MicrosoftClient(**client_args)
        self.connection_type = connection_type

    def http_request(
        self,
        method,
        url_suffix: str = None,
        full_url: str = None,
        params: dict = None,
        headers=None,
        data=None,
        timeout: int = REQUEST_BASE_TIMEOUT,
    ):
        if headers is None:
            headers = {}
        if data is None:
            data = {}
        headers.update(
            {
                "Accept": "application/json",
                "Expect": "100-Continue",
                "Content-Type": "application/json; charset=utf-8",
                "Host": self.host,
                "Connection": "Keep-Alive",
            }
        )

        res = self.ms_client.http_request(
            method=method,
            url_suffix=url_suffix,
            full_url=full_url,
            headers=headers,
            json_data=data,
            params=params,
            resp_type="response",
            timeout=timeout,
            ok_codes=(200, 204, 400, 401, 403, 404, 409),
        )

        if res.status_code in (200, 204) and not res.text:
            return res

        res_json = res.json()

        if res.status_code in (400, 401, 403, 404, 409):
            code = res_json.get("error", {}).get("code", "Error")
            error_msg = res_json.get("error", {}).get("message", res_json)
            raise ValueError(f"[{code} {res.status_code}] {error_msg}")

        return res_json

    def search_query_execute_request(
        self, database_name: str, query: str, server_timeout: Decimal, client_activity_id: str
    ) -> dict[str, Any]:
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
        data = retrieve_common_request_body(database_name, query, {"Options": {"servertimeout": f"{server_timeout}m"}})
        headers = {"x-ms-client-request-id": client_activity_id}
        response = self.http_request(
            "POST",
            url_suffix="/v1/rest/query",
            data=data,
            headers=headers,
            timeout=calculate_total_request_timeout(server_timeout),
        )
        return response

    def search_queries_list_request(self, database_name: str, client_activity_id: str) -> dict[str, Any]:
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
        mgmt_query = (
            f".show queries | where ClientActivityId=='{client_activity_id}'"
            if client_activity_id
            else ".show queries | sort by StartedOn"
        )
        return self.management_query_request(database_name, mgmt_query)

    def running_search_queries_list_request(self, database_name: str, client_activity_id: str) -> dict[str, Any]:
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
        mgmt_query = (
            f".show running queries | where ClientActivityId=='{client_activity_id}'"
            if client_activity_id
            else ".show running queries | sort by StartedOn"
        )

        return self.management_query_request(database_name, mgmt_query)

    def running_search_query_delete_request(self, database_name: str, client_activity_id: str, reason: str) -> dict[str, Any]:
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
        return self.management_query_request(database_name, cancel_running_query)

    def management_query_request(self, database_name: str, mgmt_query: str) -> dict[str, Any]:
        """
         API call method for management query endpoint.
         Each requests that uses management query endpoint uses this method.
        Args:
            database_name (str): The name of the database to see the completed queries on.
            mgmt_query (str):  Client specified identity of the request.
        Returns:
            Dict[str, Any]: API response from Azure.
        """
        data = retrieve_common_request_body(database_name, mgmt_query)
        response = self.http_request("POST", url_suffix="/v1/rest/mgmt", data=data)
        return response


def search_query_execute_command(client: DataExplorerClient, args: dict[str, Any]) -> CommandResults:
    """
    Execute search query command.
    Args:
        client (DataExplorerClient): Azure Data Explorer API client.
        args (Dict[str, Any]): Command arguments from XSOAR.
    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.

    """
    query = str(args["query"])
    database_name = str(args["database_name"])
    timeout = Decimal(args.get("timeout", "5"))
    if timeout < 0 or timeout > 60:
        raise ValueError("Timeout argument should be a float number between 0 to 60.")

    client_activity_id = f"{client.client_activity_prefix};{uuid.uuid4()}"
    response = client.search_query_execute_request(database_name, query, timeout, client_activity_id)
    response_kusto_dataset = KustoResponseDataSetV1(response)
    primary_results = convert_kusto_response_to_dict(response_kusto_dataset)
    outputs = {
        "Database": database_name,
        "Query": query,
        "ClientActivityID": client_activity_id,
        "PrimaryResults": primary_results,
    }
    readable_output = tableToMarkdown(
        f"Results of executing search query with client activity ID: {client_activity_id}",
        primary_results,
        headerTransform=pascalToSpace,
    )
    command_results = CommandResults(
        outputs_prefix="AzureDataExplorer.SearchQueryResults",
        outputs_key_field="ClientActivityID",
        outputs=outputs,
        raw_response=response,
        readable_output=readable_output,
    )

    return command_results


def search_queries_list_command(client: DataExplorerClient, args: dict[str, Any]) -> CommandResults:
    """
    List completed search queries command.
    Args:
        client (DataExplorerClient): Azure Data Explorer API client.
        args (Dict[str, Any]): Command arguments from XSOAR.
    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.

    """

    database_name = str(args["database_name"])
    page = arg_to_number(args.get("page", DEFAULT_PAGE_NUMBER))
    page_size = arg_to_number(args.get("page_size"))
    limit = arg_to_number(args.get("limit", DEFAULT_LIMIT))
    client_activity_id = str(args.get("client_activity_id", ""))
    validate_list_command_arguments(page, page_size, limit)  # type: ignore[arg-type]
    response = client.search_queries_list_request(database_name, client_activity_id)

    return retrieve_command_results_of_list_commands(
        response,
        "List of Completed Search Queries",
        page,  # type: ignore[arg-type]
        page_size,  # type: ignore[arg-type]
        limit,  # type: ignore[arg-type]
        "AzureDataExplorer.SearchQuery",
    )


def running_search_queries_list_command(client: DataExplorerClient, args: dict[str, Any]) -> CommandResults:
    """
    List currently running search queries command.
    Args:
        client (DataExplorerClient): Azure Data Explorer API client.
        args (Dict[str, Any]): Command arguments from XSOAR.
    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.

    """
    database_name = str(args["database_name"])
    page = arg_to_number(args.get("page", DEFAULT_PAGE_NUMBER))
    page_size = arg_to_number(args.get("page_size"))
    limit = arg_to_number(args.get("limit", DEFAULT_LIMIT))
    client_activity_id = str(args.get("client_activity_id", ""))

    validate_list_command_arguments(page, page_size, limit)  # type: ignore[arg-type]
    response = client.running_search_queries_list_request(database_name, client_activity_id)

    return retrieve_command_results_of_list_commands(
        response,
        "List of Currently running Search Queries",
        page,  # type: ignore[arg-type]
        page_size,  # type: ignore[arg-type]
        limit,  # type: ignore[arg-type]
        "AzureDataExplorer.RunningSearchQuery",
    )


def running_search_query_cancel_command(client: DataExplorerClient, args: dict[str, Any]) -> CommandResults:
    """
    Cancel currently running search query command.
    Args:
        client (DataExplorerClient): Azure Data Explorer API client.
        args (Dict[str, Any]): Command arguments from XSOAR.
    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.

    """
    client_activity_id = str(args["client_activity_id"])
    database_name = str(args["database_name"])
    reason = str(args.get("reason"))
    response = client.running_search_query_delete_request(database_name, client_activity_id, reason)

    response_kusto_dataset = KustoResponseDataSetV1(response)

    outputs = convert_kusto_response_to_dict(response_kusto_dataset)
    readable_output = tableToMarkdown(
        f"Canceled Search Query {client_activity_id}",
        outputs,
        headers=["ClientRequestId", "ReasonPhrase", "RunningQueryCanceled"],
        headerTransform=pascalToSpace,
    )
    command_results = CommandResults(
        outputs_prefix="AzureDataExplorer.CanceledSearchQuery",
        outputs_key_field="ClientRequestId",
        outputs=outputs,
        raw_response=response,
        readable_output=readable_output,
    )

    return command_results


def retrieve_command_results_of_list_commands(
    response: dict[str, Any], base_header: str, page: int, page_size: int, limit: int, outputs_prefix: str
) -> CommandResults:
    """
    Retrieves the command results of list commands.
    Args:
        response (Dict[str,Any]): API response from Azure.
        base_header: (str) Header prefix in the readable output.
        page (int): Page number.
        page_size (int): Page size.
        limit (int): Page size.
        outputs_prefix (str): Command context outputs prefix.
    Returns:
        CommandResults: List Command results.
    """
    response_kusto_dataset = KustoResponseDataSetV1(response)
    total_rows = response_kusto_dataset.primary_results[0].rows_count

    outputs = convert_kusto_response_to_dict(response_kusto_dataset, page, page_size, limit)
    readable_header = format_header_for_list_commands(base_header, total_rows, page, page_size, limit)
    readable_output = tableToMarkdown(
        readable_header,
        outputs,
        headers=["ClientActivityId", "User", "Text", "Database", "StartedOn", "LastUpdatedOn", "State"],
        headerTransform=pascalToSpace,
    )
    command_results = CommandResults(
        outputs_prefix=outputs_prefix,
        outputs_key_field="ClientActivityId",
        outputs=outputs,
        raw_response=response,
        readable_output=readable_output,
    )

    return command_results


""" INTEGRATION HELPER METHODS """


def convert_datetime_fields(raw_data: list[dict]) -> list[dict]:
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


def convert_kusto_response_to_dict(
    kusto_response: KustoResponseDataSet, page: int = None, page_size: int = None, limit: int = None
) -> list[dict]:
    """
    Converting KustoResponseDataSet object to dict type.
    Support two use cases of pagination: 'Manual Pagination' and 'Automatic Pagination'.
    Args:
        kusto_response (KustoResponseDataSet): The response from API call.
        page (int): First index to retrieve from.
        page_size (int) : Number of records to return per page.
        limit (int): Limit on the number of the results to return.

    Returns:
        Dict[str, Any]: Converted response.
    """
    raw_data = kusto_response.primary_results[0].to_dict().get("data", [])
    if page and page_size:  # Manual Pagination
        from_index = min((page - 1) * page_size, len(raw_data))
        to_index = min(from_index + page_size, len(raw_data))
        relevant_raw_data = raw_data[from_index:to_index]

    elif limit:  # Automatic Pagination
        relevant_raw_data = raw_data[: min(len(raw_data), limit)]

    else:  # used only in search query execution command
        relevant_raw_data = raw_data
    serialized_data: list[dict] = convert_datetime_fields(relevant_raw_data)
    return serialized_data


def format_header_for_list_commands(base_header: str, rows_count: int, page: int, page_size: int, limit: int) -> str:
    """
    Retrieve the header of the readable output for list commands.
    Format the header according to the pagination use case:
    'Manual Pagination' or 'Automatic Pagination'.
    Args:
        base_header (str): The header prefix.
        rows_count (int): The number of rows in the output.
        page (int): Client's page number argument.
        page_size (int): number of records per page.
        limit (int): Client's limit argument.
    Returns:
        Dict[str, Any]: Header for readable output of the command.
    """
    if page_size:
        total_pages = rows_count // page_size + (rows_count % page_size != 0)
        if rows_count > 0:
            base_header += f" \nShowing page {page} out of {total_pages} total pages." f" Current page size: {page_size}."
    else:
        base_header += f" \nShowing 0 to {limit} records out of {rows_count}."
    return base_header


def retrieve_common_request_body(database_name: str, query: str, properties: dict[str, Any] = None) -> dict[str, Any]:
    """
    Retrieve requests body. For every request, the body contains the database name and the query to the execute.

    Args:
        database_name (str): The database name.
        query (str): The query to execute.
        properties (Dict[str, Any], optional): Other user's properties to send in the request
                                               Defaults to None.

    Returns:
        Dict[str, Any]: Body raw data for the request.
    """
    data = {"db": database_name, "csl": query}
    if properties:
        data["properties"] = properties  # type: ignore[assignment]
    return data


def calculate_total_request_timeout(server_timeout: Decimal) -> int:
    """
    Calculates the total timeout duration of a request.
    Takes into consideration the timeout duration on server side.

    Args:
        server_timeout (int): Quesry execution duration on server side.

    Returns:
        int: Total timeout duration of a request.
    """
    server_timeout_in_seconds = int(server_timeout * 60)
    return server_timeout_in_seconds + REQUEST_BASE_TIMEOUT


def validate_list_command_arguments(page: int, page_size: int, limit: int) -> None:
    """
    Validation of page number, page size and limit arguments in list commands.

    Args:
        page (int): The page number.
        page_size(int) : Limit on page size.
        limit (int): Limit on number of records.

    Raises:
        ValueError: Error message.
    """
    if not page >= 1 and limit >= 1 and page_size >= 1:
        raise ValueError("Page and limit arguments must be integers greater than 0.")


""" AUTHORIZATION METHODS """


def start_auth(client: DataExplorerClient) -> CommandResults:
    """
    Start the authorization process.

    Args:
        client (DataExplorerClient): Azure Data Explorer API client.

    Returns:
        CommandResults: authentication guidelines.
    """
    result = client.ms_client.start_auth("!azure-data-explorer-auth-complete")
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
    return "✅ Authorization completed successfully."


def test_connection(client: DataExplorerClient) -> str:
    """
    Test the connection with Azure Data Explorer service.

    Args:
        client (DataExplorerClient): Azure Data Explorer API client.

    Returns:
          str: Message about successfully connected to the Azure Data Explorer.
    """
    client.ms_client.get_access_token()
    return "✅ Success!"


def test_module(client: DataExplorerClient) -> str:
    """Tests API connectivity and authentication for client credentials only.
    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.
    :type client: ``Client``
    :param Client: client to use
    :return: 'ok' if test passed.
    :rtype: ``str``
    """
    # This  should validate all the inputs given in the integration configuration panel,
    # either manually or by using an API that uses them.
    if "Device Code" in client.connection_type:
        raise DemistoException(
            "Please enable the integration and run `!azure-data-explorer-auth-start`"
            "and `!azure-data-explorer-auth-complete` to log in."
            "You can validate the connection by running `!azure-data-explorer-auth-test`\n"
            "For more details press the (?) button."
        )
    elif client.connection_type == "Client Credentials":
        client.ms_client.get_access_token()
        return "ok"
    else:
        raise Exception(
            "When using user auth flow configuration, "
            "Please enable the integration and run the !azure-data-explorer-auth-test command in order to test it"
        )


def main() -> None:
    """
    PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params: dict[str, Any] = demisto.params()
    args: dict[str, Any] = demisto.args()
    cluster_url = params["cluster_url"]
    client_id = params["client_id"]
    client_activity_prefix = params.get("client_activity_prefix")
    verify_certificate: bool = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    enc_key = (params.get("credentials", {})).get("password")
    tenant_id = params.get("tenant_id")
    connection_type = params.get("authentication_type", "Device Code")
    auth_code = (params.get("auth_code", {})).get("password")
    redirect_uri = params.get("redirect_uri")

    command = demisto.command()
    demisto.debug(f"Command being called is {command}")

    try:
        requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]
        client: DataExplorerClient = DataExplorerClient(
            cluster_url,
            client_id,
            client_activity_prefix,  # type: ignore[arg-type]
            verify_certificate,
            proxy,
            connection_type,
            tenant_id,
            enc_key,
            auth_code,
            redirect_uri,
        )

        commands = {
            "azure-data-explorer-search-query-execute": search_query_execute_command,
            "azure-data-explorer-search-query-list": search_queries_list_command,
            "azure-data-explorer-running-search-query-list": running_search_queries_list_command,
            "azure-data-explorer-running-search-query-cancel": running_search_query_cancel_command,
        }

        if command == "test-module":
            return_results(test_module(client))
        elif command == "azure-data-explorer-generate-login-url":
            return_results(generate_login_url(client.ms_client))
        elif command == "azure-data-explorer-auth-start":
            return_results(start_auth(client))
        elif command == "azure-data-explorer-auth-complete":
            return_results(complete_auth(client))
        elif command == "azure-data-explorer-auth-reset":
            return_results(reset_auth())
        elif command == "azure-data-explorer-auth-test":
            return_results(test_connection(client))
        elif command in commands:
            return_results(commands[command](client, args))

        else:
            raise NotImplementedError(f"{command} command is not implemented.")

    except Exception as e:
        error_text = str(e)
        if "OneApiErrors" in error_text:
            error_text = "The execution of search query failed due a client cancel request."
        elif "Request execution timeout" in error_text:
            error_text = "Search query execution took longer than the assigned timeout" " value and has been aborted."

        return_error(f"Failed to execute {command} command.\nError:\n{error_text}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
