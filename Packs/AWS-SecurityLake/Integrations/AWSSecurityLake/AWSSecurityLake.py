import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

from datetime import datetime

AWS_SERVICE_NAME = "athena"
AWS_SERVICE_NAME_LAKE = "securitylake"
QUERY_DATA_OUTPUTS_KEY = "Query"


def parse_rows_response(rows_data: list[dict]) -> list[dict]:
    """
    Parse and arrange the 'Rows' data from the response.

    Args:
        rows_data (list[dict]): The 'Rows' data from the response.

    Note:
        The 'Rows' data is returned in a table format, where each item in the list is a row.
        Example for such a response can be seen on 'test_data/raw_data_mock/get_query_results.json'

    Returns:
        list[dict]: The data in a parsed and arranged format.
    """
    if not rows_data or not rows_data[0].get("Data"):
        return []

    keys: list[str] = [item["VarCharValue"] for item in rows_data[0]["Data"]]
    raw_results = [item["Data"] for item in rows_data[1:]]
    result_data = []

    for raw_result in raw_results:
        current_item_data = {}

        for idx, value in enumerate(raw_result):
            if "VarCharValue" in value:
                current_item_data[keys[idx]] = value["VarCharValue"]

        result_data.append(current_item_data)

    return result_data


def determine_client_service_name(command: str):
    """determines the needed client service name based on the command.

    Args:
        command (str): command name being called.

    Returns:
        _type_: service name based on the command.
    """
    if command in ["aws-security-lake-data-sources-list", "aws-security-lake-data-lakes-list"]:
        return AWS_SERVICE_NAME_LAKE
    else:
        return AWS_SERVICE_NAME


def next_token_output_dict(outputs_prefix: str, next_token: str | None, page_outputs: Any, page_outputs_key: str):
    """Creates a dict for CommandResults.output with the next token."""
    outputs = {
        f"AWS.SecurityLake.{outputs_prefix}(val.{page_outputs_key} && val.{page_outputs_key} == obj.{page_outputs_key})": page_outputs,  # noqa: E501
        "AWS.SecurityLake(true)": {f"{outputs_prefix}NextToken": next_token},
    }

    return remove_empty_elements(outputs)


def parse_table_metadata(table_metadata_list: list):
    """Formats dates in the table metadata from the response.

    Args:
        table_metadata_list (list): the raw metadata returned from API.
    """
    for metadata in table_metadata_list:
        if create_time := metadata.get("CreateTime"):
            metadata["CreateTime"] = create_time.strftime("%Y-%m-%d %H:%M:%S")
        if last_access_time := metadata.get("LastAccessTime"):
            metadata["LastAccessTime"] = last_access_time.strftime("%Y-%m-%d %H:%M:%S")


# --- API Call Functions --- #


def start_query_execution(
    client,
    query_string: str,
    query_limit: int | None = None,
    client_request_token: str | None = None,
    database: str | None = None,
    output_location: str | None = None,
    encryption_option: str | None = None,
    kms_key: str | None = None,
    work_group: str | None = None,
) -> dict:
    if query_limit and "LIMIT" not in query_string:
        query_string = f"{query_string} LIMIT {query_limit}"

    kwargs: dict[str, Any] = {"QueryString": query_string}

    if client_request_token:
        kwargs.update({"ClientRequestToken": client_request_token})

    if database:
        kwargs.update({"QueryExecutionContext": {"Database": database}})

    if output_location:
        kwargs.update({"ResultConfiguration": {"OutputLocation": output_location}})

    if encryption_option:
        kwargs.update({"ResultConfiguration": {"EncryptionConfiguration": {"EncryptionOption": encryption_option}}})

    if kms_key:
        kwargs.update({"ResultConfiguration": {"EncryptionConfiguration": {"KmsKey": kms_key}}})

    if work_group:
        kwargs.update({"WorkGroup": work_group})

    return client.start_query_execution(**kwargs)


def get_query_execution(client, query_execution_id: str) -> dict:
    response = client.get_query_execution(QueryExecutionId=query_execution_id)

    # Convert datetime objects to strings
    if (datetime_value := response.get("QueryExecution", {}).get("Status", {}).get("SubmissionDateTime")) and isinstance(
        datetime_value, datetime
    ):
        response["QueryExecution"]["Status"]["SubmissionDateTime"] = datetime_value.isoformat()

    if (datetime_value := response.get("QueryExecution", {}).get("Status", {}).get("CompletionDateTime")) and isinstance(
        datetime_value, datetime
    ):
        response["QueryExecution"]["Status"]["CompletionDateTime"] = datetime_value.isoformat()

    return response["QueryExecution"]


def get_query_results(client, query_execution_id: str) -> list[dict]:
    raw_response = client.get_query_results(QueryExecutionId=query_execution_id)
    parsed_response = parse_rows_response(rows_data=raw_response["ResultSet"]["Rows"])

    for result_item in parsed_response:
        result_item["query_execution_id"] = query_execution_id

    return parsed_response


# --- Command Functions --- #


def module_test_command(client) -> str | CommandResults:
    response = client.list_named_queries()
    if response["ResponseMetadata"]["HTTPStatusCode"] == 200:
        return "ok"

    else:
        raise DemistoException(f"Error: {response}")


@polling_function(
    name=demisto.command(),
    interval=arg_to_number(demisto.args().get("interval_in_seconds", 10)),
    timeout=arg_to_number(demisto.args().get("timeout_in_seconds", 300)),
    requires_polling_arg=False,
)
def execute_query_command(args: dict, query_results_context_key: str, client):
    if "QueryExecutionId" not in args:
        start_query_response = start_query_execution(
            client=client,
            query_string=args["query_string"],
            query_limit=args.get("query_limit"),
            client_request_token=args.get("client_request_token"),
            database=args.get("database"),
            output_location=args.get("output_location"),
            encryption_option=args.get("encryption_option"),
            kms_key=args.get("kms_key"),
            work_group=args.get("work_group"),
        )
        query_execution_id = start_query_response["QueryExecutionId"]

    else:
        query_execution_id = args["QueryExecutionId"]

    query_execution_response = get_query_execution(client=client, query_execution_id=query_execution_id)
    query_state = query_execution_response["Status"]["State"]

    if query_state in ("QUEUED", "RUNNING"):
        args["QueryExecutionId"] = query_execution_id

        return PollResult(
            response=None,
            continue_to_poll=True,
            args_for_next_run=args,
            partial_result=CommandResults(readable_output=f"Query is still running. Current state: '{query_state}'."),
        )

    output_data: dict[str, Any] = {f"AWS.SecurityLake.{QUERY_DATA_OUTPUTS_KEY}": query_execution_response}
    readable_output = None

    if query_state == "SUCCEEDED":
        query_results_response = get_query_results(client=client, query_execution_id=query_execution_id)
        output_data[f"AWS.SecurityLake.{query_results_context_key}"] = query_results_response
        readable_output = tableToMarkdown("AWS Athena Query Results", query_results_response)

    elif query_state == "CANCELLED":
        readable_output = f"Query '{query_execution_id}' has been cancelled."

    elif query_state == "FAILED":
        readable_output = f"Query '{query_execution_id}' has failed."
        demisto.debug(str(query_execution_response))
        if query_execution_response["Status"].get("AthenaError", {}).get("ErrorMessage"):
            error_message = query_execution_response["Status"]["AthenaError"]["ErrorMessage"]
            readable_output += f"\nError: {error_message}"

    return PollResult(
        response=CommandResults(
            outputs=output_data,
            raw_response=output_data,
            readable_output=readable_output,
        ),
        continue_to_poll=False,
    )


def list_catalogs_command(client, args: dict):
    """Lists the data catalogs in the current Amazon Web Services account.

    Args:
        client : aws client object
        args (dict): command argument - nextToken, limit, workGroup
    """

    args_to_request = {
        "NextToken": args.get("next_token"),
        "MaxResults": arg_to_number(args.get("limit")),
        "WorkGroup": args.get("work_group"),
    }

    response = client.list_data_catalogs(**remove_empty_elements(args_to_request))

    catalogs = response.get("DataCatalogsSummary")
    next_token = response.get("NextToken")
    context_output = next_token_output_dict("Catalog", next_token, catalogs, "CatalogName")

    return CommandResults(
        outputs=context_output,
        raw_response=response,
        readable_output=tableToMarkdown(
            "AWS Security Lake Catalogs", response.get("DataCatalogsSummary"), headerTransform=pascalToSpace, removeNull=True
        ),
    )


def list_databases_command(client, args: dict):
    """Lists the databases in the specified data catalog.
    Args:
        client : aws client object
        args (dict): command argument
    """
    args_to_request = {
        "NextToken": args.get("next_token"),
        "MaxResults": arg_to_number(args.get("limit")),
        "WorkGroup": args.get("work_group"),
        "CatalogName": args.get("catalog_name"),
    }

    response = client.list_databases(**remove_empty_elements(args_to_request))

    databases = response.get("DatabaseList")
    next_token = response.get("NextToken")
    context_output = next_token_output_dict("Database", next_token, databases, "Name")

    return CommandResults(
        outputs=context_output,
        raw_response=response,
        readable_output=tableToMarkdown(
            "AWS Security Lake Databases",
            response.get("DatabaseList"),
            headers=["Name"],
            headerTransform=pascalToSpace,
            removeNull=True,
        ),
    )


def list_table_metadata_command(client, args: dict):
    """Lists the metadata for the tables in the specified data catalog database.

    Args:
        client : aws client object
        args (dict): command argument
    """

    args_to_request = {
        "NextToken": args.get("next_token"),
        "MaxResults": arg_to_number(args.get("limit")),
        "WorkGroup": args.get("work_group"),
        "CatalogName": args.get("catalog_name"),
        "DatabaseName": args.get("database_name"),
        "Expression": args.get("expression"),
    }

    response = client.list_table_metadata(**remove_empty_elements(args_to_request))
    parse_table_metadata(response.get("TableMetadataList"))

    metadata_list = response.get("TableMetadataList")
    next_token = response.get("NextToken")
    context_output = next_token_output_dict("TableMetadata", next_token, metadata_list, "Name")

    return CommandResults(
        outputs=context_output,
        raw_response=response,
        readable_output=tableToMarkdown(
            "AWS Security Lake Databases",
            metadata_list,
            headers=["Name", "TableType", "Columns", "PartitionKeys"],
            headerTransform=pascalToSpace,
            removeNull=True,
        ),
    )


def mfalogin_query_command(client, args: dict):
    """Running aws-security-lake-query-execute command with query_string:
    SELECT * FROM <{database}>.<{table}>
    WHERE CAST(actor.user.name AS VARCHAR) = '{user_name}';

        Args:
            client : aws client object
            args (dict): command argument
    """
    database = args.get("database")
    table = args.get("table")
    user_name = args.get("user_name")
    args["query_string"] = f"SELECT * FROM {database}.{table} WHERE CAST(actor.user.name AS VARCHAR) = '{user_name}';"
    result = execute_query_command(client=client, args=args, query_results_context_key="MfaLoginQueryResults")
    return result


def source_ip_query_command(client, args: dict):
    """Running aws-security-lake-query-execute command with query_string:
    SELECT * FROM <{database}>.<{table}>
    WHERE CAST(src_endpoint.ip AS VARCHAR) = '{ip_src}';

        Args:
            client : aws client object
            args (dict): command argument
    """
    database = args.get("database")
    table = args.get("table")
    ip_src = args.get("ip_src")
    args["query_string"] = f"SELECT * FROM {database}.{table} WHERE CAST(src_endpoint.ip AS VARCHAR) = '{ip_src}';"
    return execute_query_command(client=client, args=args, query_results_context_key="SourceIPQueryResults")


def guardduty_activity_query_command(client, args: dict):
    """Running aws-security-lake-query-execute command with query_string:
        SELECT * FROM <{database}>.<{table}> WHERE severity = '{severity}';

    Args:
        client : aws client object
        args (dict): command argument
    """
    database = args.get("database")
    table = args.get("table")
    severity = args.get("severity")
    args["query_string"] = f"SELECT * FROM {database}.{table} WHERE severity = '{severity}';"
    return execute_query_command(client=client, args=args, query_results_context_key="GuardDutyActivityQueryResults")


def list_sources_command(client, args: dict):
    """Retrieves a snapshot of the current Region.

    Args:
        client : aws client object
        args (dict): command argument
    """
    args_to_request = {
        "accounts": argToList(args.get("accounts")),
        "maxResults": arg_to_number(args.get("limit")),
        "nextToken": args.get("next_token"),
    }

    response = client.get_data_lake_sources(**remove_empty_elements(args_to_request))

    next_token = response.get("nextToken")
    outputs = {
        "AWS.SecurityLake.DataLakeSource.DataLakeArn": response.get("dataLakeArn"),
        "AWS.SecurityLake.DataLakeSource.DataLakeSources": response.get("dataLakeSources"),
        "AWS.SecurityLake(true)": {"DataLakeSourceNextToken": next_token},
    }

    return CommandResults(
        outputs=remove_empty_elements(outputs),
        raw_response=response,
        readable_output=tableToMarkdown(
            "AWS Security Lake Catalogs",
            response.get("dataLakeSources"),
            headers=["account", "sourceName"],
            headerTransform=pascalToSpace,
            removeNull=True,
        ),
    )


def list_data_lakes_command(client, args: dict):
    """Retrieves the Amazon Security Lake configuration object for the specified Amazon Web Services Regions.

    Args:
        client : aws client object
        args (dict): command argument
    """

    response = client.list_data_lakes(regions=argToList(args.get("regions")))
    outputs = remove_empty_elements(response.get("dataLakes"))
    return CommandResults(
        outputs_prefix="AWS.SecurityLake.DataLake",
        outputs_key_field="dataLakeArn",
        outputs=outputs,
        raw_response=response,
        readable_output=tableToMarkdown("AWS Security Lake Data Lakes", outputs, headerTransform=pascalToSpace),
    )


def main():  # pragma: no cover
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    aws_role_arn = params.get("roleArn")
    aws_role_session_name = params.get("roleSessionName")
    aws_default_region = params.get("defaultRegion")
    aws_role_session_duration = params.get("sessionDuration")
    aws_access_key_id = demisto.get(params, "credentials.identifier")
    aws_secret_access_key = demisto.get(params, "credentials.password")
    verify_certificate = not params.get("insecure", True)
    timeout = params.get("timeout")
    retries = params.get("retries", 5)

    validate_params(aws_default_region, aws_role_arn, aws_role_session_name, aws_access_key_id, aws_secret_access_key)

    try:
        demisto.debug(f"Command being called is '{command}'.")

        aws_client = AWSClient(
            aws_default_region=aws_default_region,
            aws_role_arn=aws_role_arn,
            aws_role_session_name=aws_role_session_name,
            aws_role_session_duration=aws_role_session_duration,
            aws_role_policy=None,
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            verify_certificate=verify_certificate,
            timeout=timeout,
            retries=retries,
        )

        service = determine_client_service_name(command=command)

        client = aws_client.aws_session(
            service=service,
            region=args.get("region"),
            role_arn=args.get("roleArn"),
            role_session_name=args.get("roleSessionName"),
            role_session_duration=args.get("roleSessionDuration"),
        )

        result: str | CommandResults

        if command == "test-module":
            result = module_test_command(client)

        elif command == "aws-security-lake-query-execute":
            result = execute_query_command(client=client, args=args, query_results_context_key="QueryResults")  # type: ignore

        elif command == "aws-security-lake-data-catalogs-list":
            result = list_catalogs_command(client=client, args=args)

        elif command == "aws-security-lake-databases-list":
            result = list_databases_command(client=client, args=args)

        elif command == "aws-security-lake-table-metadata-list":
            result = list_table_metadata_command(client=client, args=args)

        elif command == "aws-security-lake-user-mfalogin-query":
            result = mfalogin_query_command(client=client, args=args)  # type: ignore

        elif command == "aws-security-lake-source-ip-query":
            result = source_ip_query_command(client=client, args=args)  # type: ignore

        elif command == "aws-security-lake-guardduty-activity-query":
            result = guardduty_activity_query_command(client=client, args=args)  # type: ignore

        elif command == "aws-security-lake-data-sources-list":
            result = list_sources_command(client=client, args=args)

        elif command == "aws-security-lake-data-lakes-list":
            result = list_data_lakes_command(client=client, args=args)
        else:
            raise NotImplementedError(f'Command "{command}" is not implemented.')
        return_results(result)

    except Exception as e:
        return_error(str(e))


from AWSApiModule import *  # noqa: E402

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
