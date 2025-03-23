import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

from datetime import datetime

AWS_SERVICE_NAME = "athena"
QUERY_DATA_OUTPUTS_KEY = "Query"
QUERY_RESULTS_OUTPUTS_KEY = "QueryResults"


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


def start_query_command(args: dict, client):
    query_string: str = args["QueryString"]

    response = start_query_execution(
        client=client,
        query_string=query_string,
        query_limit=args.get("QueryLimit"),
        client_request_token=args.get("ClientRequestToken"),
        database=args.get("Database"),
        output_location=args.get("OutputLocation"),
        encryption_option=args.get("EncryptionOption"),
        kms_key=args.get("KmsKey"),
        work_group=args.get("WorkGroup"),
    )

    context_data = {"Query": query_string, "QueryExecutionId": response["QueryExecutionId"]}

    return CommandResults(
        outputs_prefix=f"AWS.Athena.{QUERY_DATA_OUTPUTS_KEY}",
        outputs_key_field="QueryExecutionId",
        outputs=context_data,
        raw_response=response,
        readable_output=tableToMarkdown("AWS Athena Query Start", context_data),
    )


def stop_query_command(args: dict, client):
    query_execution_id: str = args["QueryExecutionId"]
    response = client.stop_query_execution(QueryExecutionId=query_execution_id)

    if response.get("ResponseMetadata", {}).get("HTTPStatusCode") == 200:
        return CommandResults(readable_output=f"Query '{query_execution_id}' has been successfully stopped.")

    else:
        demisto.debug("Response:\n" + str(response))
        raise DemistoException(f"Failed to stop query '{query_execution_id}'.")


def get_query_execution_command(args: dict, client):
    query_execution_id: str = args["QueryExecutionId"]
    response = get_query_execution(client=client, query_execution_id=query_execution_id)

    return CommandResults(
        outputs_prefix=f"AWS.Athena.{QUERY_DATA_OUTPUTS_KEY}",
        outputs_key_field="QueryExecutionId",
        outputs=response,
        raw_response=response,
        readable_output=tableToMarkdown("AWS Athena Query Execution", response),
    )


def get_query_results_command(args: dict, client):
    query_execution_id: str = args["QueryExecutionId"]
    response = get_query_results(client=client, query_execution_id=query_execution_id)

    return CommandResults(
        outputs_prefix=f"AWS.Athena.{QUERY_RESULTS_OUTPUTS_KEY}",
        outputs=response,
        raw_response=response,
        readable_output=tableToMarkdown("AWS Athena Query Results", response),
    )


@polling_function(
    name=demisto.command(),
    interval=arg_to_number(demisto.args().get("interval_in_seconds", 10)),
    timeout=arg_to_number(demisto.args().get("timeout_in_seconds", 300)),
    requires_polling_arg=False,
)
def execute_query_command(args: dict, client):
    if "QueryExecutionId" not in args:
        start_query_response = start_query_execution(
            client=client,
            query_string=args["QueryString"],
            query_limit=args.get("QueryLimit"),
            client_request_token=args.get("ClientRequestToken"),
            database=args.get("Database"),
            output_location=args.get("OutputLocation"),
            encryption_option=args.get("EncryptionOption"),
            kms_key=args.get("KmsKey"),
            work_group=args.get("WorkGroup"),
        )
        query_execution_id = start_query_response["QueryExecutionId"]

        # If this is the first polling iteration, wait a second to allow the query to complete.
        # This saves time for most cases where waiting for the next poll (with a minimum of 10 seconds) is not necessary.
        time.sleep(1)

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

    output_data: dict[str, Any] = {QUERY_DATA_OUTPUTS_KEY: query_execution_response}
    readable_output = None

    if query_state == "SUCCEEDED":
        query_results_response = get_query_results(client=client, query_execution_id=query_execution_id)
        output_data[QUERY_RESULTS_OUTPUTS_KEY] = query_results_response
        readable_output = tableToMarkdown("AWS Athena Query Results", query_results_response)

    elif query_state == "CANCELLED":
        readable_output = f"Query '{query_execution_id}' has been cancelled."

    elif query_state == "FAILED":
        readable_output = f"Query '{query_execution_id}' has failed."

        if query_execution_response["QueryExecution"]["Status"].get("AthenaError", {}).get("ErrorMessage"):
            error_message = query_execution_response["QueryExecution"]["Status"]["AthenaError"]["ErrorMessage"]
            readable_output += f"\nError: {error_message}"

    return PollResult(
        response=CommandResults(
            outputs_prefix="AWS.Athena",
            outputs=output_data,
            raw_response=output_data,
            readable_output=readable_output,
        ),
        continue_to_poll=False,
    )


def main():  # pragma: no cover
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    aws_role_arn = params.get("roleArn")
    aws_role_session_name = params.get("roleSessionName")
    aws_default_region = params.get("defaultRegion")
    aws_role_session_duration = params.get("sessionDuration")
    aws_access_key_id = demisto.get(params, "credentials.identifier") or params.get("access_key")
    aws_secret_access_key = demisto.get(params, "credentials.password") or params.get("secret_key")
    verify_certificate = not params.get("insecure", True)
    timeout = params.get("timeout")
    retries = params.get("retries", 5)

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

        client = aws_client.aws_session(
            service=AWS_SERVICE_NAME,
            region=args.get("region"),
            role_arn=args.get("roleArn"),
            role_session_name=args.get("roleSessionName"),
            role_session_duration=args.get("roleSessionDuration"),
        )

        result: str | CommandResults

        if command == "test-module":
            result = module_test_command(client)

        elif command == "aws-athena-start-query":
            result = start_query_command(args=args, client=client)

        elif command == "aws-athena-stop-query":
            result = stop_query_command(args=args, client=client)

        elif command == "aws-athena-get-query-execution":
            result = get_query_execution_command(args=args, client=client)

        elif command == "aws-athena-get-query-results":
            result = get_query_results_command(args=args, client=client)

        elif command == "aws-athena-execute-query":
            result = execute_query_command(args=args, client=client)

        else:
            raise NotImplementedError(f'Command "{command}" is not implemented.')

        return_results(result)

    except Exception as e:
        return_error(f"Error: {e}")


from AWSApiModule import *  # noqa: E402

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
