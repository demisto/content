import demistomock as demisto
from CommonServerPython import *
from CoreXQLApiModule import *

from CommonServerUserPython import *

# Disable insecure warnings
urllib3.disable_warnings()

""" CLIENT CLASS """


class Client(CoreClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """


""" MAIN FUNCTION """

# COMMAND CONSTANTS

BUILT_IN_QUERY_COMMANDS = {
    "xdr-xql-file-event-query": {
        "func": get_file_event_query,
        "name": "FileEvent",
    },
    "xdr-xql-process-event-query": {
        "func": get_process_event_query,
        "name": "ProcessEvent",
    },
    "xdr-xql-dll-module-query": {
        "func": get_dll_module_query,
        "name": "DllModule",
    },
    "xdr-xql-network-connection-query": {
        "func": get_network_connection_query,
        "name": "NetworkConnection",
    },
    "xdr-xql-registry-query": {
        "func": get_registry_query,
        "name": "Registry",
    },
    "xdr-xql-event-log-query": {
        "func": get_event_log_query,
        "name": "EventLog",
    },
    "xdr-xql-dns-query": {
        "func": get_dns_query,
        "name": "DNS",
    },
    "xdr-xql-file-dropper-query": {
        "func": get_file_dropper_query,
        "name": "FileDropper",
    },
    "xdr-xql-process-instance-network-activity-query": {
        "func": get_process_instance_network_activity_query,
        "name": "ProcessInstanceNetworkActivity",
    },
    "xdr-xql-process-causality-network-activity-query": {
        "func": get_process_causality_network_activity_query,
        "name": "ProcessCausalityNetworkActivity",
    },
}

# def get_xql_query_internal_results(client: CoreClient, args: dict) -> tuple[dict, Optional[bytes]]:
#     """Retrieve results of an executed XQL query API. returns the general response and
#     a file data if the query has more than 1000 results.

#     Args:
#         client (Client): The XDR Client.
#         args (dict): The arguments to pass to the API call.

#     Returns:
#         dict: The query results.
#     """
#     query_id = args.get("query_id")
#     if not query_id:
#         raise ValueError("query ID is not specified")
#     data = {
#         "request_data": {
#             "query_id": query_id,
#         }
#     }

#     # Call the Client function and get the raw response
#     demisto.debug(f"Calling get_query_results with {data=}")
#     res = client._http_request(method="POST", json_data=data, full_url="/platform/xql/get_query_results/")
#     demisto.debug(f"get_query_results returned {res=}")
#     response = res # res.get("reply", "")
#     response["execution_id"] = query_id
#     # results = response.get("results", {})
#     stream_id = response.get("stream_id") # results.get("stream_id")
#     if response.get("status") != "PENDING" and stream_id:
#         data = {
#             "request_data": {
#                 "stream_id": stream_id,
#                 "is_gzip_compressed": True,
#             }
#         }
#         # Call the Client function and get the raw response
#         res = client._http_request(
#             method="POST",
#             url_suffix="/platform/xql/get_query_results_stream/",
#             json_data=data,
#             resp_type="response",
#             response_data_type="bin",
#         )
#         file_data = base64.b64decode(res) if client.is_core else res.content

#         response["results"] = file_data
#         return response, file_data

#     return response, None

# def get_xql_query_internal_results_polling_command(client: CoreClient, args: dict) -> Union[CommandResults, list]:
#     """Retrieve results of an executed XQL query API executes as a scheduled command.

#     Args:
#         client (Client): The XDR Client.
#         args (dict): The arguments to pass to the API call.

#     Returns:
#         Union[CommandResults, dict]: The command results.
#     """
#     # get the query data either from the integration context (if its not the first run) or from the given args.
#     parse_result_file_to_context = argToBoolean(args.get("parse_result_file_to_context", "false"))
#     command_name = args.get("command_name", demisto.command())
#     interval_in_secs = int(args.get("interval_in_seconds", 30))
#     timeout_in_secs = int(args.get("timeout_in_seconds", 600))
#     max_fields = arg_to_number(args.get("max_fields", 20))
#     if max_fields is None:
#         raise DemistoException("Please provide a valid number for max_fields argument.")
#     outputs, file_data = get_xql_query_internal_results(client, args)  # get query results with query_id
#     outputs.update({"query_name": args.get("query_name", "")})
#     outputs_prefix = get_outputs_prefix(command_name) # TODO: fix
#     command_results = CommandResults(
#         outputs_prefix=outputs_prefix, outputs_key_field="execution_id", outputs=outputs, raw_response=copy.deepcopy(outputs)
#     )
#     # if there are more than 1000 results
#     if file_data:
#         if not parse_result_file_to_context:
#             #  Extracts the results into a file only
#             file = fileResult(filename="results.gz", data=file_data)
#             command_results.readable_output = "More than 1000 results were retrieved, see the compressed gzipped file below."
#             return [file, command_results]
#         else:
#             # Parse the results to context:
#             data = gzip.decompress(file_data).decode()
#             outputs["results"] = [json.loads(line) for line in data.split("\n") if len(line) > 0]

#     # if status is pending, the command will be called again in the next run until success.
#     if outputs.get("status") == "PENDING":
#         demisto.debug(f"Returned status 'PENDING' for {args.get('query_id', '')}.")
#         scheduled_command = ScheduledCommand(
#             command="xdr-xql-get-query-results",
#             next_run_in_seconds=interval_in_secs,
#             args=args,
#             timeout_in_seconds=timeout_in_secs,
#         )
#         command_results.scheduled_command = scheduled_command
#         command_results.readable_output = "Query is still running, it may take a little while..."
#         return command_results

#     demisto.debug(f"Returned status '{outputs.get('status')}' for {args.get('query_id', '')}.")
#     results_to_format = outputs.pop("results")
#     # create Human Readable output
#     query = args.get("query", "")
#     time_frame = args.get("time_frame")
#     extra_for_human_readable = {"query": query, "time_frame": time_frame}
#     outputs.update(extra_for_human_readable)
#     command_results.readable_output = tableToMarkdown(
#         "General Information", outputs, headerTransform=string_to_table_header, removeNull=True
#     )
#     [outputs.pop(key) for key in list(extra_for_human_readable.keys())]

#     # if no fields were given in the query then the default fields are returned (without empty fields).
#     if results_to_format:
#         formatted_list = (
#             format_results(results_to_format, remove_empty_fields=False)
#             if "fields" in query
#             else format_results(results_to_format)
#         )
#         if formatted_list and command_name == "xdr-xql-generic-query" and len(formatted_list[0].keys()) > max_fields:
#             raise DemistoException(
#                 "The number of fields per result has exceeded the maximum number of allowed fields, "
#                 "please select specific fields in the query or increase the maximum number of "
#                 "allowed fields."
#             )
#         outputs.update({"results": formatted_list})
#         command_results.outputs = outputs

#     command_results.readable_output += tableToMarkdown(
#         "Data Results", outputs.get("results"), headerTransform=string_to_table_header
#     )

#     return command_results

# def get_xql_internal_quota_command(client: CoreClient, args: Dict[str, Any]) -> CommandResults:
#     return CommandResults()

def start_xql_query_internal(client: CoreClient, args: Dict[str, Any]) -> str:
    """Execute an XQL query.

    Args:
        client (Client): The XDR Client.
        args (dict): The arguments to pass to the API call.

    Returns:
        str: The query execution ID.
    """
    query = args.get("query", "")
    if not query:
        raise ValueError("query is not specified")

    if "limit" not in query:  # if user did not provide a limit in the query, we will use the default one.
        query = f"{query} \n| limit {DEFAULT_LIMIT!s}"

    data: Dict[str, Any] = {
        "query": query,
    }

    # try:
    #     add_playbook_metadata(data, "start_xql_query", silent=True)
    # except Exception as e:
    #     demisto.error(f"Error adding playbook metadata: {str(e)}")

    time_frame = args.get("time_frame")
    if time_frame:
        data["timeframe"] = convert_timeframe_string_to_json(time_frame)
    # The arg is called 'tenant_id', but to avoid BC we will also support 'tenant_ids'.
    # tenant_ids = argToList(args.get("tenant_id") or args.get("tenant_ids"))
    # if tenant_ids:
    #     data["request_data"]["tenants"] = tenant_ids
    # call the client function and get the raw response
    try:
        demisto.debug(f"Calling start_xql_query with {data=}")
        # res = client._http_request(method="POST", json_data=data, full_url="/platform/xql/start_xql_query/")
        res = demisto._platformAPICall(path="/xql_queries/submit/", method="POST", data=data)
        demisto.debug(f"start_xql_query output: {res=}")
        return res
        execution_id = res.get("reply", "")
    except Exception as e:
        if "reached max allowed amount of parallel running queries" in str(e).lower():
            return "FAILURE"
        if "autonomous playbook slot reservation not enabled or missing" in str(e).lower():
            return "UNSUPPORTED"
        raise e

    return execution_id

def start_xql_query_internal_polling_command(client: CoreClient, args: dict) -> Union[CommandResults, list]:
    """Execute an XQL query as a scheduled command.
       If 'start_xql_query' fails, the command will use a polling mechanism to start the XQL query again.

    Args:
        client (Client): The XDR Client.
        args (dict): The arguments to pass to the API call.

    Returns:
        CommandResults: The command results.
    """
    if not args.get("query_name"):
        raise DemistoException("Please provide a query name")

    res = start_xql_query_internal(client, args)
    return CommandResults(readable_output=res)
    # if execution_id == "FAILURE":
    #     demisto.debug("Did not succeed to start query, retrying.")
    #     # the 'start_xql_query' function failed because it reached the maximum allowed number of parallel running queries.
    #     # running the command again using polling with an interval of 'interval_in_secs' seconds.
    #     command_results = CommandResults()
    #     interval_in_secs = int(args.get("interval_in_seconds", 20))
    #     timeout_in_secs = int(args.get("timeout_in_seconds", 600))
    #     scheduled_command = ScheduledCommand(
    #         command="xdr-xql-generic-query-internal", next_run_in_seconds=interval_in_secs, args=args, timeout_in_seconds=timeout_in_secs
    #     )
    #     command_results.scheduled_command = scheduled_command
    #     command_results.readable_output = (
    #         f"The maximum allowed number of parallel running queries has been reached."
    #         f" The query will be executed in the next interval, in {interval_in_secs} seconds."
    #     )
    #     return command_results

    # if execution_id == "UNSUPPORTED":
    #     return CommandResults(readable_output="Autonomous playbook slot reservation not enabled or missing")
    # if not execution_id:
    #     raise DemistoException("Failed to start query\n")
    # demisto.debug(f"Succeeded to start query with {execution_id=}.")
    # args["query_id"] = execution_id
    # args["command_name"] = demisto.command()

    # return get_xql_query_internal_results_polling_command(client, args)


GENERIC_QUERY_COMMANDS = {
    "test-module": test_module,
    "xdr-xql-generic-query": start_xql_query_polling_command,
    "xdr-xql-get-query-results": get_xql_query_results_polling_command,
    "xdr-xql-get-quota": get_xql_quota_command,
    "xdr-xql-generic-query-internal": start_xql_query_internal_polling_command,
}


def main() -> None:
    """
    executes an integration command
    """
    verify_certificate = not demisto.params().get("insecure", False)
    proxy = demisto.params().get("proxy", False)
    command = demisto.command()
    demisto.debug(f"Command being called is {command}")
    args = demisto.args()
    url_suffix = "/public_api/v1"
    try:
        url = "/api/webapp/"
        base_url = urljoin(url, url_suffix)
        client = Client(base_url=base_url, proxy=proxy, verify=verify_certificate, headers={}, is_core=True)

        if command in GENERIC_QUERY_COMMANDS:
            if command == "xdr-xql-generic-query-internal":
                args["silent"] = True
            return_results(GENERIC_QUERY_COMMANDS[command](client, args))
        elif command in BUILT_IN_QUERY_COMMANDS:
            return_results(get_built_in_query_results_polling_command(client, args))
        else:
            raise NotImplementedError(f"Command {command} does not exist.")
    except Exception as e:
        return_error(f"Failed to execute {demisto.command()} command.\nError:\n{e!s}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
