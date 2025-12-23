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


def get_xql_query_results_platform(client: CoreClient, args: dict) -> dict:
    """Retrieve results of an executed XQL query API. Returns the query status and the results if the query has been completed.

    Args:
        client (Client): The XDR Client.
        args (dict): The arguments to pass to the API call.

    Returns:
        dict: The query results.
    """
    query_id = args.get("query_id")
    if not query_id:
        raise ValueError("query ID is not specified")
    data = {
        "query_id": query_id,
    }

    # Call the Client function and get the raw response
    demisto.debug(f"Calling get_query_results with {data=}")
    response = client._http_request(method="POST", json_data=data, url_suffix="/xql_queries/results/info/", ok_codes=[200])
    demisto.debug(f"get_query_results returned {response=}")

    response["execution_id"] = query_id
    stream_id = response.get("stream_id")
    if response.get("status") != "PENDING" and stream_id:
        data = {
            "stream_id": stream_id,
        }
        query_data = client._http_request(method="POST", json_data=data, url_suffix="/xql_queries/results/", ok_codes=[200])
        response["results"] = [json.loads(line) for line in query_data.split("\n") if len(line) > 0]

    return response


def get_xql_query_results_platform_polling(client: CoreClient, args: dict) -> dict:
    """Retrieve results of an executed XQL query API

    Args:
        client (Client): The XDR Client.
        args (dict): The arguments to pass to the API call.

    Returns:
        Union[CommandResults, dict]: The command results.
    """
    # get the query data either from the integration context (if its not the first run) or from the given args.
    interval_in_secs = int(args.get("interval_in_seconds", 30))
    timeout_in_secs = int(args.get("timeout_in_seconds", 600))
    max_fields = arg_to_number(args.get("max_fields", 20))
    if max_fields is None:
        raise DemistoException("Please provide a valid number for max_fields argument.")

    # Block execution until the execution status isn't pending or we time out
    polling_start_time = datetime.now()
    while (datetime.now() - polling_start_time).total_seconds() < timeout_in_secs:
        outputs = get_xql_query_results_platform(client, args)  # get query results with query_id
        if outputs.get("status") != "PENDING":
            break

        demisto.debug(f"Got status 'PENDING' for {args.get('query_id', '')}, checking again in {interval_in_secs} seconds.")
        time.sleep(interval_in_secs)

    return outputs


def start_xql_query_platform(client: CoreClient, args: Dict[str, Any]) -> str:
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
        query = f"{query} | limit {DEFAULT_LIMIT!s}"

    timeframe = args.get("timeframe", "24 hours") or "24 hours"

    data: Dict[str, Any] = {
        "query": query,
        "timeframe": convert_timeframe_string_to_json(timeframe),
    }

    demisto.debug(f"Calling start_xql_query with {data=}")
    res = client._http_request(
        url_suffix="/xql_queries/submit/", method="POST", data=data, ok_codes=[200]
    )  # TODO: test bad status code error output
    demisto.debug(f"start_xql_query output: {res=}")
    return res


def xql_query_platform_command(client: CoreClient, args: dict) -> Union[CommandResults, list]:
    """Execute an XQL query using the platform API, then polls until the results are received.

    Args:
        client (Client): The XDR Client.
        args (dict): The arguments to pass to the API call.

    Returns:
        CommandResults: The command results.
    """
    execution_id = args.get("query_id")
    if not execution_id:
        execution_id = start_xql_query_platform(client, args)

    if not execution_id:
        raise DemistoException("Failed to start query\n")

    demisto.debug(f"Polling query execution with {execution_id=}")
    args["query_id"] = execution_id

    query_url = "/".join([demisto.demistoUrls().get("server", ""), "xql/xql-search", execution_id])
    outputs = {
        "execution_id": execution_id,
        "query_url": query_url,
    }

    if argToBoolean(args.get("wait_for_results", False)):
        outputs.update(get_xql_query_results_platform_polling(client, args))

    return CommandResults(
        outputs_prefix="GenericXQLQuery", outputs_key_field="execution_id", outputs=outputs, raw_response=outputs
    )


def get_query_info(client: CoreClient, args: dict):
    query_id = args.get("query_id")
    get_results = argToBoolean(args.get("fetch_results", False))

    data: Dict[str, Any] = {
        "query_id": query_id,
    }

    demisto.debug(f"Calling get_query_id with {data=}")
    res = demisto._platformAPICall(path="/xql_queries/results/info/", method="POST", data=data)
    demisto.debug(f"get_query_id output: {res=}")

    res_data = json.loads(res.get("data", {}))
    if get_results and res_data.get("status", "").lower() == "success":
        data = {"stream_id": res_data.get("stream_id")}
        res = demisto._platformAPICall(path="/xql_queries/results/", method="POST", data=data)

    return res


GENERIC_QUERY_COMMANDS = {
    "test-module": test_module,
    "xdr-xql-generic-query": start_xql_query_polling_command,
    "xdr-xql-get-query-results": get_xql_query_results_polling_command,
    "xdr-xql-get-quota": get_xql_quota_command,
}

PLATFORM_QUERY_COMMANDS = {
    "xdr-xql-generic-query-platform": xql_query_platform_command,
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
            return_results(GENERIC_QUERY_COMMANDS[command](client, args))
        elif command in BUILT_IN_QUERY_COMMANDS:
            return_results(get_built_in_query_results_polling_command(client, args))
        elif command in PLATFORM_QUERY_COMMANDS:
            client.use_platform_api = True
            return_results(PLATFORM_QUERY_COMMANDS[command](client, args))
        elif command == "xdr-xql-get-query-info":  # TODO: Remove get query info logic
            return_results(get_query_info(client, args))
        else:
            raise NotImplementedError(f"Command {command} does not exist.")
    except Exception as e:
        return_error(f"Failed to execute {demisto.command()} command.\nError:\n{e!s}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
