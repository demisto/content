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


def get_xql_query_results_platform(client: CoreClient, execution_id: str) -> dict:
    """Retrieve results of an executed XQL query using Platform API.

    Args:
        client (CoreClient): The XDR Client.
        execution_id (str): The execution ID of the query to retrieve.

    Returns:
        dict: The query results including status, execution_id, and results if completed.
    """
    data: dict[str, Any] = {
        "query_id": execution_id,
    }

    # Call the Client function and get the raw response
    demisto.debug(f"Calling get_query_results with {data=}")
    response = client._http_request(
        method="POST", json_data=data, url_suffix="/xql_queries/results/info/", ok_codes=[200], use_platform_api=True
    )

    response["execution_id"] = execution_id
    stream_id = response.get("stream_id")
    if response.get("status") != "PENDING" and stream_id:
        data = {
            "stream_id": stream_id,
        }
        demisto.debug(f"Requesting query results using {data=}")
        query_data = client._http_request(
            method="POST", json_data=data, url_suffix="/xql_queries/results/", ok_codes=[200], use_platform_api=True
        )
        response["results"] = [json.loads(line) for line in query_data.split("\n") if line.strip()]

    if response.get("status") == "FAIL":
        # Get full error details using PAPI
        data = {
            "request_data": {
                "query_id": execution_id,
                "pending_flag": True,
                "format": "json",
            }
        }
        response["error_details"] = client.get_xql_query_results(data).get("error")

    return response


def get_xql_query_results_platform_polling(client: CoreClient, execution_id: str, timeout: int) -> dict:
    """Retrieve results of an executed XQL query using Platform API with polling.

    Args:
        client (CoreClient): The XDR Client.
        execution_id (str): The execution ID of the query to fetch.
        timeout (int): The polling timeout in seconds.

    Returns:
        dict: The query results after polling completes or timeout is reached.
    """
    interval_in_secs = 10

    # Block execution until the execution status isn't pending or we time out
    polling_start_time = datetime.now()
    while (datetime.now() - polling_start_time).total_seconds() < timeout:
        outputs = get_xql_query_results_platform(client, execution_id)
        if outputs.get("status") != "PENDING":
            break

        t_to_timeout = (datetime.now() - polling_start_time).total_seconds()
        demisto.debug(
            f"Got status 'PENDING' for {execution_id}, next poll in {interval_in_secs} seconds. Timeout in {t_to_timeout}"
        )
        time.sleep(interval_in_secs)  # pylint: disable=E9003

    return outputs


def start_xql_query_platform(client: CoreClient, query: str, timeframe: dict) -> str:
    """Execute an XQL query using Platform API.

    Args:
        client (CoreClient): The XDR Client.
        query (str): The XQL query string to execute.
        timeframe (dict): The timeframe for the query.

    Returns:
        str: The query execution ID.
    """
    if "limit" not in query:  # Add default limit if no limit was provided
        query = f"{query} | limit {DEFAULT_LIMIT!s}"

    data: Dict[str, Any] = {
        "query": query,
        "timeframe": timeframe,
    }

    demisto.debug(f"Calling xql_queries/submit with {data=}")
    res = client._http_request(
        url_suffix="/xql_queries/submit/", method="POST", json_data=data, ok_codes=[200], use_platform_api=True
    )
    return res


def xql_query_platform_command(client: CoreClient, args: dict) -> CommandResults:
    """Execute an XQL query using Platform API and poll for results.

    Args:
        client (CoreClient): The XDR Client.
        args (dict): Command arguments including query, timeframe, wait_for_results, and timeout_in_seconds.

    Returns:
        CommandResults: The command results with execution_id, query_url, and optionally status and results.
    """
    query = args.get("query", "")
    if not query:
        raise ValueError("query is not specified")

    timeframe = convert_timeframe_string_to_json(args.get("timeframe", "24 hours") or "24 hours")

    execution_id = start_xql_query_platform(client, query, timeframe)

    if not execution_id:
        raise DemistoException("Failed to start query\n")

    query_url = "/".join([demisto.demistoUrls().get("server", ""), "xql/xql-search", execution_id])
    outputs = {
        "execution_id": execution_id,
        "query_url": query_url,
    }

    if argToBoolean(args.get("wait_for_results", True)):
        demisto.debug(f"Polling query execution with {execution_id=}")
        timeout_in_secs = int(args.get("timeout_in_seconds", 180))
        outputs.update(get_xql_query_results_platform_polling(client, execution_id, timeout_in_secs))

    return CommandResults(
        outputs_prefix="GenericXQLQuery", outputs_key_field="execution_id", outputs=outputs, raw_response=outputs
    )


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
            return_results(PLATFORM_QUERY_COMMANDS[command](client, args))
        else:
            raise NotImplementedError(f"Command {command} does not exist.")
    except Exception as e:
        return_error(f"Failed to execute {demisto.command()} command.\nError:\n{e!s}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
