import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import urllib3
from CoreXQLApiModule import *

urllib3.disable_warnings()
DEFAULT_TIMEOUT = 600
DEFAULT_INTERVAL = 30
uri_fallback = r"(?P<uri>\b[a-z][a-z0-9+.-]*:[^\s]+)"  # for covering all cases in addition to "urlRegex"


def shorten_text(text: str) -> str:
    parts = text.split()
    if len(parts) == 2:
        return f"{parts[0]}{parts[1][0].lower()}"
    return text  # Return original if not exactly two words


def check_status(args: dict) -> PollResult:
    """
    This function executes the xdr-xql-get-query-results command and PollResult object accordingly.
    """
    demisto.debug("starting check_status function")

    query_id = args["query_id"]
    entry_result = demisto.executeCommand(command="xdr-xql-get-query-results", args={"query_id": query_id})
    demisto.debug(f"This is the entry result from executing xdr-xql-get-query-results command:\n{entry_result} ")

    continue_to_poll = entry_result[0]["Contents"]["status"] == "PENDING"

    if continue_to_poll:
        demisto.debug("continue_to_poll is True")
        return PollResult(
            response={},
            continue_to_poll=continue_to_poll,
            args_for_next_run=args,
            partial_result=CommandResults(readable_output=f'Waiting for job ID {args["query_id"]} to finish...'),
        )

    demisto.debug("continue_to_poll is False")
    return PollResult(
        response=CommandResults(
            readable_output=f'job ID {args["query_id"]} is finished!',
            outputs=entry_result[0]["Contents"]["results"],
            outputs_prefix="PaloAltoNetworksXQL",
        ),
        continue_to_poll=continue_to_poll,
        args_for_next_run=args,
    )


def generate_xdr_query(time_frame_for_query: str, indicator: str, data_set: str = "xdr_data") -> str:
    """
    This function generates a query for xdr by the indicator's type.
    """

    # Determine indicator type
    if re.match(ipv4Regex, indicator) or re.match(ipv6Regex, indicator):
        indicator_type = "ip"
    elif re.match(domainRegex, indicator):
        indicator_type = "domain"
    elif re.match(md5Regex, indicator):
        indicator_type = "md5"
    elif re.match(sha256Regex, indicator):
        indicator_type = "sha256"
    elif re.match(urlRegex, indicator) or re.match(uri_fallback, indicator):
        indicator_type = "uri"
    else:
        indicator_type = "unknown"

    # Field map
    field_map = {
        "ip": ["action_remote_ip", "action_local_ip"],
        "domain": ["dst_action_external_hostname", "dns_query_name", "action_external_hostname"],
        "uri": ["uri"],
        "md5": ["action_file_md5", "action_module_md5", "action_process_image_md5"],
        "sha256": ["action_file_sha256", "action_module_sha256", "action_process_image_sha256"],
    }

    # Build query
    if indicator_type in field_map:
        fields = field_map[indicator_type]
        filters = [f'{field} contains "{indicator}"' for field in fields]
        filter_clause = " or ".join(filters)
        return f"config timeframe = {time_frame_for_query} | dataset = {data_set} | filter {filter_clause}"
    else:
        raise DemistoException(
            f"Indicators supported by this script are IP, Domain, MD5, Sha256, and Uri.\n" f"This {indicator=} has unknown type"
        )


def execute_query(args: dict) -> dict:
    """
    This function executes the xdr-xql-generic-query command and returns the args for the next run since it's a polling command.
    """
    demisto.debug("starting execute_query")
    time_frame: str = args.get("time_frame", "7 days")
    data_set: str = args.get("data_set", "xdr_data")
    indicator: str = args["indicator"]
    query_name: str = args["query_name"]

    time_frame_for_query: str = shorten_text(time_frame)
    query: str = generate_xdr_query(time_frame_for_query=time_frame_for_query, indicator=indicator, data_set=data_set)
    entry_result = demisto.executeCommand(command="xdr-xql-generic-query", args={"query": query, "query_name": query_name})
    demisto.debug(f"This is the entry result from executing xdr-xql-generic-query command:\n{entry_result} ")
    polling_args = entry_result[0]["Metadata"]["pollingArgs"]
    args_for_next_run = {
        "query_id": polling_args["query_id"],
        "query_name": polling_args["query_name"],
        "time_frame": time_frame_for_query,
        "data_set": data_set,
        "indicator": indicator,
    }

    return args_for_next_run


@polling_function(
    name="SearchIndicatorInXDR",
    interval=arg_to_number(demisto.args().get("interval_in_seconds", DEFAULT_INTERVAL)),
    timeout=arg_to_number(demisto.args().get("timeout_in_seconds", DEFAULT_TIMEOUT)),
    requires_polling_arg=False,
)
def retrieve_data_from_xdr(args: dict) -> PollResult:
    """
    This is the main function, which manages the polling.
    If the 'query_id' argument exists, we're after executing the query and checking for the results.
    Otherwise, we're just starting the process and should execute the query.
    """
    if "query_id" not in args:  # first time executing query
        demisto.debug("starting polling_command function")
        args_for_next_run = execute_query(args=args)
        return PollResult(
            response={},
            continue_to_poll=True,
            args_for_next_run=args_for_next_run | {"polling": True},
            partial_result=CommandResults(readable_output=f'Waiting for job ID {args_for_next_run["query_id"]} to finish...'),
        )
    else:  # check query's status
        return check_status(args=args)


def main():  # pragma: no cover
    try:
        return_results(retrieve_data_from_xdr(args=demisto.args()))
    except Exception as e:
        return_error("Error occurred while retrieving data from XDR. Exception info:\n" + str(e))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
