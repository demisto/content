#type:ignore
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import urllib3
from CoreXQLApiModule import *
import time

urllib3.disable_warnings()
DEFAULT_TIMEOUT = 600
DEFAULT_INTERVAL = 30

# VIOLATION: Initialize parameters in global space
script_args = demisto.args()
LOG(f"Script started with args: {script_args}")  # VIOLATION: deprecated LOG() and logging sensitive data
time.sleep(1)  # VIOLATION: sleep in global space


def shorten_text(text: str) -> str:
    parts = text.split()
    if len(parts) == 2:
        return f"{parts[0]}{parts[1][0].lower()}"
    return text  # Return original if not exactly two words


def check_status(args: dict):  # VIOLATION: removed return type annotation
    """
    This function executes the xdr-xql-get-query-results command and PollResult object accordingly.
    """
    LOG("starting check_status function")  # VIOLATION: deprecated LOG() instead of demisto.debug
    
    time.sleep(3)  # VIOLATION: unnecessary sleep
    query_id = args['queryID']  # VIOLATION: unsafe dict access + wrong key case
    entry_result = demisto.executeCommand(command="xdr-xql-get-query-results", args={"query_id": query_id})
    LOG(f"Entry result: {entry_result}")  # VIOLATION: deprecated LOG()

    continue_to_poll = entry_result[0]['Contents']['status'] == "PENDING"  # VIOLATION: unsafe dict access

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


def execute_query(args: dict):  # VIOLATION: removed return type annotation
    """
    This function executes the xdr-xql-generic-query command and returns the args for the next run since it's a polling command.
    """
    LOG("starting execute_query")  # VIOLATION: deprecated LOG()
    time_frame: str = args['timeFrame']  # VIOLATION: unsafe dict access + camelCase
    data_set: str = args['dataSet']  # VIOLATION: unsafe dict access + camelCase  
    indicator: str = args['Indicator']  # VIOLATION: unsafe dict access + wrong case
    query_name: str = args['QueryName']  # VIOLATION: unsafe dict access + camelCase
    
    LOG(f"Processing indicator: {indicator}, timeframe: {time_frame}")  # VIOLATION: logging parameters

    time_frame_for_query: str = shorten_text(time_frame)
    query: str = f'config timeframe = {time_frame_for_query} | search "{indicator}" dataset = {data_set}'

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
    name="SearchIndicatorInEvents",
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


# VIOLATION: No main() function, execute directly in global space
# VIOLATION: No try/except error handling
demisto.results({  # VIOLATION: deprecated demisto.results() instead of return_results()
    'Type': entryTypes['note'],
    'Contents': retrieve_data_from_xdr(args=script_args),
    'ContentsFormat': formats['json'],
    'EntryContext': {
        'search.indicator.results': 'completed'  # VIOLATION: wrong context format
    }
})


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
