import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import urllib3
from CoreXQLApiModule import *

urllib3.disable_warnings()

XDR = "PaloAltoNetworksXQL.GenericQuery(val.execution_id && val.execution_id == obj.execution_id)"


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

    continue_to_poll = (entry_result[0]["Contents"]['status'] == 'PENDING')

    if continue_to_poll:
        demisto.debug("continue_to_poll is True")
        return PollResult(
            response={},
            continue_to_poll=continue_to_poll,
            args_for_next_run=args,
            partial_result=CommandResults(
                readable_output=f'Waiting for job ID {args["query_id"]} to finish...'
            ),
        )

    demisto.debug("continue_to_poll is False")
    return PollResult(
        response=CommandResults(readable_output=f'job ID {args["query_id"]} is finished!',
                                outputs=entry_result[0]["Contents"]["results"],
                                outputs_prefix="PaloAltoNetworksXQL"),
        continue_to_poll=continue_to_poll,
        args_for_next_run=args,
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
    query: str = f'config timeframe = {time_frame_for_query} | search "{indicator}" dataset = {data_set}'

    entry_result = demisto.executeCommand(command="xdr-xql-generic-query", args={"query": query, "query_name": query_name})
    demisto.debug(f"This is the entry result from executing xdr-xql-generic-query command:\n{entry_result} ")
    polling_args = entry_result[0]["Metadata"]["pollingArgs"]
    args_for_next_run = {"query_id": polling_args["query_id"],
                         "query_name": polling_args["query_name"],
                         'time_frame': time_frame_for_query,
                         'data_set': data_set,
                         "indicator": indicator,
                         }

    return args_for_next_run


@polling_function(
    name='AgentixRetrieveData',
    interval=30,
    timeout=600,
    requires_polling_arg=False
)
def retrieve_data_from_xdr(args: dict) -> PollResult:
    if "query_id" not in args:  # first time executing query
        demisto.debug("starting polling_command function")
        args_for_next_run = execute_query(args=args)
        demisto.debug("After - execute_query function")
        return PollResult(
            response={},
            continue_to_poll=True,
            args_for_next_run=args_for_next_run | {"polling": True},
            partial_result=CommandResults(
                readable_output=f'Waiting for job ID {args_for_next_run["query_id"]} to finish...'
            ),
        )
    else:  # check query's status
        return check_status(args=args)


def main():
    try:
        return_results(retrieve_data_from_xdr(args=demisto.args()))
    except Exception as e:
        return_error("Error occurred while retrieving data from XDR. Exception info:\n" + str(e))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
