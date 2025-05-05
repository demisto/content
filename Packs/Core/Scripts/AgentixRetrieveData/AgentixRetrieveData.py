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


def check_status(args: dict) -> bool:
    query_id = args["query_id"]
    res = demisto.executeCommand(command="xdr-xql-get-query-results", args={"query_id": query_id})
    print(res)
    continue_to_poll = (res[0]["Contents"]['status'] == 'PENDING')
    context_output = {
        'QueryID': query_id,
        'Status': res[0]["Contents"]['status']
    }

    return continue_to_poll


def execute_query(args: dict) -> dict:
    print("starting execute_query")
    time_frame: str = args.get("time_frame", "7 days")
    data_set: str = args.get("data_set", "xdr_data")
    indicator: str = args["indicator"]
    query_name: str = args["query_name"]

    time_frame_for_query: str = shorten_text(time_frame)
    query: str = f'config timeframe = {time_frame_for_query} | search "{indicator}" dataset = {data_set}'

    entry_result = demisto.executeCommand(command="xdr-xql-generic-query", args={"query": query, "query_name": query_name})
    print("after - executeCommand  xdr-xql-generic-query")
    demisto.debug(f"This is the entry result from excepting xdr-xql-generic-query command:\n{entry_result} ")
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
def polling_command(args: dict) -> PollResult:
    if "query_id" not in args:  # first time executing query
        print("starting polling_command")
        args_for_next_run = execute_query(args=args)
        print("after - execute_query func")
        poll_result = PollResult(
            response={},
            continue_to_poll=True,
            args_for_next_run=args_for_next_run | {"polling": True},
            partial_result=CommandResults(
                readable_output=f'Waiting for commit job ID {args_for_next_run["query_id"]} to finish...'
            )
        )
    else:  # check query's status
        continue_to_poll = check_status(args=args)
        if continue_to_poll:
            poll_result = PollResult(
                response={},
                continue_to_poll=True,
                args_for_next_run=args,
                partial_result=CommandResults(
                    readable_output=f'Waiting for commit job ID {args["query_id"]} to finish...'
                )
            )
        else:
            print("3")
            poll_result = PollResult(
                response=CommandResults(readable_output=f'Finish!!!'),
                continue_to_poll=False,
                args_for_next_run=args
                )
    return poll_result


def main():
    try:
        return_results(polling_command(args=demisto.args()))
    except Exception as e:
        return_error("Error occurred while retrieving data from XDR. Exception info:\n" + str(e))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
