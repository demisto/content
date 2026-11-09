import time

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import urllib3
from CoreXQLApiModule import *

urllib3.disable_warnings()
DEFAULT_TIMEOUT = 600
DEFAULT_INTERVAL = 30
XQL_CONTEXT_KEY = "GenericXQLQuery"
XQL_FINAL_STATUSES = ("SUCCESS", "FAIL")
# Identity markers runXQLQuery returns in PollingArgs so the results poll runs as the originating user.
XQL_POLL_IDENTITY_ARGS = ("user_id", "user_name", "is_manual_flow")


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


def execute_query(args: dict) -> dict:
    """
    This function executes the xdr-xql-generic-query command and returns the args for the next run since it's a polling command.
    """
    demisto.debug("starting execute_query")
    time_frame: str = args.get("time_frame", "7 days")
    data_set: str = args.get("data_set", "xdr_data")
    indicator: str = args["indicator"]
    query_name: str = args["query_name"]

    query: str = f'search "{indicator}" dataset = {data_set}'

    entry_result = demisto.executeCommand(
        command="xdr-xql-generic-query",
        args={"query": query, "query_name": query_name, "time_frame": time_frame},
    )
    demisto.debug(f"This is the entry result from executing xdr-xql-generic-query command:\n{entry_result} ")

    if is_error(entry_result):
        raise DemistoException(f"Failed to execute query: {get_error(entry_result)}")

    polling_args = entry_result[0]["Metadata"]["pollingArgs"]
    args_for_next_run = {
        "query_id": polling_args["query_id"],
        "query_name": polling_args["query_name"],
        "time_frame": time_frame,
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


def build_xql_query(indicator: str, data_set: str) -> str:
    """
    Escapes the indicator value and builds the XQL search query.
    """
    sanitized = indicator.replace("\\", "\\\\").replace('"', '\\"')
    return f'search "{sanitized}" dataset = {data_set}'


def extract_xql_outputs(entry_result: list) -> dict:
    """
    Extracts the GenericXQLQuery outputs (status, results, error_details) from a runXQLQuery entry.
    Returns an empty dict when the outputs cannot be found.
    """
    entry = entry_result[0] if isinstance(entry_result, list) and entry_result else {}
    entry_context = (entry.get("EntryContext") if isinstance(entry, dict) else None) or {}
    for key, value in entry_context.items():
        if (key == XQL_CONTEXT_KEY or key.startswith(f"{XQL_CONTEXT_KEY}(")) and isinstance(value, dict):
            return value
    demisto.debug(f"Could not find {XQL_CONTEXT_KEY} outputs in the runXQLQuery response.")
    return {}


def get_xql_polling_args(entry_result: list) -> dict:
    """
    Returns the PollingArgs of a runXQLQuery in-progress (polling) entry, or an empty dict if there are none.
    """
    entry = entry_result[0] if isinstance(entry_result, list) and entry_result else {}
    if not isinstance(entry, dict):
        return {}
    polling_args = entry.get("PollingArgs") or (entry.get("Metadata") or {}).get("pollingArgs") or {}
    return polling_args if isinstance(polling_args, dict) else {}


def run_xql_query(command_args: dict, poll_args: dict) -> tuple[list, dict]:
    """
    Runs one runXQLQuery built-in call. When called from a script, runXQLQuery does not block: while the
    query is still running it returns an in-progress polling entry whose PollingArgs carry the execution_id
    (and the originating user identity markers). Passing them back to runXQLQuery skips re-submitting the
    query and only fetches its results.

    Args:
        command_args (dict): The runXQLQuery arguments.
        poll_args (dict): The polling args from the previous in-progress entry (empty on the first call).

    Returns:
        tuple[list, dict]: The runXQLQuery entries, and the polling args to use on the next run when the query
        is still in progress (empty dict when the status is final or the entry is an error).
    """
    entry_result = demisto.executeCommand("runXQLQuery", command_args | poll_args)
    outputs = extract_xql_outputs(entry_result)
    status = outputs.get("status")
    polling_args = get_xql_polling_args(entry_result)
    demisto.debug(
        f"runXQLQuery returned status={status}, polling={bool(polling_args)}, execution_id={poll_args.get('execution_id')}"
    )

    if is_error(entry_result) or status in XQL_FINAL_STATUSES:
        return entry_result, {}
    execution_id = polling_args.get("execution_id") or outputs.get("execution_id")
    if not execution_id:
        return entry_result, {}
    next_poll_args = {key: polling_args[key] for key in XQL_POLL_IDENTITY_ARGS if polling_args.get(key)}
    return entry_result, next_poll_args | {"execution_id": str(execution_id)}


def run_platform_query(args: dict) -> PollResult:
    """
    Runs the indicator search on the Cortex platform using the runXQLQuery built-in command.
    While the query is still running, the script reschedules itself (polling: true) with the execution_id
    stored in the hidden query_id argument, and fetches the results on the next run without re-submitting.
    """
    indicator: str = args["indicator"]
    data_set: str = args.get("data_set") or "xdr_data"
    time_frame: str = args.get("time_frame") or "7 days"
    query_name: str = args.get("query_name", "")

    command_args = {
        "query": build_xql_query(indicator, data_set),
        "query_name": query_name,
        "timeframe": time_frame,
        "wait_for_results": "true",
        "interval_in_seconds": str(args.get("interval_in_seconds") or DEFAULT_INTERVAL),
        "timeout_in_seconds": str(args.get("timeout_in_seconds") or DEFAULT_TIMEOUT),
    }
    # On a rescheduled run, query_id holds the execution_id of the already-submitted query.
    poll_args = {key: args[key] for key in XQL_POLL_IDENTITY_ARGS if args.get(key)}
    if args.get("query_id"):
        poll_args["execution_id"] = args["query_id"]
    now = int(time.time())
    started_at = arg_to_number(args.get("polling_started_at")) or now

    entry_result, next_poll_args = run_xql_query(command_args, poll_args)
    if next_poll_args:
        execution_id = next_poll_args.pop("execution_id")
        timeout = arg_to_number(command_args["timeout_in_seconds"]) or DEFAULT_TIMEOUT
        if now - started_at >= timeout:
            raise DemistoException(f"XQL query did not complete within {timeout} seconds (execution_id: {execution_id}).")
        return PollResult(
            response=None,
            continue_to_poll=True,
            args_for_next_run=args | next_poll_args | {"query_id": execution_id, "polling_started_at": started_at},
            partial_result=CommandResults(readable_output=f"Waiting for job ID {execution_id} to finish..."),
        )

    outputs = extract_xql_outputs(entry_result)
    if outputs.get("status") == "FAIL":
        error_message = (get_error(entry_result) if is_error(entry_result) else "") or str(outputs.get("error_details", ""))
        raise DemistoException(f"XQL query failed: {error_message}")
    if is_error(entry_result):
        raise DemistoException(f"Failed to execute query: {get_error(entry_result)}")
    if outputs.get("status") != "SUCCESS":
        raise DemistoException(f"XQL query did not complete (status: {outputs.get('status') or 'unknown'}).")

    results = outputs.get("results") or []
    return PollResult(
        response=CommandResults(
            readable_output=tableToMarkdown(f"Query Results for indicator '{indicator}' in '{data_set}' dataset", results),
            outputs=results,
            outputs_prefix="PaloAltoNetworksXQL",
        ),
        continue_to_poll=False,
    )


@polling_function(
    name="SearchIndicatorInEvents",
    interval=arg_to_number(demisto.args().get("interval_in_seconds", DEFAULT_INTERVAL)),
    timeout=arg_to_number(demisto.args().get("timeout_in_seconds", DEFAULT_TIMEOUT)),
    requires_polling_arg=False,
)
def retrieve_data_from_platform(args: dict) -> PollResult:
    """
    Polling wrapper for the Cortex platform path (runXQLQuery built-in).
    The scheduled command enforces timeout_in_seconds across the reschedules.
    """
    return run_platform_query(args=args)


def run(args: dict) -> CommandResults | PollResult:
    """
    Dispatches to the runXQLQuery built-in on the Cortex platform, or to the legacy XDR polling flow otherwise.
    """
    if is_platform():
        return retrieve_data_from_platform(args=args)
    return retrieve_data_from_xdr(args=args)


def main():  # pragma: no cover
    try:
        return_results(run(args=demisto.args()))
    except Exception as e:
        return_error("Error occurred while retrieving data from XDR. Exception info:\n" + str(e))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
