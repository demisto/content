import time

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

BROKER_CONTEXT_KEY = "Core.Broker"
XQL_CONTEXT_KEY = "GenericXQLQuery"
XQL_FINAL_STATUSES = ("SUCCESS", "FAIL")
XQL_DEFAULT_INTERVAL = 2  # runXQLQuery default interval_in_seconds
XQL_DEFAULT_TIMEOUT = 180  # runXQLQuery default timeout_in_seconds


def get_context_value(entry_result: list, context_key: str) -> Any:
    """
    Returns the value stored under context_key (with or without a DT selector suffix) in the
    EntryContext of the first entry returned by a built-in command, or None if it is missing.
    """
    entry = entry_result[0] if isinstance(entry_result, list) and entry_result else {}
    entry_context = (entry.get("EntryContext") if isinstance(entry, dict) else None) or {}
    for key, value in entry_context.items():
        if key == context_key or key.startswith(f"{context_key}("):
            return value
    return None


def extract_broker_list(broker_result: list) -> list:
    """
    Extracts the list of brokers from a getBrokers response.
    The brokers are stored in the EntryContext under Core.Broker.
    Returns an empty list when no brokers were found.
    """
    brokers = get_context_value(broker_result, BROKER_CONTEXT_KEY) or []
    if isinstance(brokers, dict):
        brokers = [brokers]
    return [broker for broker in brokers if isinstance(broker, dict)]


def extract_xql_outputs(xql_result: list) -> dict:
    """
    Extracts the query outputs (status, results, error_details) from a runXQLQuery response.
    The outputs are stored in the EntryContext under GenericXQLQuery.
    """
    outputs = get_context_value(xql_result, XQL_CONTEXT_KEY)
    return outputs if isinstance(outputs, dict) else {}


def get_xql_polling_args(xql_result: list) -> dict:
    """
    Returns the PollingArgs of a runXQLQuery in-progress (polling) entry, or an empty dict if there are none.
    """
    entry = xql_result[0] if isinstance(xql_result, list) and xql_result else {}
    if not isinstance(entry, dict):
        return {}
    polling_args = entry.get("PollingArgs") or (entry.get("Metadata") or {}).get("pollingArgs") or {}
    return polling_args if isinstance(polling_args, dict) else {}


def run_xql_query(xql_args: dict) -> list:
    """
    Runs the runXQLQuery built-in command and waits for a final status.
    When called from a script, runXQLQuery returns an in-progress polling entry instead of blocking.
    In that case it is called again with the returned PollingArgs (which carry the execution_id, so the
    query is not re-submitted and only its results are fetched) until the status is SUCCESS / FAIL,
    an error is returned, or the timeout is reached.
    """
    next_args = dict(xql_args)
    waited = 0
    while True:
        xql_result = demisto.executeCommand("runXQLQuery", next_args)
        outputs = extract_xql_outputs(xql_result)
        status = outputs.get("status")
        polling_args = get_xql_polling_args(xql_result)
        demisto.debug(f"runXQLQuery returned status={status}, polling={bool(polling_args)}, waited={waited}s")

        if is_error(xql_result) or status in XQL_FINAL_STATUSES:
            return xql_result

        if polling_args:
            next_args = polling_args
        elif outputs.get("execution_id"):
            next_args = next_args | {"execution_id": outputs["execution_id"]}
        execution_id = next_args.get("execution_id")
        if not execution_id:
            # Nothing to poll on, let the caller handle the unexpected response.
            return xql_result

        interval = arg_to_number(next_args.get("interval_in_seconds")) or XQL_DEFAULT_INTERVAL
        timeout = arg_to_number(next_args.get("timeout_in_seconds")) or XQL_DEFAULT_TIMEOUT
        if waited >= timeout:
            raise DemistoException(f"XQL query did not complete within {timeout} seconds (execution_id: {execution_id}).")
        # Bounded wait (capped by runXQLQuery's timeout_in_seconds): this non-polling script must block until
        # the built-in returns a final status, since runXQLQuery does not block when called from a script.
        time.sleep(interval)  # pylint: disable=E9003
        waited += interval


def diagnose_syslog_collector(broker_vm_name: str, timeframe: str) -> CommandResults:
    """
    Diagnoses why the syslog collector on a specified Broker VM is failing.

    This function performs the following checks:
    1. Calls the getBrokers built-in command to get broker information
    2. Checks if the Syslog Collector app is present and has "Active" status
    3. If collector is valid, queries collection_auditing for errors/warnings using the runXQLQuery built-in command

    Args:
        broker_vm_name (str): The name of the Broker VM to diagnose.
        timeframe (str): Timeframe for error checking (default: "24 hours")

    Returns:
        CommandResults: Object containing the diagnostic results.
    """
    default_limit = 10

    demisto.debug(f"Starting syslog collector diagnosis for broker: {broker_vm_name}")

    # Get basic broker information
    broker_result = demisto.executeCommand("getBrokers", {"broker_vm_names": broker_vm_name})

    if is_error(broker_result) or not broker_result or not isinstance(broker_result, list):
        if is_error(broker_result):
            demisto.debug(f"Error retrieving broker information: {get_error(broker_result)}")
        raise DemistoException("Failed to retrieve broker information: Internal Error.")

    broker_data_list = extract_broker_list(broker_result)

    if not broker_data_list:
        raise DemistoException(f"Broker VM '{broker_vm_name}' not found")

    broker_data = broker_data_list[0]
    demisto.debug(f"Found broker data: {broker_data}")

    # Check if Syslog Collector app exists and is active
    apps = broker_data.get("Apps") or broker_data.get("APPS") or []
    syslog_collector = None

    for app in apps:
        if app.get("display_name") == "Syslog Collector":
            syslog_collector = app
            break

    # Build diagnosis report
    diagnosis_report = []

    if not syslog_collector:
        status = "ERROR"
        diagnosis_report.append(f"The Syslog Collector app is not configured on broker '{broker_vm_name}'")
    else:
        collector_status = syslog_collector.get("status", "").lower()

        if collector_status != "active":
            status = "ERROR"
            diagnosis_report.append(f"Syslog Collector status is '{collector_status}' (expected 'active')")

            # Extract additional information from the reasons field
            reasons = syslog_collector.get("reasons", {})
            if reasons:
                errors = reasons.get("errors", [])
                warnings = reasons.get("warnings", [])

                # Add errors to diagnosis report
                for error in errors:
                    if error:
                        diagnosis_report.append(f"[ERROR] {error}")

                # Add warnings to diagnosis report
                for warning in warnings:
                    if warning:
                        diagnosis_report.append(f"[WARNING] {warning}")
        else:
            # Step 3: Collector is active, check for errors in collection_auditing
            demisto.debug("Syslog Collector is active, checking for errors in collection_auditing")

            xql_query = f"""
dataset = collection_auditing
| filter collector_type = "Syslog Collector"
  and _broker_device_name = "{broker_vm_name}"
  and classification in ("ERROR", "WARNING")
| fields _time, classification, description
| limit {default_limit}
"""
            try:
                # Call the runXQLQuery built-in command
                xql_args = {
                    "query": xql_query,
                    "timeframe": timeframe,
                    "wait_for_results": "true",
                }

                demisto.debug(f"Executing XQL query with args: {xql_args}")
                xql_result = run_xql_query(xql_args)

                if not xql_result or not isinstance(xql_result, list):
                    raise DemistoException("Failed to execute XQL query")

                xql_outputs = extract_xql_outputs(xql_result)

                # A FAILed query is returned as an error entry that still holds the query outputs.
                if is_error(xql_result) and xql_outputs.get("status") != "FAIL":
                    demisto.debug(f"XQL query failed: {get_error(xql_result)}")
                    raise DemistoException("Failed to execute XQL query")

                query_status = xql_outputs.get("status")
                errors_found = xql_outputs.get("results", [])

                demisto.debug(f"XQL Query finished with status={query_status}, found {len(errors_found)} Syslog errors.")

                if query_status == "SUCCESS":
                    if errors_found:
                        status = "WARNING"
                        # Deduplicate errors by description
                        seen_descriptions = set()
                        for error in errors_found:
                            error_desc = error.get("description", "")
                            if error_desc and error_desc not in seen_descriptions:
                                seen_descriptions.add(error_desc)
                                classification = error.get("classification", "UNKNOWN")
                                timestamp = error.get("_time", "")
                                diagnosis_report.append(f"[{timestamp}][{classification}] {error_desc}")
                    else:
                        status = "HEALTHY"
                        diagnosis_report.append(f"Syslog Collector is active with no errors in the last {timeframe}")
                else:
                    status = "ERROR"
                    error_details = (get_error(xql_result) if is_error(xql_result) else "") or str(
                        xql_outputs.get("error_details") or f"XQL query finished with status {query_status}"
                    )
                    raise DemistoException(error_details)

            except Exception as e:
                raise DemistoException(f"Internal error while trying to query collection_auditing. {str(e)}")

    # Final output with only status and diagnosis_report
    diagnostics = {
        "status": status,
        "diagnosis_report": diagnosis_report,
    }

    readable_output = tableToMarkdown(
        f"Syslog Collector Diagnostics for {broker_vm_name}",
        diagnostics,
        headerTransform=string_to_table_header,
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Core.SyslogCollectorDiagnostics",
        outputs_key_field="status",
        outputs=diagnostics,
    )


def main():
    args = demisto.args()
    broker_vm_name = args.get("broker_vm_name")
    timeframe = args.get("timeframe", "24 hours")

    if not broker_vm_name:
        return_error("Broker VM name is required for diagnosing the syslog collector.")

    try:
        return_results(diagnose_syslog_collector(broker_vm_name, timeframe))
    except Exception as e:
        error_msg = str(e) if str(e) else repr(e)
        demisto.error(f"DiagnoseSyslogCollector script failed: {error_msg}\n{traceback.format_exc()}")
        return_error(f"Failed to execute DiagnoseSyslogCollector script.\nError: {error_msg}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
