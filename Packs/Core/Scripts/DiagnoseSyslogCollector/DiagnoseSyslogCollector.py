import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def diagnose_syslog_collector(broker_vm_name: str, timeframe: str) -> CommandResults:
    """
    Diagnoses why the syslog collector on a specified Broker VM is failing.

    This function performs the following checks:
    1. Calls core-list-brokers to get broker information
    2. Checks if the Syslog Collector app is present and has "Active" status
    3. If collector is valid, queries collection_auditing for errors/warnings using core-xql-generic-query-platform

    Args:
        broker_vm_name (str): The name of the Broker VM to diagnose.
        timeframe (str): Timeframe for error checking (default: "24 hours")

    Returns:
        CommandResults: Object containing the diagnostic results.
    """
    default_limit = 10

    demisto.debug(f"Starting syslog collector diagnosis for broker: {broker_vm_name}")

    # Get basic broker information
    broker_result = demisto.executeCommand("core-list-brokers", {"broker_vm_names": broker_vm_name})

    if is_error(broker_result) or not broker_result or not isinstance(broker_result, list):
        if is_error(broker_result):
            demisto.debug(f"Error retrieving broker information: {get_error(broker_result)}")
        raise DemistoException("Failed to retrieve broker information: Internal Error.")

    broker_data_list = broker_result[0].get("Contents", [])

    if not broker_data_list or not isinstance(broker_data_list, list):
        raise DemistoException(f"Broker VM '{broker_vm_name}' not found")

    broker_data = broker_data_list[0]
    demisto.debug(f"Found broker data: {broker_data}")

    # Check if Syslog Collector app exists and is active
    apps = broker_data.get("APPS", [])
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
                # Call core-xql-generic-query-platform
                xql_args = {
                    "query": xql_query,
                    "timeframe": timeframe,
                    "wait_for_results": "true",
                }

                demisto.debug(f"Executing XQL query with args: {xql_args}")
                xql_result = demisto.executeCommand("core-xql-generic-query-platform", xql_args)

                demisto.debug(f"XQL query result: {xql_result}")

                if is_error(xql_result) or not xql_result or not isinstance(xql_result, list) or len(xql_result) == 0:
                    if is_error(xql_result):
                        demisto.debug(f"XQL query failed: {get_error(xql_result)}")
                    raise DemistoException("Failed to execute XQL query")

                xql_outputs = xql_result[0].get("Contents", {})
                demisto.debug(f"XQL outputs: {xql_outputs}")

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
                    error_details = xql_outputs.get("error_details")
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
