from CommonServerPython import *  # noqa: F401

""" CONSTANTS """

# The `getRawAlerts` command is only available from this server version onwards.
# On older servers we fall back to the legacy `core-get-cloud-original-alerts` command.
MIN_SERVER_VERSION_FOR_RAW_ALERTS = "8.16.0"

""" COMMAND FUNCTION """


def get_additonal_info() -> List[Dict]:
    alerts = demisto.context().get("Core", {}).get("OriginalAlert")
    if not alerts:
        # No original alert in context (e.g. the issue has no cloud-analytics original
        # alert, or retrieval returned nothing). Return an empty result so the widget
        # renders a friendly message instead of surfacing an error banner.
        return []
    if not isinstance(alerts, list):
        alerts = [alerts]

    results = []
    for alert in alerts:
        # Alerts with no XDR cloud-analytics event are returned without an "event" key
        # (both getRawAlerts and the legacy core-get-cloud-original-alerts omit it in that
        # case - see filter_general_fields "No XDR cloud analytics event"). Default to an
        # empty dict so the per-field .get() calls below degrade gracefully instead of
        # raising 'NoneType' object has no attribute 'get'.
        alert_event = alert.get("event") or {}
        res = {
            "Alert Full Description": alert.get("alert_full_description"),
            "Detection Module": alert.get("detection_modules"),
            "Vendor": alert_event.get("vendor"),
            "Provider": alert_event.get("cloud_provider"),
            "Log Name": alert_event.get("log_name"),
            "Event Type": demisto.get(alert_event, "raw_log.eventType"),
            "Caller IP": alert_event.get("caller_ip"),
            "Caller IP Geo Location": alert_event.get("caller_ip_geolocation"),
            "Resource Type": alert_event.get("resource_type"),
            "Identity Name": alert_event.get("identity_name"),
            "Operation Name": alert_event.get("operation_name"),
            "Operation Status": alert_event.get("operation_status"),
            "User Agent": alert_event.get("user_agent"),
        }
        results.append(res)
    indicators = [res.get("Caller IP") for res in results]
    indicators_callable = indicators_value_to_clickable(indicators)
    for res in results:
        res["Caller IP"] = indicators_callable.get(res.get("Caller IP"))
    return results


def verify_list_type(original_alert_data):
    if not isinstance(original_alert_data, list) or not original_alert_data:
        return None
    entry_context = original_alert_data[0].get("EntryContext") or {}
    # Match the `Core.OriginalAlert` prefix so we are resilient to the exact DT selector form.
    original_alert_key = next(
        (key for key in entry_context if key.startswith("Core.OriginalAlert")),
        None,
    )
    if not original_alert_key:
        return None
    res = {"OriginalAlert": entry_context.pop(original_alert_key)}
    if isinstance(res["OriginalAlert"], list):
        res["OriginalAlert"] = res["OriginalAlert"][0]
    return res


""" MAIN FUNCTION """


def main():  # pragma: no cover
    try:
        alert_context = demisto.investigation()
        core_alert_context = demisto.context().get("Core", {})
        if not core_alert_context.get("OriginalAlert"):
            if is_demisto_version_ge(MIN_SERVER_VERSION_FOR_RAW_ALERTS):
                original_alert_data = demisto.executeCommand("getRawAlerts", {"issue_ids": alert_context.get("id")})
            else:
                original_alert_data = demisto.executeCommand(
                    "core-get-cloud-original-alerts", {"alert_ids": alert_context.get("id")}
                )
            if isError(original_alert_data):
                raise DemistoException(f"Failed to retrieve original alerts: {get_error(original_alert_data)}")
            if original_alert_data:
                res = verify_list_type(original_alert_data)
                if res:
                    demisto.executeCommand("SetByIncidentId", {"key": "Core", "value": res, "id": alert_context.get("id")})
        results = get_additonal_info()
        if not results:
            # Nothing to show (no cloud-analytics original alert for this issue).
            return_results(CommandResults(readable_output="No additional alert information available."))
            return
        command_results = CommandResults(
            readable_output=tableToMarkdown("Original Alert Additional Information", results, headers=list(results[0].keys()))
        )
        return_results(command_results)
    except Exception as ex:
        return_error(f"Failed to execute AdditionalAlertInformationWidget. Error: {ex!s}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
