import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from typing import Any
import traceback


def rcs_scan_set_context(scan_id: str, demisto: Any):
    """
    Sets the RCSScanId in the context.

    Args:
        scan_id (str): The scan ID to be set in the context.

    Returns:
        None: The function returns_results() handles the output.
    """
    context_get = demisto.context()

    # If the context was not previously set
    if "RCSScanId" not in context_get.keys():
        args_set_scan = {"key": "RCSScanId", "value": scan_id}
        demisto.executeCommand("Set", args_set_scan)
        return "RCSScanId Key Value set"

    # If the context was previously set, then check if it is same as new value.
    # If its the same value, dont do anything, otherwise, delete old value and set new value
    elif "RCSScanId" in context_get.keys() and scan_id != context_get["RCSScanId"]:
        # Delete Old Scan ID
        delete_args = {"key": "RCSScanId"}
        demisto.executeCommand("DeleteContext", delete_args)

        args_set_scan = {"key": "RCSScanId", "value": scan_id}
        demisto.executeCommand("Set", args_set_scan)
        return "Updated RCSScanId Key Value"
    return "RCSScanId remains unchanged"


def rcs_scan_start(
    service_id: str, attack_surface_rule_id: str, alert_internal_id: str, demisto: Any
):
    """
    Main command that kicks off a RCS confirmation scan and gets the status of the scan.

    Args:
        args: A dictionary of arguments passed to the function.

    Returns:
        A dictionary containing the scan ID, creation status, and scan status.
    """

    args_scan_start = {
        "service_id": service_id,
        "attack_surface_rule_id": attack_surface_rule_id,
        "alert_internal_id": alert_internal_id,
    }
    output_scan_start = demisto.executeCommand(
        "asm-start-remediation-confirmation-scan", args_scan_start
    )

    # Raise error if the command execution failed
    if output_scan_start[0].get("Type") and "Failed to execute" in output_scan_start[
        0
    ].get("Contents"):
        raise ValueError("Failed to execute RCSScanStatus. Check input values.")

    scan_id = output_scan_start[0].get("Contents").get("reply").get("scanId")

    if scan_id:
        return rcs_scan_set_context(scan_id, demisto)


def main():
    args = demisto.args()
    service_id, attack_surface_rule_id, alert_internal_id = (
        args.get("service_id"),
        args.get("attack_surface_rule_id"),
        args.get("alert_internal_id"),
    )

    if not service_id:
        raise ValueError("service_id argument need to be specified")

    if not attack_surface_rule_id:
        raise ValueError("attack_surface_rule_id argument needs to be specified")

    if not alert_internal_id:
        raise ValueError("alert_internal_id argument needs to be specified")

    try:
        return_results(
            rcs_scan_start(
                service_id, attack_surface_rule_id, alert_internal_id, demisto
            )
        )
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Failed to execute RCSScanStatus. Error: {str(ex)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
