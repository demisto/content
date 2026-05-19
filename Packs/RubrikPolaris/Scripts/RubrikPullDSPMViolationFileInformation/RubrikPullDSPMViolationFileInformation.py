import demistomock as demisto
from CommonServerPython import *

ERROR_MESSAGES = {"MISSING_ARGUMENT": "Please provide correct input for '{}' argument."}
HR_DATE_TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

""" COMMAND FUNCTION """


def sync_the_violation_file_information(args: dict[str, Any]) -> list:
    """
    Sync the DSPM Violation file information from RSC.

    :type args: ``Dict[str, Any]``
    :param args: Arguments provided by user.

    :rtype: ``list``
    :return: command result.
    """
    remove_nulls_from_dictionary(args)

    incident_info = demisto.incident()
    incident_violation_id = demisto.get(incident_info, "CustomFields.rubrikviolationid")
    incident_object_id = demisto.get(incident_info, "CustomFields.rubrikpolarisobjectid")
    incident_snapshot_id = demisto.get(incident_info, "CustomFields.rubriksnapshotid")

    violation_id = args.get("violation_id") or incident_violation_id
    object_id = args.get("object_id") or incident_object_id
    snapshot_id = args.get("snapshot_id") or incident_snapshot_id
    limit = arg_to_number(args.get("limit", 1000))

    if not violation_id:
        raise ValueError(ERROR_MESSAGES["MISSING_ARGUMENT"].format("violation_id"))
    if not object_id:
        raise ValueError(ERROR_MESSAGES["MISSING_ARGUMENT"].format("object_id"))
    if not snapshot_id:
        raise ValueError(ERROR_MESSAGES["MISSING_ARGUMENT"].format("snapshot_id"))

    command_args = {"violation_id": violation_id, "object_id": object_id, "snapshot_id": snapshot_id, "limit": limit}

    command_results = demisto.executeCommand("rubrik-data-security-violation-file-list", command_args)
    if not isinstance(command_results, list):
        command_results = [command_results]

    command_result = {}
    for cmd_result in command_results:
        if not isError(cmd_result):
            command_result = cmd_result
            break

    if not command_result:
        raise ValueError(f"Failed to get violation file information: {command_results[0].get('Contents')}")

    response = command_result.get("Contents")
    file_info = demisto.get(response, "data.policyObj.fileResultConnection", {})
    edges = file_info.get("edges", [])

    file_data = []
    for edge in edges:
        node = edge.get("node", {})
        total_risk_hits = demisto.get(node, "hits.violations") or 0
        high_risk_hits = demisto.get(node, "sensitiveHits.highRiskHits.violatedHits") or 0
        medium_risk_hits = demisto.get(node, "sensitiveHits.mediumRiskHits.violatedHits") or 0
        low_risk_hits = demisto.get(node, "sensitiveHits.lowRiskHits.violatedHits") or 0
        no_risk_hits = demisto.get(node, "sensitiveHits.noRiskHits.violatedHits") or 0
        last_modified_time = node.get("lastModifiedTime")
        last_modified_time_str = (
            datetime.fromtimestamp(last_modified_time, tz=timezone.utc).strftime(HR_DATE_TIME_FORMAT)
            if last_modified_time is not None
            else ""
        )
        data_categories = [
            {
                "name": demisto.get(result, "analyzerGroup.name"),
                "totalViolatedHits": demisto.get(result, "hits.violations") or 0,
            }
            for result in node.get("analyzerGroupResults", [])
        ]
        file_data.append(
            {
                "stdPath": node.get("stdPath", ""),
                "createdBy": node.get("createdBy", ""),
                "lastModifiedTime": last_modified_time_str,
                "size": node.get("size", 0),
                "totalHits": total_risk_hits,
                "highRiskHits": high_risk_hits,
                "mediumRiskHits": medium_risk_hits,
                "lowRiskHits": low_risk_hits,
                "noRiskHits": no_risk_hits,
                "dataCategories": data_categories,
            }
        )

    results: list = [command_result]
    if file_data:
        demisto.executeCommand("setIncident", {"rubrikfilesatrisk": file_data})
        results.append(
            CommandResults(readable_output=f"#### Violation {violation_id} file information has been synchronized successfully.")
        )

    return results


""" MAIN FUNCTION """


def main():
    try:
        return_results(sync_the_violation_file_information(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Failed to execute RubrikPullDSPMViolationFileInformation-RubrikSecurityCloud. Error: {ex!s}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
