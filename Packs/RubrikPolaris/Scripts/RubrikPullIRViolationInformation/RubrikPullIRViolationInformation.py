import demistomock as demisto
from CommonServerPython import *

ERROR_MESSAGES = {"MISSING_ARGUMENT": "Please provide correct input for '{}' argument."}

""" COMMAND FUNCTION """


def sync_the_violation_information(args: dict[str, Any]) -> list:
    """
    Sync the IR Violation information from RSC.

    :type args: ``Dict[str, Any]``
    :param args: Arguments provided by user.

    :rtype: ``list``
    :return: command result.
    """
    remove_nulls_from_dictionary(args)

    incident_info = demisto.incident()
    incident_violation_id = demisto.get(incident_info, "CustomFields.rubrikviolationid")
    incident_policy_type = demisto.get(incident_info, "CustomFields.rubrikpolicytype")
    violation_id = args.get("violation_id") or incident_violation_id
    policy_type = args.get("policy_type") or incident_policy_type

    if not violation_id:
        raise ValueError(ERROR_MESSAGES["MISSING_ARGUMENT"].format("violation_id"))

    command_args = {"violation_id": violation_id, "policy_type": policy_type}

    command_results = demisto.executeCommand("rubrik-identity-resilience-violation-get", command_args)
    if not isinstance(command_results, list):
        command_results = [command_results]

    command_result = {}
    for cmd_result in command_results:
        if not isError(cmd_result):
            command_result = cmd_result
            break

    if not command_result:
        raise ValueError(f"Failed to sync the violation information: {command_results[0].get('Contents')}")

    response = command_result.get("Contents")
    violation_data = demisto.get(response, "data.policyViolation") or {}
    mapped_object = demisto.mapObject(violation_data, "Rubrik Polaris Radar - Mapping", "Rubrik IR Violation") or {}
    updated_mapped_data = {}

    for key, value in mapped_object.items():
        new_key = "".join(key.lower().split())
        updated_mapped_data[new_key] = value

    principal_summary = demisto.get(response, "principal_summary_data.data.principalSummary.summary") or {}

    data_categories = principal_summary.get("dataCategoryResults", [])
    data_categories_data = [
        {
            "name": dc.get("dataCategoryName"),
            "totalViolatedHits": demisto.get(dc, "dataCategoryHits.totalViolatedHits", 0),
        }
        for dc in data_categories
    ]

    sensitive_hits = principal_summary.get("sensitiveHits") or {}
    total_risk_hits = demisto.get(sensitive_hits, "totalHits.violatedHits", 0)
    high_risk_hits = demisto.get(sensitive_hits, "highRiskHits.violatedHits", 0)
    medium_risk_hits = demisto.get(sensitive_hits, "mediumRiskHits.violatedHits", 0)
    low_risk_hits = demisto.get(sensitive_hits, "lowRiskHits.violatedHits", 0)
    no_risk_hits = demisto.get(sensitive_hits, "noRiskHits.violatedHits", 0)
    identity_tags = principal_summary.get("identityTags")

    principal_summary_data: dict[str, Any] = {
        "rubriktotalriskhits": total_risk_hits,
        "rubrikhighriskhits": high_risk_hits,
        "rubrikmediumriskhits": medium_risk_hits,
        "rubriklowriskhits": low_risk_hits,
        "rubriknoriskhits": no_risk_hits,
        "rubrikdatacategories": data_categories_data,
        "rubrikidentitytags": identity_tags,
    }
    remove_nulls_from_dictionary(principal_summary_data)

    updated_mapped_data.update(principal_summary_data)

    results: list = [command_result]
    if updated_mapped_data:
        demisto.executeCommand("setIncident", updated_mapped_data)

    results.append(
        CommandResults(readable_output=f"#### Violation {violation_id} information has been synchronized successfully.")
    )

    return results


""" MAIN FUNCTION """


def main():
    try:
        return_results(sync_the_violation_information(demisto.args()))
    except Exception as ex:
        return_error(f"Failed to execute RubrikPullIRViolationInformation-RubrikSecurityCloud. Error: {ex!s}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
