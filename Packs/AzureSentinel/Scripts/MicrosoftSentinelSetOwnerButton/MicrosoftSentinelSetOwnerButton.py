import demistomock as demisto
from CommonServerPython import *


def set_owner(context_results: dict):
    """
    Updates the owner of an Azure Sentinel incident and returns the results.

    Args:
        context_results (dict): Contains incident details including "CustomFields" with "sourceid" for the incident ID
                                and "labels" with an "Instance" type label for the instance name.

    Returns:
        CommandResults: Includes a markdown-formatted string with the updated owner details,
                         and the updated owner information.
    """
    incident_id = context_results.get("CustomFields").get("sourceid")  # type: ignore
    instance_name = context_results.get("sourceInstance")
    user_principal_email = demisto.args().get("owner_email")

    demisto.debug(f"set owner remote incident with owner email {user_principal_email}")
    result = execute_command(
        "azure-sentinel-update-incident",
        {
            "using": instance_name,
            "incident_id": incident_id,
            "user_principal_name": user_principal_email,
        },
    )
    remote_owner: dict = dict_safe_get(result, ["properties", "owner"])  # type: ignore
    readable_output = tableToMarkdown(
        f"Updated incident {incident_id} with new owner",
        remote_owner,
        headers=list(remote_owner.keys()),
        headerTransform=pascalToSpace,
        removeNull=True,
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="AzureSentinel.Incident.Owner",
        outputs=remote_owner,
        raw_response=result,
    )


def main():  # pragma: no cover
    context = dict_safe_get(demisto.callingContext, ["context", "Incidents", 0], {})

    if not context:
        return_error("No data to present")

    return_results(set_owner(context))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
