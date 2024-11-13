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
    args = demisto.args()
    incident_id = args.get("incident_id") or dict_safe_get(
        context_results, ["CustomFields", "sourceid"], ""
    )
    instance_name = context_results.get("sourceInstance") or args.get("using")
    user_principal_email = args.get("user_principal_name")
    if not instance_name:
        return_error(
            message="Missing instance name. \
                Make sure to provide a non-empty 'using' argument when executing the script from the War Room."
        )
    if not user_principal_email:
        return_error(
            message="Please provide a not empty 'user_principal_name' as an argument when executing the script from the War Room."
        )
    if not incident_id:
        return_error(
            message="""The specified 'incident_id' was not found.
            Please ensure you provide a valid 'incident_id' as an argument when executing the script from the War Room."""
        )

    result = execute_command(
        "azure-sentinel-update-incident",
        {
            "using": instance_name,
            "incident_id": incident_id,
            "user_principal_name": user_principal_email,
        },
    )
    demisto.info(
        f"Assigned remote incident owner: Incident ID {incident_id}, \
            Instance Name {instance_name}, Owner Email {user_principal_email}."
    )
    return result


def main():  # pragma: no cover
    context = dict_safe_get(demisto.callingContext, ["context", "Incidents", 0], {})

    if not context:
        return_error("No data to present")

    return_results(set_owner(context))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
