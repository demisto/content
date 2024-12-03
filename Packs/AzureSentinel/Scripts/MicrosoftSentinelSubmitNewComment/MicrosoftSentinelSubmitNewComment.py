import demistomock as demisto
from CommonServerPython import *


def add_new_comment(context_results: dict):
    """
    Adds a new comment to an Azure Sentinel incident and returns the result.

    Args:
        context_results (dict): Contains incident details, including "CustomFields" with "sourceid" for the incident ID
                                and "sourceInstance" for the instance name.

    Returns:
        CommandResults: Includes a markdown-formatted string confirming the new comment and the comment details.
    """
    args = demisto.args()

    incident_id = args.get("incident_id") or dict_safe_get(
        context_results, ["CustomFields", "sourceid"], ""
    )
    instance_name = context_results.get("sourceInstance") or args.get("using")
    new_comment = args.get("new_comment")
    if not instance_name:
        return_error(
            "Please provide a not empty 'using' as an argument when executing the script from the War Room."
        )
    if not new_comment:
        return_error(
            "New comment not provided. Please provide the 'new_comment' argument when running the script from the War Room."
        )
    if not incident_id:
        return_error(
            "Incident ID not found. \
                Please provide the remote 'incident_id' either as an argument when running the script from the War Room."
        )
    execute_command(
        "azure-sentinel-incident-add-comment",
        {"using": instance_name, "incident_id": incident_id, "message": new_comment},
    )

    demisto.info(f"update remote incident with new XSOAR comment: {new_comment}")

    readable_output = tableToMarkdown(
        "The new comment has been recorded and will appear in your comments field shortly.",
        {"Instance Name": instance_name, "New Comment": new_comment},
        headers=["New Comment", "Instance Name"],
        removeNull=True,
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="AzureSentinel.AddComment",
        outputs={
            "IncidentId": incident_id,
            "Message": new_comment,
            "InstanceName": instance_name,
        },
    )


def main():  # pragma: no cover
    context = dict_safe_get(demisto.callingContext, ["context", "Incidents", 0], {})

    if not context:
        return_error("No data to present")

    return_results(add_new_comment(context))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
