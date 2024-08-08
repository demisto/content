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
    print(f"{args=}")
    
    incident_id = dict_safe_get(context_results, ["CustomFields", "sourceid"], "") or args.get("incident_id")  # type: ignore
    instance_name = context_results.get("sourceInstance") or args.get("using")
    new_comment = args.get("new_comment")
    if not incident_id:
        return_error(
            "Incident ID not found. Please provide the remote 'incident_id' either as an argument when running the script from the War Room."  # noqa: E501
        )

    demisto.debug(f"update remote incident with new XSOAR comments: {new_comment}")
    execute_command(
        "azure-sentinel-incident-add-comment",
        {"using": instance_name, "incident_id": incident_id, "message": new_comment},
    )
    readable_output = tableToMarkdown(
        "The new comment has been recorded and will appear in your comments field in a minute \n(Only if you have A 'Mirror In')",  # noqa: E501
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
