import demistomock as demisto
from CommonServerPython import *


def add_new_comment(context_results: dict):
    incident_id = context_results.get("CustomFields").get("sourceid")  # type: ignore
    instance_name = next((item['value'] for item in context_results.get("labels", []) if item['type'] == 'Instance'), None)
    new_comment = demisto.args().get("new_comment")

    demisto.debug(f"update remote incident with new XSOAR comments: {new_comment}")
    execute_command(
        "azure-sentinel-incident-add-comment",
        {"using": instance_name, "incident_id": incident_id, "message": new_comment},
    )
    readable_output = tableToMarkdown('The new comment has been recorded and will appear in your comments field in a minute (Only if you have A \'Mirror In\')',  # noqa: E501
                                      {"Instance Name": instance_name, "New Comment": new_comment},
                                      headers=["New Comment", "Instance Name"],
                                      removeNull=True)
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='AzureSentinel.AddComment',
        outputs={"incident_id": incident_id, "message": new_comment},
    )


def main():  # pragma: no cover
    context = dict_safe_get(demisto.callingContext, ["context", "Incidents", 0], {})

    if not context:
        return_error("No data to present")

    return_results(add_new_comment(context))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
