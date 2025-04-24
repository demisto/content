import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

"""
  Script Name: DSPMExtractRiskDetails
  Description:
  This script extracts risk details from an incident object, processes asset tags,
  and sets the user's Slack email for future notifications. It retrieves the incident
  details, including risk information, asset tags, and configuration details from the DSPM integration.
  If the asset owner's email is found, it is stored; otherwise, a default email is used.
  The extracted data is stored in the XSOAR context and displayed in a readable markdown format.
  """

import json
from datetime import datetime


def set_user_slack_email(incident_details, defaultSlackUser):
    """
    Sets the Slack email of the asset owner in the XSOAR context.
    If the email is not available, it defaults to a pre-configured Slack user.

    Args:
    incident_details (dict): The incident details containing asset tags and risk data.

    Returns:
    None
    """
    assetDigTags = incident_details.get("asset Dig Tags")

    # Extract the email from the 'Owner' field in assetDigTags
    email = None
    if assetDigTags:
        assetDigTags = json.loads(assetDigTags)
        if isinstance(assetDigTags.get("Owner"), list) and assetDigTags.get("Owner"):
            email = assetDigTags.get("Owner")[0]

    # If email is not found, set it to the default value "jira"
    if not email:
        email = defaultSlackUser

    # Set the email in XSOAR context
    demisto.setContext("userSlackEmail", email)


def get_incident_details_command(args):
    """
    Extracts the incident details from the provided incident object, ensuring that asset tags are parsed and included.

    Args:
    args (dict): Arguments passed to the script containing the incident object.

    Returns:
    dict: A dictionary containing the extracted incident details.
    """
    incident_data = args.get("incident_object", {})

    # Get assetdigtags and ensure it's a dictionary; if not, parse it or assign an empty dictionary
    assetDigTags = incident_data.get("assetdigtags", "{}")
    if isinstance(assetDigTags, str) and assetDigTags.strip():  # Check if it's a non-empty string
        try:
            assetDigTags = json.loads(assetDigTags)
        except json.JSONDecodeError:
            demisto.error(f"Failed to parse assetDigTags: {assetDigTags}")
            assetDigTags = {}
    elif not isinstance(assetDigTags, dict):
        assetDigTags = {}

    # Construct the incident object with relevant fields
    incident_object = {
        "incidentId": incident_data.get("id", "N/A"),
        "riskFindingId": incident_data.get("riskfindingid", "N/A"),
        "ruleName": str(incident_data.get("riskname", "N/A")),
        "severity": incident_data.get("severity", "N/A"),
        "assetName": incident_data.get("assetname", "N/A"),
        "assetId": incident_data.get("assetid", "N/A"),
        "Status": incident_data.get("status", "N/A"),
        "projectId": incident_data.get("projectid", "N/A"),
        "cloudProvider": incident_data.get("cloud", "N/A"),
        "serviceType": incident_data.get("servicetype", "N/A"),
        "firstDetectedOn": incident_data.get("firstdetectedon", "N/A"),
        "asset Dig Tags": json.dumps(assetDigTags),  # Ensure it's always a string representation
        "remediateInstruction": incident_data.get("remediateinstruction", "N/A"),
        "incidentCreated": datetime.strftime(datetime.now(), "%Y-%m-%d %H:%M:%S.%f"),
    }
    return incident_object


""" MAIN FUNCTION """


def main():
    """
    Main function to extract incident details, set the user's Slack email, and store the results in the XSOAR context.
    The incident details are displayed in a markdown format and available for further use in playbooks.
    """
    try:
        # Retrieve incident object and details
        defaultSlackUser = demisto.args().get("defaultSlackUser")

        dspmRiskObject = get_incident_details_command(demisto.args())

        # Set the Slack email based on asset tags
        set_user_slack_email(dspmRiskObject, defaultSlackUser)

        # Return the results in markdown format
        return_results(
            CommandResults(
                readable_output=tableToMarkdown("Incident Details : ", dspmRiskObject, removeNull=True),
                outputs_prefix="incident_object",
                outputs=dspmRiskObject,
            )
        )
    except Exception as e:
        return_error(f"Error building incident object: {str(e)}")


""" ENTRY POINT """
if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
