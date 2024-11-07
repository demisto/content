import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from typing import Any


def create_slack_block(incident: dict, rule_names_dict: dict, incidentLink: str) -> dict:
    """
    Creates a Slack block message structure for a DSPM incident.

    The Slack block contains incident details such as Incident ID, DSPM Risk ID, Rule Name,
    Severity, Asset Information, and Remediation instructions. Additionally, a radio button
    to 'Create a Jira ticket' is included, and if the rule name matches specific conditions,
    an option to 'Remediate a Risk' is added.

    Args:
        incident (dict): A dictionary containing details of the DSPM incident.
        rule_names_dict (dict): A dictonary of rule names that trigger the addition of a 'Remediate a Risk' option.

    Returns:
        block (dict): A structured Slack block message in JSON format to be sent to Slack.
    """
    rule_name = incident.get("ruleName")

    # Slack block structure
    block: dict[str, list[dict[str, Any]]] = {
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "THE FOLLOWING RISK HAS BEEN DETECTED BY THE DSPM :warning:",
                    "emoji": True,
                },
            },
            {
                "type": "section",
                "block_id": "section_incident_details",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*XSOAR Incident ID:* {incident.get('incidentId')}\n"
                    f"*XSOAR Incident link:* {incidentLink}\n"
                    f"*DSPM Risk ID:* {incident.get('riskFindingId')}\n"
                    f"*Rule Name:* {incident.get('ruleName')}\n"
                    f"*Severity:* {incident.get('severity')}\n"
                    f"*Asset Name:* {incident.get('assetName')}\n"
                    f"*Asset ID:* {incident.get('assetId')}\n"
                    f"*Project ID:* {incident.get('projectId')}\n"
                    f"*Cloud Provider:* {incident.get('cloudProvider')}\n"
                    f"*Service Type:* {incident.get('serviceType')}\n"
                    f"*First Discovered:* {incident.get('firstDetectedOn')}\n"
                    f"*Remediate Instruction:* {incident.get('remediateInstruction')}\n",
                },
            },
            {"type": "divider"},
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "radio_buttons",
                        "options": [
                            {
                                "text": {"type": "plain_text", "text": "Create a Jira ticket", "emoji": True},
                                "value": "Create a Jira ticket",
                            }
                        ],
                        "action_id": "actionId-0",
                    }
                ],
            },
            {
                "type": "input",
                "element": {
                    "type": "plain_text_input",
                    "placeholder": {"type": "plain_text", "text": "Please enter a valid Project Name", "emoji": True},
                    "action_id": "project_name",
                },
                "label": {"type": "plain_text", "text": "Enter Project Name", "emoji": True},
            },
            {
                "type": "input",
                "element": {
                    "type": "plain_text_input",
                    "placeholder": {"type": "plain_text", "text": "Please enter a valid Issue type", "emoji": True},
                    "action_id": "Issue_type",
                },
                "label": {"type": "plain_text", "text": "Enter Issue Type", "emoji": True},
            },
            {"type": "divider"},
        ]
    }

    # Log the block structure to verify correctness
    demisto.info(f"Block structure before modification: {json.dumps(block, indent=2)}")

    # Add the "Remediate a Risk" radio button option if ruleName exists in rule_names_dict
    if rule_name in rule_names_dict:
        try:
            # Ensure the 'actions' block exists at the correct index
            elements = block["blocks"][3].get("elements", [{}])[0].get("options", [])
            elements.insert(
                0,
                {
                    "text": {
                        "type": "plain_text",
                        "text": f"Remediate a Risk - {rule_names_dict.get(rule_name)}",
                        "emoji": True,
                    },
                    "value": "Remediate a Risk",
                },
            )
        except (AttributeError, IndexError, TypeError) as e:
            demisto.error(f"Error inserting 'Remediate a Risk' option: {str(e)}")
            raise
    res = {"block": block}
    return res


""" MAIN FUNCTION """


def main():  # pragma: no cover
    """
    The main function for creating and storing a Slack block message based on DSPM risk data.

    It processes the DSPM incident details, creates a Slack block and outputs the block.
    If the rule name matches certain conditions, a 'Remediate a Risk'
    option is added to the Slack block.

    Returns:
        None: Results are returned via demisto.results() and CommandResults().
    """
    rule_names_dict = {
        "Sensitive asset open to world": (
            "This action would block the public access to specific containers in storage account "
            "(Azure) or to the bucket (AWS/GCP) based on the cloud provider."
        ),
        "Empty storage asset": (
            "This action would delete the storage account (Azure) or the storage bucket "
            "(AWS/GCP) based on the cloud provider."
        )
    }
    try:
        incident = demisto.args().get("dspmIncident")
        incidentLink = demisto.args().get("incidentLink")
        slackBlock = create_slack_block(incident, rule_names_dict, incidentLink)

        return_results(
            CommandResults(
                outputs_prefix="slackBlock",
                outputs=slackBlock,
            )
        )

    except Exception as excep:
        return_error(f"Failed to execute CreateDSPMRiskSlackBlocks. Error: {str(excep)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
