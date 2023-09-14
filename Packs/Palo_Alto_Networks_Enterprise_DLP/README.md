## Palo Alto Networks Enterprise DLP Content Pack

This content pack enables Cortex XSOAR to integrate with Palo Alto Networks Enterprise DLP. Using this content pack, you can fetch DLP incidents using the `Long running instance` checkbox and update DLP incidents with user feedback. This pack includes the **Palo Alto Networks Enterprise DLP** integration and a sample playbook to gather user feedback for a DLP incident using Slack.


### Palo Alto Networks Enterprise DLP Integration

Integrates with the Enterprise DLP service to get details about DLP violations and to update DLP incidents with user feedback.

The integration includes commands to:
 - Fetch DLP incidents as a long running instance.
 - Fetch DLP reports with data pattern match details.
 - Fetch DLP reports with data pattern match details and snippets from the file.
 - Update a DLP incident with user feedback and approval process.
 - Check if the option to exempt the violation should be provided for a given DLP data profile name.
 - Get approval for any exemption requests.
 - Send a customized Slack bot message to the user to ask for feedback.
 - Reset the last run.
