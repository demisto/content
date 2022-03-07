## Palo Alto Networks Enterprise DLP Content Pack

This content pack enables Cortex XSOAR to integrate with Palo Alto Networks Enterprise DLP. Using this content pack, the user can fetch DLP reports and update DLP incidents with user feedback. This pack includes the **Palo Alto Networks Enterprise DLP** integration and a sample Playbook to gather user feedback to a DLP incident through Slack integration.


### Palo Alto Networks Enterprise DLP Integration

Integrate with Enterprise DLP service to get details about DLP violations and to update DLP incident with user feedback.

The integration includes commands to:
 - Fetch DLP reports with data pattern match details.
 - Fetch DLP reports with data pattern match details and the corresponding snippet from the file.
 - Update a DLP incident with user feedback
 - Check if the option to exempt the violation should be provided given a DLP data profile name
 - Get the customized Slack bot message to send to the user to ask for feedback
