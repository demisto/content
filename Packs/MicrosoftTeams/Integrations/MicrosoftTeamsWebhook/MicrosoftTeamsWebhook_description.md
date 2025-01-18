Use the Microsoft Teams Webhook integration to send messages and notifications to Teams configured with an incoming webhook or a workflow.  When using an adaptive card, the message will always include a link back to the investigation from which it was sent.
​
## Create a workflow in Microsoft Teams.
First, [Install the Workflows app in Microsoft Teams](https://learn.microsoft.com/en-us/power-automate/teams/install-teams-app).<br/>
Second, [Browse and add workflows in Microsoft Teams Create a workflow to support Teams Webhook](https://support.microsoft.com/en-us/office/browse-and-add-workflows-in-microsoft-teams-4998095c-8b72-4b0e-984c-f2ad39e6ba9a). <br/>
Create a workflow of type `Post to a channel when a webhook request is received` and follow the set up instructions.<br/>
In order to create an instance of the Microsoft Teams Webhook in Cortex XSOAR, complete the following:
​
1. Add an instance of the integration and add the Workflow URL for the Teams channel.
2. Test the integration. If successful, you'll see a test message in the channel.
​
​
## Support for Multiple Teams
​
This integration supports sending messages to additional Teams via a workflow.  There are 2 methods for this:
​
- Configure additional integration instances, adding the workflow URL for each Team. You can then send notifications to multiple teams at once, or select the integration instance to use via the playbook task editor.
​
- The ***ms-teams-message*** command includes the *team_webhook* argument, which allows you to pass an alternative workflow URL to override the one from the integration settings.  
​
You can store the additional workflow in a Cortex XSOAR list, and use a transformer on the task in a playbook to send to a specific team.  
​
For example, create a list containing a dictionary where the **Key** is the Team, and the **Value** is the webhook for that team.
​
```
{
"ReadyTeamOne":"workflow url",
"ReadyTeamTwo":"workflow url"
}
```
​
You can then pass the list into the *team_webhook* argument, and use the GetField transformer with the value of the Team   (i.e., ReadyTeamOne) to retrieve the workflow URL that will be used to override the default from the integration instance, and send the message. <br/>
​
For more information, see the [integration documentation](https://xsoar.pan.dev/docs/reference/integrations/microsoft-teams)

---
[View Integration Documentation](https://xsoar.pan.dev/docs/reference/integrations/microsoft-teams-via-webhook)