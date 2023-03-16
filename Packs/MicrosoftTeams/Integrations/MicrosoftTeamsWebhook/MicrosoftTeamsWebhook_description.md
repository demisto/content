Use the Microsoft Teams Webhook integration to send messages and notifications to Teams configured with an incoming webhook.  The message will always include a link back to the investigation from which it was sent.
​
## Create an Incoming Webhook on the Team in Microsoft Teams.  
For information, see the [Microsoft Create an Incoming Webhook Documentation](https://docs.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook)
​
To create an instance of the Microsoft Teams Webhook in Cortex XSOAR, complete the following:
​
1. Add an instance of the integration and add the Webhook URL for the Teams channel.
2. Test the integration. If successful, you'll see a test message in the channel.
​
​
## Support for Multiple Teams
​
This integration supports sending messages to additional Teams via an incoming webhook.  There are 2 methods for this:
​
- Configure additional integration instances, adding the webhook URL for each Team. You can then send notifications to multiple teams at once, or select the integration instance to use via the playbook task editor.
​
- The ***ms-teams-message*** command includes the *team_webhook* argument, which allows you to pass an alternative webhook URL to override the one from the integration settings.  
​
You can store the additional webhooks in a Cortex XSOAR list, and use a transformer on the task in a playbook to send to a specific team.  
​
For example, create a list containing a dictionary where the **Key** is the Team, and the **Value** is the webhook for that team.
​
```
{
"ReadyTeamOne":"webhook url",
"ReadyTeamTwo":"webhook url"
}
```
​
You can then pass the list into the *team_webhook* argument, and use the GetField transformer with the value of the Team   (i.e., ReadyTeamOne) to retrieve the webhook URL that will be used to override the default from the integration instance, and send the message.
​
For more information, see the [integration documentation](https://xsoar.pan.dev/docs/reference/integrations/microsoft-teams)

---
[View Integration Documentation](https://xsoar.pan.dev/docs/reference/integrations/microsoft-teams-via-webhook)