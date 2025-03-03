Use the Microsoft Teams integration to send messages and notifications to your team members and create meetings. 
Note: The integration is supported in Cortex XSOAR 8 and Cortex XSIAM without using an engine.

### To create an instance of the Microsoft Teams integration in Cortex XSOAR, complete the following:

1. Create the Demisto Bot in Microsoft Teams
2. Grant the Demisto Bot Permissions in Microsoft Graph
3. Configure Microsoft Teams on Cortex XSOAR or Cortex XSIAM
4. Add the Demisto Bot to a Team
 
Important note: resetting the integration cache removes all data about teams, channels, members saved in the integration context. Performing this step requires removing the bot from all teams it was added to.

For more information about registering a calling bot see the [Microsoft Teams Documentation](https://docs.microsoft.com/en-us/microsoftteams/platform/bots/calls-and-meetings/registering-calling-bot#add-microsoft-graph-permissions).

#### Authorize Cortex XSOAR for Azure Active Directory Users (Self deployed Azure App)

There are two different authentication methods for [self-deployed configuration](https://xsoar.pan.dev/docs/reference/integrations/microsoft-teams#configuring-the-instance-with-the-chosen-authentication-flow): 
- [Client Credentials flow](https://xsoar.pan.dev/docs/reference/integrations/microsoft-teams#client-credentials-flow)
- [Authorization Code flow](https://xsoar.pan.dev/docs/reference/integrations/microsoft-teams#authorization-code-flow)

In order to use ***microsoft-teams-ring-user***, you must use the **Client Credentials flow**.

In order to use the following commands, you must use the **Authorization Code flow**:
  - ***microsoft-teams-chat-create***
  - ***microsoft-teams-message-send-to-chat***
  - ***microsoft-teams-chat-add-user***
  - ***microsoft-teams-chat-list***
  - ***microsoft-teams-chat-member-list***
  - ***microsoft-teams-chat-message-list***
  - ***microsoft-teams-chat-update***


**Notes:** 
- When switching from the **Client Credentials Flow** to the **Authorization Code Flow** do as follow: Save the instance, run the ***!microsoft-teams-generate-login-url*** command and follow the instructions mentioned there. Once done, test the validity of your instance by running the ***!microsoft-teams-auth-test*** command. When switching from the **Authorization Code Flow** to the **Client Credentials Flow**, test the validity of the instance by clicking the 'Test' button.
- When using the **Authorization Code flow**, make sure the user you authenticate with has the relevant roles in Azure AD in order to execute the operation. To verify that authentication was configured correctly, run the ***!microsoft-teams-auth-test*** command.