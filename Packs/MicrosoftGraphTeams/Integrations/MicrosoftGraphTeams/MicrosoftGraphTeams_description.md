Microsoft integrations (Graph and Azure) in Cortex XSOAR use Azure Active Directory applications to authenticate with Microsoft APIs. These integrations use OAuth 2.0 and OpenID Connect standard-compliant authentication services, which use an Application to sign-in or delegate authentication. For more information, see the Microsoft identity platform overview.

# Self-Deployed Application
To use a [Self-Deployed Application](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#self-deployed-application)
 , you need to add a [new Azure App Registration in the Azure Portal](https://docs.microsoft.com/en-us/graph/auth-register-app-v2#register-a-new-application-using-the-azure-portal).
 
### Authentication Using the User - Authorization Code Flow

Follow these steps for [Authorization Code flow](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#authorize-on-behalf-of-a-user) configuration:

1. To use a self-configured Azure application, you need to add a new Azure App Registration in the Azure Portal. To add the registration, refer to the following [Microsoft article](https://docs.microsoft.com/en-us/microsoft-365/security/defender/api-create-app-web?view=o365-worldwide#create-an-app) steps 1-8.
2. choose the user_auth_flow option in the ***Authentication Type*** parameter.
3. Enter your Client/Application ID in the ***Application ID*** parameter. 
4. Enter your Client Secret in the ***Client Secret*** parameter.
5. Enter your Tenant ID in the ***Tenant ID*** parameter.
6. Enter your Application redirect URI in the ***Application redirect URI*** parameter.
7. Enter your Authorization code in the ***Authorization code*** parameter.
7. Save the instance.
8. Run the ***!msgraph-teams-test*** command - a 'Success' message should be printed to the War Room.

### Required Permissions
Chat.Create - Delegated
Chat.Read - Delegated 
Chat.ReadBasic - Delegated 
Chat.ReadWrite - Delegated 
ChatMember.Read - Delegated 
ChatMember.ReadWrite - Delegated 
ChatMessage.Read - Delegated 
ChatMessage.Send - Delegated

This is a long-running integration. For more information about long-running integrations, check out the <~XSIAM>[Forward requests to long-running integrations](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Administrator-Guide/Forward-Requests-to-Long-Running-Integrations) article.</~XSIAM> <~XSOAR_SAAS>Forward Requests to Long-Running Integrations article: [Cortex XSOAR 8 Cloud](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8/Cortex-XSOAR-Cloud-Documentation/Forward-Requests-to-Long-Running-Integrations) or [Cortex XSOAR 8 On-prem](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8.7/Cortex-XSOAR-On-prem-Documentation/Integration-commands-in-the-CLI) documentation.</~XSOAR_SAAS>