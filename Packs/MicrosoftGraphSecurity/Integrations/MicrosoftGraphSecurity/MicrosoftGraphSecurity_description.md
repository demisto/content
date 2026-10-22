# Microsoft Graph Security

The eDiscovery APIs in Microsoft Graph only work with eDiscovery (Premium) cases.
The legacy content search solution has been deprecated. You can now search by [case](https://learn.microsoft.com/en-us/purview/ediscovery).

# Fetch
Use the **Fetch incidents type** parameter to control what this integration ingests. You can select **Alerts**, **Incidents**, or both:

* **Alerts** - Each Microsoft Graph Security alert is fetched individually.
* **Incidents** - Each Microsoft Graph Security incident is fetched individually, with all associated alerts embedded within it and stored as raw JSON. This provides a single grouped incident containing its underlying alerts, rather than multiple separate alerts.

You can narrow what is fetched using the **Alerts Filter** and **Incidents Filter** parameters. These accept an OData `$filter` expression, for example `severity eq 'medium' and status eq 'active'`. For the supported syntax and operators, see [Microsoft query parameters](https://learn.microsoft.com/en-us/graph/query-parameters?tabs=http).

<~XSOAR>

# Mirroring
Mirroring is supported in Cortex XSOAR only.

1. Under **Incident Mirroring Direction**, select **Incoming**, **Outgoing**, or **Incoming And Outgoing**.
2. Select the **Fetches incidents** radio button.
3. Under **Classifier**, select **Graph Security Classifier**. It routes alerts to the **Graph Security Alert** incident type and incidents to the **Graph Security Incident** incident type. Alternatively, under **Incident type**, select **Graph Security Alert** or **Graph Security Incident**.
4. Under **Mapper (incoming)**, select **Graph Security Mapper - Incoming**. This mapper covers both alerts and incidents.
5. Under **Mapper (outgoing)**, select **Graph Security Mapper - Outgoing**. This mapper covers both alerts and incidents.
6. To close the Cortex XSOAR incident when the Microsoft alert or incident is resolved, select the **Close Mirrored XSOAR Incident** checkbox.
7. To resolve the Microsoft alert or incident when the Cortex XSOAR incident is closed, select the **Close Mirrored Microsoft Alert/Incident** checkbox.
8. In **Comment Entry Tag (to Microsoft)**, enter a tag (default: `CommentToMicrosoftGraphSecurity`). War Room entries with this tag are sent to Microsoft as alert or incident comments.
9. In **Comment Entry Tag (from Microsoft)**, enter a tag (default: `CommentFromMicrosoftGraphSecurity`). Microsoft alert or incident comments are added to the War Room with this tag. The two tags must be different.

Closing behavior and comment mirroring depend on the selected direction: **Close Mirrored XSOAR Incident** and incoming comments require **Incoming**, and **Close Mirrored Microsoft Alert/Incident** and outgoing comments require **Outgoing**. **Incoming And Outgoing** enables both.
Outgoing mirroring requires the `SecurityIncident.ReadWrite.All` and `SecurityAlert.ReadWrite.All` permissions.
For the full steps, see [Configure Incident Mirroring](https://xsoar.pan.dev/docs/reference/integrations/microsoft-graph#configure-incident-mirroring).

</~XSOAR>

# Authentication
You can authenticate either by Entra ID applications or by Azure Managed Identities.

### Authentication Based on Entra ID Applications

Microsoft integrations (Graph and Azure) in Cortex use Entra ID applications to authenticate with Microsoft APIs. These integrations use OAuth 2.0 and OpenID Connect standard compliant authentication services, which use an application to sign in or delegate authentication. For more information, see the Microsoft identity platform overview.

There are two application authentication methods available:

 * [Cortex XSOAR Application](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#cortex-xsoar-application)
 * [Self-Deployed Application](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#self-deployed-application)

Depending on the authentication method that you use, the integration parameters might change.

To use the integration and grant Cortex access to Microsoft Graph Security, an administrator must approve the application through the admin consent flow by clicking this **[link](https://oproxy.demisto.ninja/ms-graph-security)**.
After authorizing the Cortex app, you will get an ID, Token, and Key which should be inserted in the integration instance settings fields.
If you previously had an API V1 configured based on the credentials obtained from this method, refer to the link above to gain new credentials with the relevant permissions.

### Important
1. The ***eDiscovery*** and ***Threat Assessment*** commands are only supported when using the `Authorization Code flow` with `Delegated (work or school account)` permission type.
2. When using `Authorization Code flow`, the connection should be tested using the ***!msg-auth-test*** command.
3. When using the `Authorization Code flow` for this integration, you should log in as an administrator or a user with administrative privileges (`Security Reader` or `Security Administrator`) after running the ***msg-generate-login-url*** command and the login window appears. For more information, see [here](https://learn.microsoft.com/en-us/graph/security-authorization).

### Authentication Based on Azure Managed Identities
##### Note: This option is relevant only if the integration is running on Azure VM.
Follow one of these steps for authentication based on Azure Managed Identities:

- ##### To use System Assigned Managed Identity
   - Select the **Use Azure Managed Identities** checkbox and leave the **Azure Managed Identities Client ID** field empty.

- ##### To use User Assigned Managed Identity
   1. Go to [Azure Portal](https://portal.azure.com/) -> **Managed Identities**.
   2. Select your User Assigned Managed Identity -> copy the Client ID -> paste it in the **Azure Managed Identities Client ID** field in the instance settings.
   3. Select the **Use Azure Managed Identities** checkbox.

For more information, see [Managed identities for Azure resources](https://learn.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview).
