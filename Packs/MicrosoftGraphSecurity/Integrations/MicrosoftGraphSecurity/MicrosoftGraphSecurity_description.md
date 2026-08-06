The eDiscovery APIs in Microsoft Graph only work with eDiscovery (Premium) cases.
The legacy content search solution has been retired; you can now search by a [case](https://learn.microsoft.com/en-us/purview/ediscovery).

# Fetch
Use the **Fetch incidents type** parameter to control what this integration ingests. You can select **Alerts**, **Incidents**, or both:

* **Alerts** - Each Microsoft Graph Security alert is fetched on its own. The alert data is mapped into the incident/issue.
* **Incidents** - Each Microsoft Graph Security incident is fetched on its own, with all of its associated alerts embedded within it and stored as raw JSON. This gives you one grouped incident that already contains its underlying alerts, instead of many separate alert incidents.

Alerts and Incidents are fetched independently, each with its own time window cursor, so selecting both will not cause one to interfere with the other.

You can narrow what is fetched using the **Fetched Alerts filter** and **Fetched Incidents filter** parameters. These accept an OData `$filter` expression, for example `severity eq 'medium' and status eq 'active'`. For the supported syntax and operators, see [Microsoft query parameters](https://learn.microsoft.com/en-us/graph/query-parameters?tabs=http).

# Authentication
You can authenticate either by Entra ID applications or by Azure Managed Identities.

### Authentication Based on Entra ID Applications

Microsoft integrations (Graph and Azure) in Cortex XSOAR use Entra ID applications to authenticate with Microsoft APIs. These integrations use OAuth 2.0 and OpenID Connect standard compliant authentication services, which use an application to sign in or delegate authentication. For more information, see the Microsoft identity platform overview.

There are two application authentication methods available:

 * [Cortex XSOAR Application](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#cortex-xsoar-application)
 * [Self-Deployed Application](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#self-deployed-application)

Depending on the authentication method that you use, the integration parameters might change.

To use the **Cortex application** and allow Cortex access to Microsoft Graph Security an administrator has to approve our app using an admin consent flow by clicking this **[link](https://oproxy.demisto.ninja/ms-graph-security)**.
After authorizing the Cortex XSOAR app, you will get an ID, Token, and Key which should be inserted in the integration instance settings fields.
If you previously had an API V1 configured based on the credentials obtained from this method, refer to the link above to gain new credentials with the relevant permissions.

### Important
1. The ***eDiscovery*** and ***Threat Assessment*** commands are only supported when using the `Authorization Code flow` with `Delegated (work or school account)` permission type.
2. When using `Authorization Code flow`, the connection should be tested using the ***!msg-auth-test*** command.
3. When using the `Authorization Code flow` for this integration, you should log in as an administrator or a user with administrative privileges (`Security Reader` or `Security Administrator`) after running the ***msg-generate-login-url*** command and the login window appears. For more information, see [here](https://learn.microsoft.com/en-us/graph/security-authorization).

### Authentication Based on Azure Managed Identities
##### Note: This option is relevant only if the integration is running on Azure VM.
For more information, see [Managed identities for Azure resources](https://learn.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview).
