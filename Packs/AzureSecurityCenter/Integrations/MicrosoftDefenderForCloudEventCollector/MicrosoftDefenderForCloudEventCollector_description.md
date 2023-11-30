Microsoft Defender for Cloud Event Collector provides unified security management and advanced threat protection across hybrid cloud workloads.
This collector retrieves a list of all the alerts that are associated with a subscription.

#### Authentication with Microsoft Defender For Cloud (Self deployed Azure App)

Self-deployed configuration:
 * [Self-Deployed Application](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#self-deployed-application)

#### Required permissions.

After you finish configuring your application,
add a “Security Reader” role to the application from the subscription.
In order to add a role to a subscription, refer to:
* [Azure AD built-in roles](https://learn.microsoft.com/en-us/azure/active-directory/roles/permissions-reference)

#### Additional information

For additional information on the API, refer to:
* [Alerts](https://learn.microsoft.com/en-us/rest/api/defenderforcloud/alerts/list?tabs=HTTP)