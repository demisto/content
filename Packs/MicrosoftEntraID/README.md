<~XSIAM>  

<html>

<h1>Microsoft Entra ID</h1>

<details>
    <summary><h2 style="display:inline-block">What does this pack do</h2></summary>

<h3>Log Normalization - One Data Model</h3>
<p>This pack supports normalization of the below log categories of Microsoft Entra ID:</p>
<ol>
    <li>AuditLogs</li>
    <li>SignInLogs</li>
    <li>NonInteractiveUserSignInLogs</li>
    <li>ServicePrincipalSignInLogs</li>
    <li>ManagedIdentitySignInLogs</li>
    <li>ADFSSignInLogs</li>
    <li>ProvisioningLogs</li>
    <li>RiskyUsers</li>
    <li>UserRiskEvents</li>
    <li>RiskyServicePrincipals</li>
    <li>ServicePrincipalRiskEvents</li>
</ol>

<h3>Timestamp Parsing</h3>
<p>Timestamp parsing relies on 2 fields, which depends on the log category:</p>
<ol>
  <li>`properties.createdDateTime`
    <ol>
        <li>SignInLogs</li>
        <li>NonInteractiveUserSignInLogs</li>
        <li>ServicePrincipalSignInLogs</li>
        <li>ManagedIdentitySignInLogs</li>
        <li>ADFSSignInLogs</li>
    </ol>
  </li>
  <li>`properties.activityDateTime`
    <ol>
        <li>AuditLogs</li>
        <li>ProvisioningLogs</li>
        <li>UserRiskEvents</li>
        <li>ServicePrincipalRiskEvents</li>
    </ol>
  </li>
  <li>`properties.riskLastUpdatedDateTime`
    <ol>
        <li>RiskyUsers</li>
        <li>RiskyServicePrincipals</li>
    </ol>
  </li>
</ol>
</details>
<hr>

<details>
<summary><h2 style="display:inline-block">Data Collection</h2></summary>
<h3 >Entra ID Side</h3>
<p>To configure Microsoft Entra ID to send logs to Cortex XSIAM, follow the below steps.</p>
<h4>Prerequisites</h4>
<ol>
    <li>Create an <b>Azure event hub</b>. For more information, refer to Microsoft's official <a href="https://learn.microsoft.com/en-us/azure/event-hubs/event-hubs-create">documentation</a>.</li>
    <li>Make sure that you have at least Security Administrator role.</li>
</ol>
<h4>Stream logs to an event hub</h4>
<ol>
    <li>Sign in to the <b>Microsoft Entra admin center</b>.</li>
    <li>Navigate to <b>Identity</b> &rarr; <b>Monitoring & health</b> &rarr; <b>Diagnostic settings</b>.</li>
    <li>Select <b>+ Add diagnostic setting</b> to create a new integration or select <b>Edit setting</b> for an existing integration.</li>
    <li>Enter a <b>Diagnostic setting name</b>. If you're editing an existing integration, you can't change the name.</li>
    <li>Select the log categories that you want to stream. Refer to the <b>Log Normalization</b> section for the supported log categories for normalization.</li>
    <li>Select the <b>Stream to an event hub </b>checkbox.</li>
    <li>Select the Azure subscription, Event Hubs namespace, and optional event hub where you want to route the logs.</li>
</ol>

<p>For more information, refer to Microsoft's official <a href="https://learn.microsoft.com/en-us/entra/identity/monitoring-health/howto-stream-logs-to-event-hub">documentation</a>.</p>

<h3>Cortex XSIAM side</h3>
<p>To connect XSIAM to the Azure Event Hub, follow the below steps.</p>
<h4>Azure Event Hub Collector</h4>
<ol>
    <li>Navigate to <b>Settings</b> &rarr; <b>Data Sources</b>.</li>
    <li>If you have already configured an <b>Azure Event Hub Collector</b>, select the <b>3 dots</b>, and then select <b>+ Add New Instance</b>. If not, select <b>+ Add Data Source</b>, search for "Azure Event Hub" and then select <b>Connect</b>.</li>
    <li>Fill in the attributes based on the Azure Event Hub you streamed your data to.</li>
    <li>Leave the <b>Use audit logs in analytics</b> checkbox selected, unless you were told otherwise.</li>
</ol>
<p>More information can be found <a href="https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Administrator-Guide/Ingest-Logs-from-Microsoft-Azure-Event-Hub?tocId=yjPDSlvRYtlNncGBLHOzvw">here</a>.</p>
</details>
<hr>

<details>
<summary><h2 style="display:inline-block">XQL Queries</h2></summary>
<p>Use the below queries to review the mapped logs (post installation).</p> 
<details>
<summary>AuditLogs</summary>
<br>
<pre><code>datamodel dataset = msft_azure_raw 
| filter xdm.event.original_event_type = "AuditLogs"
| fields xdm.event.original_event_type, xdm.event.type, xdm.event.id,  xdm.session_context_id, xdm.event.description, xdm.event.operation_sub_type, xdm.event.outcome_reason, xdm.event.outcome, xdm.source.cloud.project_id, xdm.source.cloud.geo_region, xdm.observer.type, xdm.source.user.upn, xdm.source.user.identifier, xdm.source.user.username, xdm.source.application.name, xdm.target.resource.sub_type, xdm.target.resource.id, xdm.target.resource.name, xdm.target.resource.type, xdm.source.ipv4, xdm.source.ipv6, xdm.source.user_agent</code></pre>

</details>
<br>
<details>
<summary>SignInLogs, NonInteractiveUserSignInLogs, ServicePrincipalSignInLogs, ManagedIdentitySignInLogs, ADFSSignInLogs</summary>
<br>
<pre><code>datamodel dataset = msft_azure_raw 
| filter xdm.event.original_event_type in ("SignInLogs", "NonInteractiveUserSignInLogs", "ServicePrincipalSignInLogs", "ManagedIdentitySignInLogs", "ADFSSignInLogs")
| fields xdm.event.original_event_type, xdm.event.type, xdm.event.duration, xdm.event.id, xdm.session_context_id, xdm.source.cloud.project_id, xdm.event.outcome_reason, xdm.event.outcome, xdm.source.user.username, xdm.source.user.upn, xdm.source.user.identifier, xdm.source.application.name, xdm.auth.service, xdm.source.host.device_id, xdm.source.host.os, xdm.source.host.os_family, xdm.network.http.browser, xdm.source.location.country, xdm.source.location.city, xdm.source.location.latitude, xdm.source.location.longitude, xdm.logon.type, xdm.alert.severity, xdm.alert.risks, xdm.target.resource.name, xdm.target.resource.id, xdm.auth.auth_method, xdm.auth.is_mfa_needed, xdm.auth.privilege_level, xdm.source.asn.as_number, xdm.source.ipv4, xdm.source.ipv6, xdm.source.user_agent</code></pre>

</details>
<br>
<details>
<summary>ProvisioningLogs</summary>
<br>
<pre><code>datamodel dataset = msft_azure_raw 
| filter xdm.event.original_event_type = "ProvisioningLogs"
| fields xdm.event.original_event_type, xdm.event.duration, xdm.event.type, xdm.event.outcome, xdm.event.outcome_reason, xdm.event.description, xdm.source.cloud.project_id, xdm.event.id, xdm.session_context_id, xdm.event.operation_sub_type, xdm.source.application.name, xdm.target.application.name, xdm.source.user.username, xdm.source.user.identifier, xdm.target.resource.id, xdm.target.resource.type, xdm.target.resource.name, xdm.target.resource.value</code></pre>

</details>
<br>
<details>
<summary>RiskyUsers, RiskyServicePrincipals</summary>
<br>
<pre><code>datamodel dataset = msft_azure_raw 
| filter xdm.event.original_event_type in ("RiskyUsers", "RiskyServicePrincipals")
| fields xdm.event.original_event_type, xdm.session_context_id, xdm.source.cloud.project_id, xdm.event.type, xdm.event.id, xdm.source.user.username, xdm.source.user.upn, xdm.alert.name, xdm.alert.severity, xdm.source.application.name, xdm.source.user.is_disabled</code></pre>
</details>
<br>
<details>
<summary>UserRiskEvents, ServicePrincipalRiskEvents</summary>
<br>
<pre><code>datamodel dataset = msft_azure_raw 
| filter xdm.event.original_event_type in ("UserRiskEvents", "ServicePrincipalRiskEvents")
| fields xdm.event.original_event_type, xdm.event.description, xdm.session_context_id, xdm.source.cloud.project_id, xdm.event.type, xdm.event.id, xdm.source.ipv4, xdm.source.ipv6, xdm.logon.logon_guid, xdm.alert.subcategory, xdm.alert.severity, xdm.alert.name, xdm.observer.type, xdm.source.location.country, xdm.source.location.city, xdm.source.location.latitude, xdm.source.location.longitude, xdm.source.user.username, xdm.source.user.upn, xdm.source.user.identifier, xdm.auth.privilege_level, xdm.source.application.name</code></pre>
</details>
</details>

</html>


</~XSIAM>
