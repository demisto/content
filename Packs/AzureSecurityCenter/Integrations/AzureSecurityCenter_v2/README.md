Unified security management and advanced threat protection across hybrid cloud workloads.

<h2>Use Case</h2>
With Security Center, you can apply security policies across your workloads, limit your exposure to threats, and detect and respond to attacks.
<h2>Detailed Description</h2>
<li>To allow us access to Azure Security Center, an admin has to approve our app using an admin consent flow, by clicking on the following [link](https://oproxy.demisto.ninja/ms-azure-sc).</li>
<li>After authorizing the Demisto app, you will get an ID, Token, and Key, which should be inserted in the integration instance configuration's corresponding fields. After giving consent, the application has to have a role assigned so it can access the relevant resources per subscription. </li>
<li>In order to assign a role to the application after consent was given: 
  <ul>
    <li>Go to the Azure Portal UI.</li>
    <li>Go to Subscriptions, and then Access Control (IAM).</li>
    <li>Click Add.</li>
    <li>Select a role that includes the following permissions:
    <ul>
      <li>Microsoft.Security/locations/read</li>
      <li>Microsoft.Security/alerts/read</li>
      <li>Microsoft.Security/locations/alerts/read</li>
      <li>Microsoft.Storage/storageAccounts/read</li>
      <li>Microsoft.Management/managementGroups/read</li>
      <li>Microsoft.Security/advancedThreatProtectionSettings/*</li>
      <li>Microsoft.Security/informationProtectionPolicies/read</li>
      <li>Microsoft.Security/locations/jitNetworkAccessPolicies/*</li>
      <li>Microsoft.Security/locations/jitNetworkAccessPolicies/initiate/action</li>
    </ul></li>
    <li>Select the Azure Secruity Center application.</li>
  </ul>
</li>
<h2>Configure Azure Security Center v2 on Demisto</h2>
<ol>
  <li>Navigate to&nbsp;<strong>Settings</strong>&nbsp;&gt;&nbsp;<strong>Integrations</strong>
  &nbsp;&gt;&nbsp;<strong>Servers &amp; Services</strong>.</li>
  <li>Search for Azure Security Center v2.</li>
  <li>
    Click&nbsp;<strong>Add instance</strong>&nbsp;to create and configure a new integration instance.
    <ul>
      <li><strong>Name</strong>: a textual name for the integration instance.</li>
   <li><strong>Microsoft Azure Management URL</strong></li>
   <li><strong>ID (received from the admin consent - see Detailed Instructions (?)</strong></li>
   <li><strong>Token (received from the admin consent - see Detailed Instructions (?) section)</strong></li>
   <li><strong>Key (received from the admin consent - see Detailed Instructions (?)</strong></li>
   <li><strong>Trust any certificate (not secure)</strong></li>
   <li><strong>Use system proxy settings</strong></li>
   <li><strong>Default subscription ID to use</strong></li>
    </ul>
  </li>
  <li>
    Click&nbsp;<strong>Test</strong>&nbsp;to validate the new instance.
  </li>
</ol>

<h2>Use a Self-Deployed Azure Application</h2>
<p>To use a self-configured Azure application, a need to add a new Azure App Registration in the Azure Portal. To add the registration refer to the
<a href="https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app">Microsoft documentation</a></p>
<p>The Tenant ID, Client ID, and Client secret are required for the integration. When you configure the integration in Demisto enter those parameters in the appropriate fields (instead of how you received them from the admin consent in the current doc).<p>ID - Client ID<br>
Token - Tenant ID<br>
Key - Client Secret</p>

<h2>Commands</h2>
<p>
  You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
  After you successfully execute a command, a DBot message appears in the War Room with the command details.
</p>
<ol>
  <li>azure-sc-list-alert</li>
  <li>azure-sc-update-atp</li>
  <li>azure-sc-get-atp</li>
  <li>azure-sc-update-aps</li>
  <li>azure-sc-get-aps</li>
  <li>azure-sc-list-aps</li>
  <li>azure-sc-list-jit</li>
  <li>azure-sc-list-storage</li>
  <li>azure-list-subscriptions</li>
  <li>azure-sc-list-location</li>
</ol>
<h3>1. azure-sc-list-alert</h3>
<hr>
<p>Lists alerts for the subscription according to the specified filters.</p>
<h5>Base Command</h5>
<p>
  <code>azure-sc-list-alert</code>
</p>

<h5>Input</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Argument Name</strong>
      </th>
      <th>
        <strong>Description</strong>
      </th>
      <th>
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>resource_group_name</td>
      <td>The name of the resource group within the user's subscription. The name is case insensitive.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>asc_location</td>
      <td>The location where Azure Security Center stores the data of the subscription. Run the 'azure-sc-list-location' command to get the ascLocation. This command requires the resourceGroupName argument.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>filter</td>
      <td>OData filter</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>select</td>
      <td>OData select</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>expand</td>
      <td>OData expand</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>subscription_id</td>
      <td>Subscription ID to use. Can be retrieved from the azure-sc-list-subscriptions command. If not specified, the default subscripton ID will be used.</td>
      <td>Optional</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Context Output</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Path</strong>
      </th>
      <th>
        <strong>Type</strong>
      </th>
      <th>
        <strong>Description</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>AzureSecurityCenter.Alert.AlertDisplayName</td>
      <td>string</td>
      <td>Alert display name</td>
    </tr>
    <tr>
      <td>AzureSecurityCenter.Alert.CompromisedEntity</td>
      <td>string</td>
      <td>The entity on which the incident occurred</td>
    </tr>
    <tr>
      <td>AzureSecurityCenter.Alert.DetectedTimeUtc</td>
      <td>date</td>
      <td>Time the vendor detected the incident</td>
    </tr>
    <tr>
      <td>AzureSecurityCenter.Alert.ReportedSeverity</td>
      <td>string</td>
      <td>Estimated severity of this alert</td>
    </tr>
    <tr>
      <td>AzureSecurityCenter.Alert.State</td>
      <td>string</td>
      <td>Alert state (Active, Dismissed, etc.)</td>
    </tr>
    <tr>
      <td>AzureSecurityCenter.Alert.ID</td>
      <td>string</td>
      <td>Alert ID</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!azure-sc-list-alert</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "AzureSecurityCenter.Alert": [
        {
            "ActionTaken": "Undefined",
            "CompromisedEntity": "alerts",
            "Description": "Azure security center has detected incoming traffic from IP addresses, which have been identified as IP addresses that should be blocked by the Adaptive Network Hardening control",
            "DetectedTime": "2019-10-27T00:00:00Z",
            "DisplayName": "Traffic from unrecommended IP addresses was detected",
            "ID": "2518301663999999999_d1521d81-f4c1-40ae-b224-01456637790c",
            "ReportedSeverity": "Information",
            "State": "Active"
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>Azure Security Center - List Alerts</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>DisplayName</strong></th>
      <th><strong>CompromisedEntity</strong></th>
      <th><strong>DetectedTime</strong></th>
      <th><strong>ReportedSeverity</strong></th>
      <th><strong>State</strong></th>
      <th><strong>ActionTaken</strong></th>
      <th><strong>Description</strong></th>
      <th><strong>ID</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> Traffic from unrecommended IP addresses was detected </td>
      <td> alerts </td>
      <td> 2019-10-27T00:00:00Z </td>
      <td> Information </td>
      <td> Active </td>
      <td> Undefined </td>
      <td> Azure security center has detected incoming traffic from IP addresses, which have been identified as IP addresses that should be blocked by the Adaptive Network Hardening control </td>
      <td> 2518301663999999999_d1521d81-f4c1-40ae-b224-01456637790c </td>
    </tr>
  </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->

<h3>2. azure-sc-update-atp</h3>
<hr>
<p>Updates Advanced Threat Detection settings.</p>
<h5>Base Command</h5>
<p>
  <code>azure-sc-update-atp</code>
</p>

<h5>Input</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Argument Name</strong>
      </th>
      <th>
        <strong>Description</strong>
      </th>
      <th>
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>resource_group_name</td>
      <td>Resource group name</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>setting_name</td>
      <td>Name of the Advanced Threat Detection setting, default is 'current'.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>storage_account</td>
      <td>Storage name in your Azure account</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>is_enabled</td>
      <td>Indicates whether Advanced Threat Protection is enabled.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>subscription_id</td>
      <td>Subscription ID to use. Can be retrieved from the azure-sc-list-subscriptions command. If not specified, the default subscripton ID will be used.</td>
      <td>Optional</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Context Output</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Path</strong>
      </th>
      <th>
        <strong>Type</strong>
      </th>
      <th>
        <strong>Description</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>AzureSecurityCenter.AdvancedThreatProtection.ID</td>
      <td>string</td>
      <td>Resource ID</td>
    </tr>
    <tr>
      <td>AzureSecurityCenter.AdvancedThreatProtection.Name</td>
      <td>string</td>
      <td>Resource Name</td>
    </tr>
    <tr>
      <td>AzureSecurityCenter.AdvancedThreatProtection.IsEnabled</td>
      <td>string</td>
      <td>Indicates whether Advanced Threat Protection is enabled</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!azure-sc-update-atp resource_group_name=recouce_name</code>
</p>


<h3>3. azure-sc-get-atp</h3>
<hr>
<p>Returns the Advanced Threat Protection setting.</p>
<h5>Base Command</h5>
<p>
  <code>azure-sc-get-atp</code>
</p>

<h5>Input</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Argument Name</strong>
      </th>
      <th>
        <strong>Description</strong>
      </th>
      <th>
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>resource_group_name</td>
      <td>Name of the resource group.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>setting_name</td>
      <td>Name of Advanced Threat Detection setting, default setting's name is 'current'.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>storage_account</td>
      <td>Name of a storage in your azure account.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>subscription_id</td>
      <td>Subscription ID to use. Can be retrieved from the azure-sc-list-subscriptions command. If not specified, the default subscripton ID will be used.</td>
      <td>Optional</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Context Output</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Path</strong>
      </th>
      <th>
        <strong>Type</strong>
      </th>
      <th>
        <strong>Description</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>AzureSecurityCenter.AdvancedThreatProtection.ID</td>
      <td>string</td>
      <td>Resource ID</td>
    </tr>
    <tr>
      <td>AzureSecurityCenter.AdvancedThreatProtection.Name</td>
      <td>string</td>
      <td>Resource name</td>
    </tr>
    <tr>
      <td>AzureSecurityCenter.AdvancedThreatProtection.IsEnabled</td>
      <td>string</td>
      <td>Indicates whether Advanced Threat Protection is enabled</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!azure-sc-get-atp resource_group_name=resource_group storage_account=st_acc1</code>
</p>


<h3>4. azure-sc-update-aps</h3>
<hr>
<p>Updates a specific auto provisioning setting.</p>
<h5>Base Command</h5>
<p>
  <code>azure-sc-update-aps</code>
</p>

<h5>Input</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Argument Name</strong>
      </th>
      <th>
        <strong>Description</strong>
      </th>
      <th>
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>setting_name</td>
      <td>Name of the auto provisioning setting, default setting's name is 'default'</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>auto_provision</td>
      <td>Describes the type of security agent provisioning action to take (On or Off)</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>subscription_id</td>
      <td>Subscription ID to use. Can be retrieved from the azure-sc-list-subscriptions command. If not specified, the default subscripton ID will be used.</td>
      <td>Optional</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Context Output</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Path</strong>
      </th>
      <th>
        <strong>Type</strong>
      </th>
      <th>
        <strong>Description</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>AzureSecurityCenter.AutoProvisioningSetting.Name</td>
      <td>string</td>
      <td>Setting display name</td>
    </tr>
    <tr>
      <td>AzureSecurityCenter.AutoProvisioningSetting.AutoProvision</td>
      <td>string</td>
      <td>Display the type of security agent provisioning action to take (On or Off)</td>
    </tr>
    <tr>
      <td>AzureSecurityCenter.AutoProvisioningSetting.ID</td>
      <td>string</td>
      <td>Setting resource ID</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!azure-sc-update-aps setting_name=default auto_provision=Off</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "AzureSecurityCenter.AutoProvisioningSetting": [
        {
            "AutoProvision": null,
            "ID": "/subscriptions/xxxx-xxxx-xxxx-xxxx-xxxx/providers/Microsoft.Security/autoProvisioningSettings/default",
            "Name": "default"
        }
    ]
}
</pre>

<h5>Human Readable Output</h5>
<h3>Azure Security Center - Update Auto Provisioning Setting</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Name</strong></th>
      <th><strong>ID</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> default </td>
      <td> /subscriptions/xxxx-xxxx-xxxx-xxxx-xxxx/providers/Microsoft.Security/autoProvisioningSettings/default </td>
    </tr>
  </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->

<h3>5. azure-sc-get-aps</h3>
<hr>
<p>Returns details of a specific auto provisioning setting.</p>
<h5>Base Command</h5>
<p>
  <code>azure-sc-get-aps</code>
</p>

<h5>Input</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Argument Name</strong>
      </th>
      <th>
        <strong>Description</strong>
      </th>
      <th>
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>setting_name</td>
      <td>Name of the auto provisioning setting</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>subscription_id</td>
      <td>Subscription ID to use. Can be retrieved from the azure-sc-list-subscriptions command. If not specified, the default subscripton ID will be used.</td>
      <td>Optional</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Context Output</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Path</strong>
      </th>
      <th>
        <strong>Type</strong>
      </th>
      <th>
        <strong>Description</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>AzureSecurityCenter.AutoProvisioningSetting.Name</td>
      <td>string</td>
      <td>Setting display name</td>
    </tr>
    <tr>
      <td>AzureSecurityCenter.AutoProvisioningSetting.AutoProvision</td>
      <td>string</td>
      <td>Display the type of security agent provisioning action to take (On or Off)</td>
    </tr>
    <tr>
      <td>AzureSecurityCenter.AutoProvisioningSetting.ID</td>
      <td>string</td>
      <td>Set resource ID</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!azure-sc-get-aps setting_name=default</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "AzureSecurityCenter.AutoProvisioningSetting": [
        {
            "AutoProvision": "Off",
            "ID": "/subscriptions/0xxxx-xxxx-xxxx-xxxx-xxxx/providers/Microsoft.Security/autoProvisioningSettings/default",
            "Name": "default"
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<h3>Azure Security Center - Get Auto Provisioning Setting</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Name</strong></th>
      <th><strong>AutoProvision</strong></th>
      <th><strong>ID</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> default </td>
      <td> Off </td>
      <td> /subscriptions/xxxx-xxxx-xxxx-xxxx-xxxx/providers/Microsoft.Security/autoProvisioningSettings/default </td>
    </tr>
  </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->

<h3>6. azure-sc-list-aps</h3>
<hr>
<p>Lists auto provisioning settings in the subscription.</p>
<h5>Base Command</h5>
<p>
  <code>azure-sc-list-aps</code>
</p>

<h5>Input</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Argument Name</strong>
      </th>
      <th>
        <strong>Description</strong>
      </th>
      <th>
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>subscription_id</td>
      <td>Subscription ID to use. Can be retrieved from the azure-sc-list-subscriptions command. If not specified, the default subscripton ID will be used.</td>
      <td>Optional</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Context Output</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Path</strong>
      </th>
      <th>
        <strong>Type</strong>
      </th>
      <th>
        <strong>Description</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>AzureSecurityCenter.AutoProvisioningSetting.Name</td>
      <td>string</td>
      <td>Setting display name</td>
    </tr>
    <tr>
      <td>AzureSecurityCenter.AutoProvisioningSetting.AutoProvision</td>
      <td>string</td>
      <td>Display the type of security agent provisioning action to take (On or Off)</td>
    </tr>
    <tr>
      <td>AzureSecurityCenter.AutoProvisioningSetting.ID</td>
      <td>string</td>
      <td>Setting resource ID</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!azure-sc-list-aps</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "AzureSecurityCenter.AutoProvisioningSetting": [
        {
            "AutoProvision": "Off",
            "ID": "/subscriptions/xxxx-xxxx-xxxx-xxxx-xxxx/providers/Microsoft.Security/autoProvisioningSettings/default",
            "Name": "default"
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<h3>Azure Security Center - List Auto Provisioning Settings</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Name</strong></th>
      <th><strong>AutoProvision</strong></th>
      <th><strong>ID</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> default </td>
      <td> Off </td>
      <td> /subscriptions/xxxx-xxxx-xxxx-xxxx-xxxx/providers/Microsoft.Security/autoProvisioningSettings/default </td>
    </tr>
  </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->

<h3>7. azure-sc-list-jit</h3>
<hr>
<p>Lists all policies for protecting resources using Just-in-Time access control.</p>
<h5>Base Command</h5>
<p>
  <code>azure-sc-list-jit</code>
</p>

<h5>Input</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Argument Name</strong>
      </th>
      <th>
        <strong>Description</strong>
      </th>
      <th>
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>asc_location</td>
      <td>The location where Azure Security Center stores the data of the subscription. Run the 'azure-sc-list-location' command to get the asc_location.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>resource_group_name</td>
      <td>The name of the resource group within the user's subscription. The name is case insensitive.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>subscription_id</td>
      <td>Subscription ID to use. Can be retrieved from the azure-sc-list-subscriptions command. If not specified, the default subscripton ID will be used.</td>
      <td>Optional</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Context Output</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Path</strong>
      </th>
      <th>
        <strong>Type</strong>
      </th>
      <th>
        <strong>Description</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>AzureSecurityCenter.JITPolicy.Name</td>
      <td>string</td>
      <td>Poliyc display name</td>
    </tr>
    <tr>
      <td>AzureSecurityCenter.JITPolicy.Rules</td>
      <td>string</td>
      <td>CSV list of access rules for Microsoft.Compute/virtualMachines resource, in the format (VMName: allowPort1,...)</td>
    </tr>
    <tr>
      <td>AzureSecurityCenter.JITPolicy.Location</td>
      <td>string</td>
      <td>Location where the resource is stored</td>
    </tr>
    <tr>
      <td>AzureSecurityCenter.JITPolicy.Kind</td>
      <td>string</td>
      <td>Policy resource type</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!azure-sc-list-jit </code>
</p>
<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->

<h3>8. azure-sc-list-storage</h3>
<hr>
<p>Lists all the storage accounts available under the subscription.</p>
<h5>Base Command</h5>
<p>
  <code>azure-sc-list-storage</code>
</p>

<h5>Input</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Argument Name</strong>
      </th>
      <th>
        <strong>Description</strong>
      </th>
      <th>
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>subscription_id</td>
      <td>Subscription ID to use. Can be retrieved from the azure-sc-list-subscriptions command. If not specified, the default subscripton ID will be used.</td>
      <td>Optional</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Context Output</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Path</strong>
      </th>
      <th>
        <strong>Type</strong>
      </th>
      <th>
        <strong>Description</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>AzureSecurityCenter.Storage.Name</td>
      <td>string</td>
      <td>Name of the storage account</td>
    </tr>
    <tr>
      <td>AzureSecurityCenter.Storage.ResourceGroupName</td>
      <td>string</td>
      <td>Names of the attached resource group</td>
    </tr>
    <tr>
      <td>AzureSecurityCenter.Storage.Location</td>
      <td>string</td>
      <td>The geo-location where the resource resides</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!azure-sc-list-storage</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "AzureSecurityCenter.Storage": [
        {
            "ID": "/subscriptions/xxxx-xxxx-xxxx-xxxx-xxxx/resourceGroups/cloud-shell-storage-eastus/providers/Microsoft.Storage/storageAccounts/cs20f907ea4bc8bx4c11x9d7",
            "Location": "eastus",
            "Name": "cs20f907ea4bc8bx4c11x9d7",
            "ResourceGroupName": "cloud-shell-storage-eastus"
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<h3>Azure Security Center - List Storage Accounts</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Name</strong></th>
      <th><strong>ResourceGroupName</strong></th>
      <th><strong>Location</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> cs20f907ea4bc8bx4c11x9d7 </td>
      <td> cloud-shell-storage-eastus </td>
      <td> eastus </td>
    </tr>
    <tr>
      <td> useastrgdiag204 </td>
      <td> us-east-rg </td>
      <td> eastus </td>
    </tr>
    <tr>
      <td> demistodevops </td>
      <td> cloud-shell-storage-eastus </td>
      <td> westeurope </td>
    </tr>
  </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->

<h3>9. azure-list-subscriptions</h3>
<hr>
<p>List available subscriptions for this application.</p>
<h5>Base Command</h5>
<p>
  <code>azure-list-subscriptions</code>
</p>

<h5>Input</h5>
There are no input arguments for this command.
<p>&nbsp;</p>
<h5>Context Output</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Path</strong>
      </th>
      <th>
        <strong>Type</strong>
      </th>
      <th>
        <strong>Description</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Azure.Subscription.ID</td>
      <td>String</td>
      <td>Subscription ID</td>
    </tr>
    <tr>
      <td>Azure.Subscription.Name</td>
      <td>String</td>
      <td>Subscription Name</td>
    </tr>
    <tr>
      <td>Azure.Subscription.Enabled</td>
      <td>String</td>
      <td>Subscription state</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!azure-list-subscriptions</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Azure.Subscription": [
        {
            "ID": "/subscriptions/xxxx-xxxx-xxxx-xxxx-xxxx",
            "Name": "Pay-As-You-Go",
            "State": "Enabled"
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<h3>Azure Security Center - Subscriptions</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>ID</strong></th>
      <th><strong>Name</strong></th>
      <th><strong>State</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> /subscriptions/xxxx-xxxx-xxxx-xxxx-xxxx </td>
      <td> Pay-As-You-Go </td>
      <td> Enabled </td>
    </tr>
  </tbody>
</table>

<h3>List of Subscriptions</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>ID</strong></th>
      <th><strong>Name</strong></th>
      <th><strong>State</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> /subscriptions/xxxx-xxxx-xxxx-xxxx-xxxx</td>
      <td> Pay-As-You-Go </td>
      <td> Enabled </td>
    </tr>
  </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->

<h3>10. azure-sc-list-location</h3>
<hr>
<p>The location of the responsible ASC of the specific subscription. For each subscription there is only one responsible location.</p>
<h5>Base Command</h5>
<p>
  <code>azure-sc-list-location</code>
</p>

<h5>Input</h5>
There are no input arguments for this command.
<p>&nbsp;</p>
<h5>Context Output</h5>
There are no context output for this command.
<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!azure-sc-list-location</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "AzureSecurityCenter.Location": [
        {
            "HomeRegionName": "centralus",
            "ID": "/subscriptions/xxxx-xxxx-xxxx-xxxx-xxxx/providers/Microsoft.Security/locations/centralus",
            "Name": "centralus"
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<h3>Azure Security Center - List Locations</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>HomeRegionName</strong></th>
      <th><strong>Name</strong></th>
      <th><strong>ID</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> centralus </td>
      <td> centralus </td>
      <td> /subscriptions/xxxx-xxxx-xxxx-xxxx-xxxx/providers/Microsoft.Security/locations/centralus </td>
    </tr>
  </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
<h2>Additional Information</h2>
<span>For more information regarding roles, see <a href="https://docs.microsoft.com/en-us/azure/role-based-access-control/role-assignments-portal">the microsoft documentation.</a></span>