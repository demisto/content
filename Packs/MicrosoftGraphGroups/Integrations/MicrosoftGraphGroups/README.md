<p>
Azure Active Directory Groups enables you to create and manage different types of groups and group functionality according to your requirements.

This integration was integrated and tested with version 1.0 of Microsoft Graph Groups API
</p>
<h2>Use Cases</h2>
<ul>
<li>Manage the organization groups.</li>
</ul>
<h2>Authentication</h2>
For more details about the authentication used in this integration, see <a href="https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication">Microsoft Integrations - Authentication</a>.

<h3>Required Permissions</h3>
<li>Directory.ReadWrite.All - Delegated</li>
<li>Directory.ReadWrite.All - Application</li>
<li>Group.ReadWrite.All - Application</li>

<h2>Configure Azure Active Directory Groups on Cortex XSOAR</h2>

<li>Manage the organization groups.</li>

<ol>
  <li>Navigate to&nbsp;<strong>Settings</strong>&nbsp;&gt;&nbsp;<strong>Integrations</strong>
  &nbsp;&gt;&nbsp;<strong>Servers &amp; Services</strong>.</li>
  <li>Search for Azure Active Directory Groups.</li>
  <li>
    Click&nbsp;<strong>Add instance</strong>&nbsp;to create and configure a new integration instance.
    <ul>
      <li><strong>Name</strong>: a textual name for the integration instance.</li>
   <li><strong>Server URL</strong></li>
   <li><strong>ID (received from the admin consent - see Detailed Instructions (?)</strong></li>
   <li><strong>Token (received from the admin consent - see Detailed Instructions (?) section)</strong></li>
   <li><strong>Key (received from the admin consent - see Detailed Instructions (?)</strong></li>
   <li><strong>Certificate Thumbprint</strong></li>
   <li><strong>Private Key</strong></li>
   <li><strong>Trust any certificate (not secure)</strong></li>
   <li><strong>Use system proxy settings</strong></li>
    </ul>
  </li>
  <li>
    Click&nbsp;<strong>Test</strong>&nbsp;to validate the new instance.
  </li>
</ol>

<h2>Commands</h2>
<p>
  You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
  After you successfully execute a command, a DBot message appears in the War Room with the command details.
</p>
<ol>
  <li><a href="#msgraph-groups-list-groups" target="_self">Provides a list of groups: msgraph-groups-list-groups</a></li>
  <li><a href="#msgraph-groups-get-group" target="_self">Returns details of a group: msgraph-groups-get-group</a></li>
  <li><a href="#msgraph-groups-create-group" target="_self">Create a group: msgraph-groups-create-group</a></li>
  <li><a href="#msgraph-groups-delete-group" target="_self">Deletes a group: msgraph-groups-delete-group</a></li>
  <li><a href="#msgraph-groups-list-members" target="_self">Lists group members: msgraph-groups-list-members</a></li>
  <li><a href="#msgraph-groups-add-member" target="_self">Add a member to a group: msgraph-groups-add-member</a></li>
  <li><a href="#msgraph-groups-remove-member" target="_self">Removes a member from a group: msgraph-groups-remove-member</a></li>
  <li><a href="#msgraph-groups-generate-login-url" target="_self">Generates the login url used for Authorization code flow.: msgraph-groups-generate-login-url</a></li>
</ol>
<h3 id="msgraph-groups-list-groups">1. msgraph-groups-list-groups</h3>
<hr>
<p>Provides a list of groups.</p>
<h5>Base Command</h5>
<p>
  <code>msgraph-groups-list-groups</code>
</p>

<h5>Required Permissions</h5>
<p>The following permissions are required for this command.</p>
<ul>
    <li>Directory.ReadWrite.All - Delegated</li>
    <li>Group.ReadWrite.All - Application</li>
</ul>
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
      <td>order_by</td>
      <td>Sorts groups in an organization by the field values. For example, displayName.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>next_link</td>
      <td>The URL to the next results page.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>top</td>
      <td>Sets the page size of the results.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>filter</td>
      <td>Filters group results. For example, startswith(displayName,'J'), groupTypes/any(c:c+eq+'Unified').</td>
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
      <td>MSGraphGroups.Classification</td>
      <td>String</td>
      <td>A classification for the group (such as low, medium or high business impact).</td>
    </tr>
    <tr>
      <td>MSGraphGroups.CreatedDateTime</td>
      <td>String</td>
      <td>The timestamp when the group was created.</td>
    </tr>
    <tr>
      <td>MSGraphGroups.DeletedDateTime</td>
      <td>String</td>
      <td>The timestamp when the group was deleted.</td>
    </tr>
    <tr>
      <td>MSGraphGroups.Description</td>
      <td>String</td>
      <td>An optional description for the group.</td>
    </tr>
    <tr>
      <td>MSGraphGroups.GroupTypes</td>
      <td>String</td>
      <td>Specifies the group type and its membership.
If the group collection contains a Unified value, the group is an Office 365 group; otherwise it's a security group.
If the collection includes DynamicMembership, the group has dynamic membership; otherwise, membership is static.</td>
    </tr>
    <tr>
      <td>MSGraphGroups.ID</td>
      <td>String</td>
      <td>The unique identifier for the group.</td>
    </tr>
    <tr>
      <td>MSGraphGroup.IsAssignableToRole</td>
      <td>String</td>
      <td>Whether the group assigned to a specific role.</td>
    </tr>
    <tr>
      <td>MSGraphGroup.Mail</td>
      <td>String</td>
      <td>The SMTP address for the group. For example, "serviceadmins@contoso.onmicrosoft.com".</td>
    </tr>
    <tr>
      <td>MSGraphGroup.MailEnabled</td>
      <td>Boolean</td>
      <td>Specifies whether the group is mail-enabled.</td>
    </tr>
    <tr>
      <td>MSGraphGroup.MailNickname</td>
      <td>String</td>
      <td>The mail alias for the group, which is unique in the organization.</td>
    </tr>
    <tr>
      <td>MSGraphGroup.OnPremisesDomainName</td>
      <td>String</td>
      <td>Contains the on-premises domain FQDN. Also called dnsDomainName, which is synchronized from the on-premises directory.</td>
    </tr>
    <tr>
      <td>MSGraphGroup.OnPremisesLastSyncDateTime</td>
      <td>String</td>
      <td>Indicates the last time at which the group was synced with the on-premises directory. The Timestamp type represents date and time information using ISO 8601 format in UTC time. For example, midnight UTC on Jan 1, 2019 is '2019-01-01T00:00:00Z'.</td>
    </tr>
    <tr>
      <td>MSGraphGroup.OnPremisesSyncEnabled</td>
      <td>String</td>
      <td>Whether this group is synced from an on-premises directory (true). This group was originally synced from an on-premises directory but is no longer synced (false). Null if this object has never been synced from an on-premises directory (default).
</td>
    </tr>
    <tr>
      <td>MSGraphGroup.ProxyAddresses</td>
      <td>String</td>
      <td>Email addresses for the group that directs to the same group mailbox. For example: ["SMTP: example@demisto.com", "smtp: example@demisto.com"].</td>
    </tr>
    <tr>
      <td>MSGraphGroup.RenewedDateTime</td>
      <td>String</td>
      <td>Timestamp of when the group was last renewed, which represents the time and date information using ISO 8601 format. Always in UTC time. For example, midnight UTC on Jan 1, 2019 is '2019-01-01T00:00:00Z'.</td>
    </tr>
    <tr>
      <td>MSGraphGroup.SecurityEnabled</td>
      <td>Boolean</td>
      <td>Specifies whether the group is a security group.</td>
    </tr>
    <tr>
      <td>MSGraphGroup.Visibility</td>
      <td>String</td>
      <td>Specifies the visibility of an Office 365 group. Can be: "Private", "Public", or "Hiddenmembership". Blank values are treated as public.</td>
    </tr>
    <tr>
      <td>MSGraphGroup.NextLink</td>
      <td>String</td>
      <td>The URL of the next results page.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!msgraph-groups-list-groups top=4</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "MSGraphGroups": "https://graph.microsoft.com/v1.0/groups?$top=4&$skiptoken={skip_token}"
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>Groups (Note that there are more results. Please use the next_link argument to see them.):</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>ID</strong></th>
      <th><strong>Display Name</strong></th>
      <th><strong>Description</strong></th>
      <th><strong>Created Date Time</strong></th>
      <th><strong>Mail</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> id </td>
      <td> DemistoTeam </td>
      <td> DemistoTeam </td>
      <td> 2019-08-24T09:39:03Z </td>
      <td> DemistoTeam@demistodev.onmicrosoft.com </td>
    </tr>
    <tr>
      <td> id </td>
      <td> Graph Groups Test - TEMP </td>
      <td>  </td>
      <td> 2019-12-04T11:57:29Z </td>
      <td>  </td>
    </tr>
    <tr>
      <td> id </td>
      <td> TestPublic </td>
      <td> TestPublic </td>
      <td> 2018-12-26T09:44:16Z </td>
      <td> testpublic@demistodev.onmicrosoft.com </td>
    </tr>
    <tr>
      <td> id </td>
      <td> Graph Groups Test - DELETE </td>
      <td>  </td>
      <td> 2019-11-17T11:50:59Z </td>
      <td>  </td>
    </tr>
  </tbody>
</table>
</p>

<h3 id="msgraph-groups-get-group">2. msgraph-groups-get-group</h3>
<hr>
<p>Returns details of a group.</p>
<h5>Base Command</h5>
<p>
  <code>msgraph-groups-get-group</code>
</p>

<h5>Required Permissions</h5>
<p>The following permissions are required for this command.</p>
<ul>
    <li>Directory.ReadWrite.All - Delegated</li>
    <li>Group.ReadWrite.All - Application</li>
</ul>
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
      <td>group_id</td>
      <td>The ID of the group.</td>
      <td>Required</td>
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
      <td>MSGraphGroups.Classification</td>
      <td>String</td>
      <td>A classification for the group (such as low, medium or high business impact).</td>
    </tr>
    <tr>
      <td>MSGraphGroups.CreatedDateTime</td>
      <td>String</td>
      <td>The timestamp when the group was created.</td>
    </tr>
    <tr>
      <td>MSGraphGroups.DeletedDateTime</td>
      <td>String</td>
      <td>The timestamp when the group was deleted.</td>
    </tr>
    <tr>
      <td>MSGraphGroups.Description</td>
      <td>String</td>
      <td>An optional description for the group.</td>
    </tr>
    <tr>
      <td>MSGraphGroups.GroupTypes</td>
      <td>String</td>
      <td>Specifies the group type and its membership.
If the group collection contains a Unified value, the group is an Office 365 group; otherwise it's a security group.
If the collection includes DynamicMembership, the group has dynamic membership; otherwise, membership is static.</td>
    </tr>
    <tr>
      <td>MSGraphGroups.ID</td>
      <td>String</td>
      <td>The unique identifier for the group.</td>
    </tr>
    <tr>
      <td>MSGraphGroup.IsAssignableToRole</td>
      <td>String</td>
      <td>Whether the group assigned to a specific role.</td>
    </tr>
    <tr>
      <td>MSGraphGroup.Mail</td>
      <td>String</td>
      <td>The SMTP address for the group. For example, "serviceadmins@contoso.onmicrosoft.com".</td>
    </tr>
    <tr>
      <td>MSGraphGroup.MailEnabled</td>
      <td>Boolean</td>
      <td>Specifies whether the group is mail-enabled.</td>
    </tr>
    <tr>
      <td>MSGraphGroup.MailNickname</td>
      <td>String</td>
      <td>The mail alias for the group, unique in the organization.</td>
    </tr>
    <tr>
      <td>MSGraphGroup.OnPremisesDomainName</td>
      <td>String</td>
      <td>Contains the on-premises domain FQDN. Also called dnsDomainName, which is synchronized from the on-premises directory.</td>
    </tr>
    <tr>
      <td>MSGraphGroup.OnPremisesLastSyncDateTime</td>
      <td>String</td>
      <td>Indicates the last time at which the group was synced with the on-premises directory.The Timestamp type represents date and time information using ISO 8601 format in UTC time. For example, midnight UTC on Jan 1, 2019 is '2019-01-01T00:00:00Z'.</td>
    </tr>
    <tr>
      <td>MSGraphGroup.OnPremisesSyncEnabled</td>
      <td>String</td>
      <td>Whether the group is synced from an on-premises directory (true). This group was originally synced from an on-premises directory but is no longer synced (false). Null if this object has never been synced from an on-premises directory (default).
</td>
    </tr>
    <tr>
      <td>MSGraphGroup.ProxyAddresses</td>
      <td>String</td>
      <td>Email addresses for the group that directs to the same group mailbox. For example: ["SMTP: example@demisto.com", "smtp: example@demisto.com"].</td>
    </tr>
    <tr>
      <td>MSGraphGroup.RenewedDateTime</td>
      <td>String</td>
      <td>The timestamp of when the group was last renewed. This cannot be modified directly and is only updated via the renew service action. The Timestamp type represents date and time information using ISO 8601 format in UTC time. For example, midnight UTC on Jan 1, 2019 is '2019-01-01T00:00:00Z'.</td>
    </tr>
    <tr>
      <td>MSGraphGroup.SecurityEnabled</td>
      <td>Boolean</td>
      <td>Specifies whether the group is a security group.</td>
    </tr>
    <tr>
      <td>MSGraphGroup.Visibility</td>
      <td>String</td>
      <td>Specifies the visibility of an Office 365 group. Possible values are: Private, Public, or Hiddenmembership. Blank values are treated as public.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!msgraph-groups-get-group group_id={group_id}</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "MSGraphGroups": {
        "Classification": null,
        "CreatedDateTime": "2019-08-24T09:39:03Z",
        "DeletedDateTime": null,
        "Description": "DemistoTeam",
        "DisplayName": "DemistoTeam",
        "GroupTypes": [
            "Unified"
        ],
        "ID": "id",
        "IsAssignableToRole": null,
        "Mail": "DemistoTeam@demistodev.onmicrosoft.com",
        "MailEnabled": true,
        "MailNickname": "DemistoTeam",
        "OnPremisesDomainName": null,
        "OnPremisesLastSyncDateTime": null,
        "OnPremisesSyncEnabled": null,
        "ProxyAddresses": [
            "SPO:spo",
            "SMTP:DemistoTeam@demistodev.onmicrosoft.com"
        ],
        "RenewedDateTime": "2019-11-07T11:40:09Z",
        "SecurityEnabled": false,
        "Visibility": "Public"
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>Groups:</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>ID</strong></th>
      <th><strong>Display Name</strong></th>
      <th><strong>Description</strong></th>
      <th><strong>Created Date Time</strong></th>
      <th><strong>Mail</strong></th>
      <th><strong>Security Enabled</strong></th>
      <th><strong>Visibility</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> id </td>
      <td> DemistoTeam </td>
      <td> DemistoTeam </td>
      <td> 2019-08-24T09:39:03Z </td>
      <td> DemistoTeam@demistodev.onmicrosoft.com </td>
      <td> false </td>
      <td> Public </td>
    </tr>
  </tbody>
</table>
</p>

<h3 id="msgraph-groups-create-group">3. msgraph-groups-create-group</h3>
<hr>
<p>Create a group.</p>
<h5>Base Command</h5>
<p>
  <code>msgraph-groups-create-group</code>
</p>

<h5>Required Permissions</h5>
<p>The following permissions are required for this command.</p>
<ul>
    <li>Directory.ReadWrite.All - Delegated</li>
    <li>Group.ReadWrite.All - Application</li>
</ul>
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
      <td>display_name</td>
      <td>The display name of the group.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>mail_enabled</td>
      <td>Set to true for mail-enabled groups. False for groups without an email.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>mail_nickname</td>
      <td>The mail alias for the group.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>security_enabled</td>
      <td>Set to true for security groups. False for non security groups (regular groups).</td>
      <td>Required</td>
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
      <td>MSGraphGroups.Classification</td>
      <td>String</td>
      <td>A classification for the group (such as low, medium or high business impact).</td>
    </tr>
    <tr>
      <td>MSGraphGroups.CreatedDateTime</td>
      <td>String</td>
      <td>The timestamp when the group was created.</td>
    </tr>
    <tr>
      <td>MSGraphGroups.DeletedDateTime</td>
      <td>String</td>
      <td>The timestamp when the group was deleted.</td>
    </tr>
    <tr>
      <td>MSGraphGroups.Description</td>
      <td>String</td>
      <td>An optional description for the group.</td>
    </tr>
    <tr>
      <td>MSGraphGroups.GroupTypes</td>
      <td>String</td>
      <td>Specifies the group type and its membership.
If the group collection contains a Unified value, the group is an Office 365 group; otherwise it's a security group.
If the group collection includes DynamicMembership, the group has dynamic membership; otherwise, membership is static.</td>
    </tr>
    <tr>
      <td>MSGraphGroups.ID</td>
      <td>String</td>
      <td>The unique identifier for the group.</td>
    </tr>
    <tr>
      <td>MSGraphGroup.IsAssignableToRole</td>
      <td>String</td>
      <td>Whether the group is assigned to a specific role.</td>
    </tr>
    <tr>
      <td>MSGraphGroup.Mail</td>
      <td>String</td>
      <td>The SMTP address for the group. For example, "serviceadmins@contoso.onmicrosoft.com".</td>
    </tr>
    <tr>
      <td>MSGraphGroup.MailEnabled</td>
      <td>Boolean</td>
      <td>Specifies whether the group is mail-enabled.</td>
    </tr>
    <tr>
      <td>MSGraphGroup.MailNickname</td>
      <td>String</td>
      <td>The mail alias for the group, unique in the organization.</td>
    </tr>
    <tr>
      <td>MSGraphGroup.OnPremisesDomainName</td>
      <td>String</td>
      <td>Contains the on-premises domain FQDN. Also called dnsDomainName, which is synchronized from the on-premises directory.</td>
    </tr>
    <tr>
      <td>MSGraphGroup.OnPremisesLastSyncDateTime</td>
      <td>String</td>
      <td>Indicates the last time at which the group was synced with the on-premises directory.The Timestamp type represents date and time information using ISO 8601 format in UTC time. For example, midnight UTC on Jan 1, 2019 is '2019-01-01T00:00:00Z'.</td>
    </tr>
    <tr>
      <td>MSGraphGroup.OnPremisesSyncEnabled</td>
      <td>String</td>
      <td>Whether this group is synced from an on-premises directory (true). This group was originally synced from an on-premises directory but is no longer synced (false). Null if this object has never been synced from an on-premises directory (default).
</td>
    </tr>
    <tr>
      <td>MSGraphGroup.ProxyAddresses</td>
      <td>String</td>
      <td>Email addresses for the group that directs to the same group mailbox. For example, ["SMTP: example@demisto.com", "smtp: example@demisto.com"].</td>
    </tr>
    <tr>
      <td>MSGraphGroup.RenewedDateTime</td>
      <td>String</td>
      <td>Timestamp of when the group was last renewed. This cannot be modified directly and is only updated via the renew service action. The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z'.</td>
    </tr>
    <tr>
      <td>MSGraphGroup.SecurityEnabled</td>
      <td>Boolean</td>
      <td>Specifies whether the group is a security group.</td>
    </tr>
    <tr>
      <td>MSGraphGroup.Visibility</td>
      <td>String</td>
      <td>Specifies the visibility of an Office 365 group. Possible values are: Private, Public, or Hiddenmembership; blank values are treated as public.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!msgraph-groups-create-group display_name="Graph Groups Test - TEMP" mail_nickname="Test_Group_101" security_enabled="true"</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "MSGraphGroups": {
        "Classification": null,
        "CreatedDateTime": "2019-12-04T11:59:44Z",
        "DeletedDateTime": null,
        "Description": null,
        "DisplayName": "Graph Groups Test - TEMP",
        "GroupTypes": [],
        "ID": "id",
        "IsAssignableToRole": null,
        "Mail": null,
        "MailEnabled": false,
        "MailNickname": "Test_Group_101",
        "OnPremisesDomainName": null,
        "OnPremisesLastSyncDateTime": null,
        "OnPremisesSyncEnabled": null,
        "ProxyAddresses": [],
        "RenewedDateTime": "2019-12-04T11:59:44Z",
        "SecurityEnabled": true,
        "Visibility": null
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>Graph Groups Test - TEMP was created successfully:</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>ID</strong></th>
      <th><strong>Display Name</strong></th>
      <th><strong>Created Date Time</strong></th>
      <th><strong>Security Enabled</strong></th>
      <th><strong>Mail Enabled</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> id </td>
      <td> Graph Groups Test - TEMP </td>
      <td> 2019-12-04T11:59:44Z </td>
      <td> true </td>
      <td> false </td>
    </tr>
  </tbody>
</table>
</p>

<h3 id="msgraph-groups-delete-group">4. msgraph-groups-delete-group</h3>
<hr>
<p>Deletes a group.</p>
<h5>Base Command</h5>
<p>
  <code>msgraph-groups-delete-group</code>
</p>

<h5>Required Permissions</h5>
<p>The following permissions are required for this command.</p>
<ul>
    <li>Directory.ReadWrite.All - Delegated</li>
    <li>Group.ReadWrite.All - Application</li>
</ul>
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
      <td>group_id</td>
      <td>The group ID.</td>
      <td>Required</td>
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
      <td>MSGraphGroups.ID</td>
      <td>String</td>
      <td>The unique identifier for the group.</td>
    </tr>
    <tr>
      <td>MSGraphGroup.Deleted</td>
      <td>Boolean</td>
      <td>Specifies whether the group was deleted.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!msgraph-groups-delete-group group_id="id"</code>
</p>

<h5>Human Readable Output</h5>

<h3 id="msgraph-groups-list-members">5. msgraph-groups-list-members</h3>
<hr>
<p>Lists group members.</p>
<h5>Base Command</h5>
<p>
  <code>msgraph-groups-list-members</code>
</p>

<h5>Required Permissions</h5>
<p>The following permissions are required for this command.</p>
<ul>
    <li>Directory.ReadWrite.All - Delegated</li>
    <li>Group.ReadWrite.All - Application</li>
</ul>
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
      <td>group_id</td>
      <td>The group ID.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>next_link</td>
      <td>The URL for the next results page.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>top</td>
      <td>Sets the page size of results.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>filter</td>
      <td>Filters members results. For example, startswith(displayName,'user').</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>count</td>
      <td>Retrieves the total count of matching resources.</td>
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
      <td>MSGraphGroups.Members.BussinessPhones</td>
      <td>String</td>
      <td>The telephone numbers for the user.</td>
    </tr>
    <tr>
      <td>MSGraphGroups.Members.GivenName</td>
      <td>String</td>
      <td>The given name (first name) of the user.</td>
    </tr>
    <tr>
      <td>MSGraphGroups.Members.MobilePhone</td>
      <td>String</td>
      <td>The primary mobile telephone number for the user.</td>
    </tr>
    <tr>
      <td>MSGraphGroups.Members.DisplayName</td>
      <td>String</td>
      <td>The name displayed in the address book for the user.
Usually the combination of the user's first name, middle initial and last name.</td>
    </tr>
    <tr>
      <td>MSGraphGroups.Members.UserPrincipalName</td>
      <td>Unknown</td>
      <td>The user principal name (UPN) of the user.
The UPN is an Internet-style login name for the user based on the Internet standard RFC 822.
By convention, this should map to the user's email name.
The general format is alias@domain, where the domain must be present in the tenant’s collection of verified domains.</td>
    </tr>
    <tr>
      <td>MSGraphGroups.Members.OfficeLocation</td>
      <td>String</td>
      <td>The office location in the user's place of business.</td>
    </tr>
    <tr>
      <td>MSGraphGroups.Members.Mail</td>
      <td>String</td>
      <td>The SMTP address for the user. For example, "jeff@contoso.onmicrosoft.com".</td>
    </tr>
    <tr>
      <td>MSGraphGroups.Members.PreferredLanguage</td>
      <td>String</td>
      <td>The preferred language for the user. Should follow ISO 639-1 Code. For example, "en-US".</td>
    </tr>
    <tr>
      <td>MSGraphGroups.Members.Surname</td>
      <td>String</td>
      <td>The user's surname (family name or last name).</td>
    </tr>
    <tr>
      <td>MSGraphGroups.Members.JobTitle</td>
      <td>String</td>
      <td>The user’s job title.</td>
    </tr>
    <tr>
      <td>MSGraphGroups.Members.ID</td>
      <td>String</td>
      <td>The unique identifier for the user.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!msgraph-groups-list-members group_id=id</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "MSGraphGroups": {
        "Classification": null,
        "CreatedDateTime": "2019-08-24T09:39:03Z",
        "DeletedDateTime": null,
        "Description": "DemistoTeam",
        "DisplayName": "DemistoTeam",
        "GroupTypes": [
            "Unified"
        ],
        "ID": "id",
        "IsAssignableToRole": null,
        "Mail": "DemistoTeam@demistodev.onmicrosoft.com",
        "MailEnabled": true,
        "MailNickname": "DemistoTeam",
        "Members": [
            {
                "BusinessPhones": [],
                "DisplayName": "name",
                "GivenName": "name",
                "ID": "id",
                "JobTitle": "test",
                "Mail": "name@demistodev.onmicrosoft.com",
                "MobilePhone": null,
                "OfficeLocation": null,
                "PreferredLanguage": "en-US",
                "Surname": "name",
                "UserPrincipalName": "name@demistodev.onmicrosoft.com"
            },
        ],
        "OnPremisesDomainName": null,
        "OnPremisesLastSyncDateTime": null,
        "OnPremisesSyncEnabled": null,
        "ProxyAddresses": [
            "SPO:spo",
            "SMTP:DemistoTeam@demistodev.onmicrosoft.com"
        ],
        "RenewedDateTime": "2019-11-07T11:40:09Z",
        "SecurityEnabled": false,
        "Visibility": "Public"
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>Group {group_id} members:</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>ID</strong></th>
      <th><strong>Display Name</strong></th>
      <th><strong>Job Title</strong></th>
      <th><strong>Mail</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> id </td>
      <td> name </td>
      <td> test </td>
      <td> name@demistodev.onmicrosoft.com </td>
    </tr>
  </tbody>
</table>
</p>

<h3 id="msgraph-groups-add-member">6. msgraph-groups-add-member</h3>
<hr>
<p>Add a member to a group.</p>
<h5>Base Command</h5>
<p>
  <code>msgraph-groups-add-member</code>
</p>

<h5>Required Permissions</h5>
<p>The following permissions are required for this command.</p>
<ul>
    <li>Directory.ReadWrite.All - Delegated</li>
    <li>Group.ReadWrite.All - Application</li>
</ul>
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
      <td>group_id</td>
      <td>The group ID.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>user_id</td>
      <td>The user ID.</td>
      <td>Required</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Context Output</h5>
There are no context output for this command.
<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!msgraph-groups-add-member group_id="id" user_id="id"</code>
</p>
<h5>Context Example</h5>
<pre>
{}
</pre>
<h5>Human Readable Output</h5>
<p>
<p>
User {user_id} was added to the Group {group_id} successfully.
</p>
</p>

<h3 id="msgraph-groups-remove-member">7. msgraph-groups-remove-member</h3>
<hr>
<p>Removes a member from a group.</p>
<h5>Base Command</h5>
<p>
  <code>msgraph-groups-remove-member</code>
</p>

<h5>Required Permissions</h5>
<p>The following permissions are required for this command.</p>
<ul>
    <li>Directory.ReadWrite.All - Delegated</li>
    <li>Group.ReadWrite.All - Application</li>
</ul>
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
      <td>group_id</td>
      <td>The group ID.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>user_id</td>
      <td>The user ID.</td>
      <td>Required</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Context Output</h5>
There are no context output for this command.
<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!msgraph-groups-remove-member group_id="id" user_id="id"</code>
</p>
<h5>Context Example</h5>
<pre>
{}
</pre>
<h5>Human Readable Output</h5>
<p>
<p>
User {user_id} was removed from the Group {group_id} successfully.
</p>

<h3 id="msgraph-groups-auth-reset">8. msgraph-groups-auth-reset</h3>
<hr>
<p>Run this command if for some reason you need to rerun the authentication process.</p>
<h5>Base Command</h5>
<p>
  <code>msgraph-groups-auth-reset</code>
</p>

<h5>Input</h5>

<p>There are no input arguments for this command.&nbsp;</p>
<h5>Context Output</h5>
There are no context output for this command.
<p>&nbsp;</p>

<h2>Additional Information</h2><h2>Troubleshooting</h2>

<h2>Known Limitations</h2>
<p>
<a href="https://learn.microsoft.com/en-us/graph/api/resources/groups-overview?view=graph-rest-1.0&tabs=http">As per</a>, Microsoft also supports dynamic distribution groups which cannot be managed or retrieved through Microsoft Graph.
</p>
