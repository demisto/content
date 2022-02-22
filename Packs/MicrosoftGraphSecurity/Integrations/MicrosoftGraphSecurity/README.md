<!-- HTML_DOC -->
<p>Use the Microsoft Graph integration to connect to and interact with data on Microsoft Platforms. This integration was integrated and tested with Microsoft Graph v1.0.</p>
<h2>Use Cases</h2>
<ol>
<li>Manage alerts</li>
<li>Manage users</li>
</ol>

<h2>Authentication</h2>
For more details about the authentication used in this integration, see <a href="https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication">Microsoft Integrations - Authentication</a>.

<h3>Required Permissions</h3>
<ul>
<li>SecurityEvents.Read.All - Application (required for the commands: <code>msg-search-alerts</code> and <code>msg-get-alert-details</code>)</li>
<li>SecurityEvents.ReadWrite.All - Application (required for updating alerts with the command: <code>msg-update-alert</code>)</li>
<li>User.Read.All - Application (Only required if using the deprecated commands: <code>msg-get-user</code> and <code>msg-get-users</code>)</li>
</ul>


<h2>Configure Microsoft Graph on Cortex XSOAR</h2>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for Microsoft Graph.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong>Host URL (e.g., <a href="https://graph.microsoft.com/" rel="nofollow">https://graph.microsoft.com</a>)</strong></li>
<li><strong>ID you received from the admin consent</strong></li>
<li><strong>Key you received from the admin consent</strong></li>
<li><strong>Token you received from the admin consent</strong></li>
<li><strong>Trust any certificate (not secure)</strong></li>
<li><strong>Use system proxy settings</strong></li>
</ul>
</li>
<li>Click <strong>Test</strong> to validate the URLs, token, and connection.</li>
</ol>

<h2>Commands</h2>
<p>You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.<br> After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li><a href="#h_842458104521538470633978">Search alerts: msg-search-alerts</a></li>
<li><a href="#h_3611731291071538470639531">Get details for an alert: msg-get-alert-details</a></li>
<li><a href="#h_4798847561611538470644248">Update an alert: msg-update-alert</a></li>
<li><a href="#h_6620251952141538470649590">Get a list of user objects: msg-get-users</a> - Deprecated - Use the Azure Active Directory Users integration instead.</li>
<li><a href="#h_4642340712641538470655690">Get information for a user object: msg-get-user</a> - Deprecated - Use the Azure Active Directory Users integration instead.</li>
</ol>
<h3 id="h_842458104521538470633978">1. Search alerts</h3>
<hr>
<p>List alerts (security issues) within a customer's tenant that Microsoft or partner security solutions have identified.</p>
<h5>Required Permissions</h5>
<p>For more information about required permissions, see the <a href="https://docs.microsoft.com/en-us/graph/permissions-reference" target="_blank" rel="noopener">Microsoft Graph documentation.</a></p>
<ul>
<li>SecurityEvents.Read.All</li>
<li>SecurityEvents.ReadWrite.All</li>
</ul>
<h5>Base Command</h5>
<p><code>msg-search-alerts</code></p>
<h5>Input</h5>
<table style="width: 746px;">
<thead>
<tr>
<th style="width: 136px;"><strong>Argument Name</strong></th>
<th style="width: 549px;"><strong>Description</strong></th>
<th style="width: 55px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 136px;">last_modified</td>
<td style="width: 549px;">When the alert was last modified (string format - YYYY-MM-DD)</td>
<td style="width: 55px;">Optional</td>
</tr>
<tr>
<td style="width: 136px;">severity</td>
<td style="width: 549px;">Alert severity - set by vendor/provider</td>
<td style="width: 55px;">Optional</td>
</tr>
<tr>
<td style="width: 136px;">category</td>
<td style="width: 549px;">Category of the alert, e.g. credentialTheft, ransomware.<br> Categories can be added or removed by vendors.</td>
<td style="width: 55px;">Optional</td>
</tr>
<tr>
<td style="width: 136px;">time_from</td>
<td style="width: 549px;">The start time (creation time of alert) for the search<br> (string format - YYYY-MM-DD)</td>
<td style="width: 55px;">Optional</td>
</tr>
<tr>
<td style="width: 136px;">time_to</td>
<td style="width: 549px;">The end time (creation time of alert) for the search<br> (string format - YYYY-MM-DD)</td>
<td style="width: 55px;">Optional</td>
</tr>
<tr>
<td style="width: 136px;">filter</td>
<td style="width: 549px;">
<p>Use this field to filter on any of the alert properties in the format "{property} eq '{property-value}'", e.g. "category eq 'ransomware'".</p>
<p>For Microsoft filter syntax, see the <a href="https://docs.microsoft.com/en-us/graph/query-parameters#filter-parameter" target="_blank" rel="noopener">Microsoft Graph Documentation</a>.</p>
</td>
<td style="width: 55px;">Optional</td>
</tr>
</tbody>
</table>
<h5>Context Output</h5>
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 293px;"><strong>Path</strong></th>
<th style="width: 22px;"><strong>Type</strong></th>
<th style="width: 425px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 293px;">MsGraph.Alert.ID</td>
<td style="width: 22px;">string</td>
<td style="width: 425px;">Alert ID</td>
</tr>
<tr>
<td style="width: 293px;">MsGraph.Alert.Title</td>
<td style="width: 22px;">string</td>
<td style="width: 425px;">Alert title</td>
</tr>
<tr>
<td style="width: 293px;">MsGraph.Alert.Category</td>
<td style="width: 22px;">string</td>
<td style="width: 425px;">Alert category</td>
</tr>
<tr>
<td style="width: 293px;">MsGraph.Alert.Severity</td>
<td style="width: 22px;">string</td>
<td style="width: 425px;">Alert severity</td>
</tr>
<tr>
<td style="width: 293px;">MsGraph.Alert.CreatedDate</td>
<td style="width: 22px;">date</td>
<td style="width: 425px;">Alert created date</td>
</tr>
<tr>
<td style="width: 293px;">MsGraph.Alert.EventDate</td>
<td style="width: 22px;">date</td>
<td style="width: 425px;">Alert event time</td>
</tr>
<tr>
<td style="width: 293px;">MsGraph.Alert.Status</td>
<td style="width: 22px;">string</td>
<td style="width: 425px;">Alert status</td>
</tr>
<tr>
<td style="width: 293px;">MsGraph.Alert.Vendor</td>
<td style="width: 22px;">string</td>
<td style="width: 425px;">Alert vendor/provider</td>
</tr>
<tr>
<td style="width: 293px;">MsGraph.Alert.MalwareStates</td>
<td style="width: 22px;">string</td>
<td style="width: 425px;">Alert malware states</td>
</tr>
<tr>
<td style="width: 293px;">MsGraph.Alert.Vendor</td>
<td style="width: 22px;">string</td>
<td style="width: 425px;">Alert vendor</td>
</tr>
<tr>
<td style="width: 293px;">MsGraph.Alert.Provider</td>
<td style="width: 22px;">string</td>
<td style="width: 425px;">Alert provider</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!msg-search-alerts category=repeatedShareActivity time_from=2018-09-19</pre>
<h5>Context Example</h5>
<pre>{
    "MsGraph": {
      "Alert": [
        {
            "Category": "repeatedShareActivity",
            "CreatedDate": "2018-09-21T14:33:00Z",
            "EventDate": "2018-09-21T13:34:00Z",
            "ID": "E21C584F-EA0B-34D9-8DD6-4DABF442A232",
            "Provider": "Cloud Application Security",
            "Severity": "medium",
            "Status": "newAlert",
            "Title": "Mass share",
            "Vendor": "Microsoft"
        },
        {
            "Category": "repeatedShareActivity",
            "CreatedDate": "2018-09-18T18:10:00Z",
            "EventDate": "2018-09-18T16:09:00Z",
            "ID": "F5295FF7-C6DF-49B7-B6BF-4C298D5A7510",
            "Provider": "Cloud Application Security",
            "Severity": "medium",
            "Status": "newAlert",
            "Title": "Mass share",
            "Vendor": "Microsoft"
        }
     ]
   }
}
</pre>
<p> </p>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/31018228/46071116-0053b900-c188-11e8-8d29-3a3831af3151.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/31018228/46071116-0053b900-c188-11e8-8d29-3a3831af3151.png" alt="screen shot 2018-09-26 at 12 29 33" width="748" height="150"></a></p>
<p> </p>
<h3 id="h_3611731291071538470639531">2. Get details for an alert</h3>
<hr>
<p>Get details for a specific alert.</p>
<h5>Required Permissions</h5>
<p>For more information about required permissions, see the <a href="https://docs.microsoft.com/en-us/graph/permissions-reference" target="_blank" rel="noopener">Microsoft Graph documentation.</a></p>
<ul>
<li>SecurityEvents.Read.All</li>
<li>SecurityEvents.ReadWrite.All</li>
</ul>
<h5>Base Command</h5>
<p><code>msg-get-alert-details</code></p>
<h5>Input</h5>
<table style="width: 747px;">
<thead>
<tr>
<th style="width: 125px;"><strong>Argument Name</strong></th>
<th style="width: 565px;"><strong>Description</strong></th>
<th style="width: 50px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 125px;">alert_id</td>
<td style="width: 565px;">The Alert ID - Provider-generated GUID/unique identifier.</td>
<td style="width: 50px;">Required</td>
</tr>
<tr>
<td style="width: 125px;">fields_to_include</td>
<td style="width: 565px;">Fields to fetch for specified Alert apart from the basic properties, given as comma separated values. For example: NetworkConnections,Processes.<br> Optional values: All, NetworkConnections, Processes, RegistryKeys, UserStates, HostStates, FileStates, CloudAppStates, MalwareStates, CustomerComment, Triggers, VendorInformation, VulnerabilityStates</td>
<td style="width: 50px;">Optional</td>
</tr>
</tbody>
</table>
<h5>Context Output</h5>
<table style="width: 747px;">
<thead>
<tr>
<th style="width: 284px;"><strong>Path</strong></th>
<th style="width: 36px;"><strong>Type</strong></th>
<th style="width: 420px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 284px;">MsGraph.Alert.ID</td>
<td style="width: 36px;">string</td>
<td style="width: 420px;">Alert ID</td>
</tr>
<tr>
<td style="width: 284px;">MsGraph.Alert.Title</td>
<td style="width: 36px;">string</td>
<td style="width: 420px;">Alert title</td>
</tr>
<tr>
<td style="width: 284px;">MsGraph.Alert.Category</td>
<td style="width: 36px;">string</td>
<td style="width: 420px;">Alert category</td>
</tr>
<tr>
<td style="width: 284px;">MsGraph.Alert.Severity</td>
<td style="width: 36px;">string</td>
<td style="width: 420px;">Alert severity</td>
</tr>
<tr>
<td style="width: 284px;">MsGraph.Alert.CreatedDate</td>
<td style="width: 36px;">date</td>
<td style="width: 420px;">Alert created date</td>
</tr>
<tr>
<td style="width: 284px;">MsGraph.Alert.EventDate</td>
<td style="width: 36px;">date</td>
<td style="width: 420px;">Alert event date</td>
</tr>
<tr>
<td style="width: 284px;">MsGraph.Alert.Status</td>
<td style="width: 36px;">string</td>
<td style="width: 420px;">Alert status</td>
</tr>
<tr>
<td style="width: 284px;">MsGraph.Alert.VendorProvider</td>
<td style="width: 36px;">string</td>
<td style="width: 420px;">Alert vendor/provider</td>
</tr>
<tr>
<td style="width: 284px;">MsGraph.Alert.MalwareStates</td>
<td style="width: 36px;">string</td>
<td style="width: 420px;">Alert malware states</td>
</tr>
</tbody>
</table>
<h5>Command Example</h5>
<pre>!msg-get-alert-details alert_id=E21C584F-EA0B-34D9-8DD6-4DABF442A232 fields_to_include=VendorInformation</pre>
<h5>Context Example</h5>
<pre>{
    "MsGraph": {
      "Alert": {
        "Category": "repeatedShareActivity",
        "CreatedDate": "2018-09-21T14:33:00Z",
        "EventDate": "2018-09-21T13:34:00Z",
        "ID": "E21C584F-EA0B-34D9-8DD6-4DABF442A232",
        "MalwareStates": [],
        "Severity": "medium",
        "Status": "newAlert",
        "Title": "Mass share"
      }
    }
}
</pre>
<p> </p>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/31018228/46071327-6dffe500-c188-11e8-9390-9c4e60c0935b.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/31018228/46071327-6dffe500-c188-11e8-9390-9c4e60c0935b.png" alt="screen shot 2018-09-26 at 12 33 24" width="751" height="623"></a></p>
<p> </p>
<h3 id="h_4798847561611538470644248">3. Update an alert: msg-update-alert</h3>
<hr>
<p>Update an editable alert property within any integrated solution to keep alert status and assignments in sync across solutions using its reference ID.</p>
<h4>Required Permissions</h4>
<p>For more information about required permissions, see the <a href="https://docs.microsoft.com/en-us/graph/permissions-reference" target="_blank" rel="noopener">Microsoft Graph documentation.</a></p>
<ul>
<li>SecurityEvents.Read.All</li>
<li>SecurityEvents.ReadWrite.All</li>
</ul>
<h5>Base Command</h5>
<p><code>msg-update-alert</code></p>
<h5>Input</h5>
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 143px;"><strong>Argument Name</strong></th>
<th style="width: 527px;"><strong>Description</strong></th>
<th style="width: 70px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 143px;">alert_id</td>
<td style="width: 527px;">Alert ID. Provider-generated GUID/unique identifier.</td>
<td style="width: 70px;">Required</td>
</tr>
<tr>
<td style="width: 143px;">assigned_to</td>
<td style="width: 527px;">Name of the analyst the alert is assigned to for triage, investigation, or remediation.</td>
<td style="width: 70px;">Optional</td>
</tr>
<tr>
<td style="width: 143px;">closed_date_time</td>
<td style="width: 527px;">Time that the alert was closed (string format - MM/DD/YYYY)</td>
<td style="width: 70px;">Optional</td>
</tr>
<tr>
<td style="width: 143px;">comments</td>
<td style="width: 527px;">Analyst comments on the alert (for customer alert management)</td>
<td style="width: 70px;">Optional</td>
</tr>
<tr>
<td style="width: 143px;">feedback</td>
<td style="width: 527px;">Analyst feedback on the alert.</td>
<td style="width: 70px;">Optional</td>
</tr>
<tr>
<td style="width: 143px;">status</td>
<td style="width: 527px;">Alert lifecycle status (stage).</td>
<td style="width: 70px;">Optional</td>
</tr>
<tr>
<td style="width: 143px;">tags</td>
<td style="width: 527px;">User-definable labels that can be applied to an alert and can serve as filter conditions, e.g. "HVA", "SAW").</td>
<td style="width: 70px;">Optional</td>
</tr>
<tr>
<td style="width: 143px;">vendor_information</td>
<td style="width: 527px;">Details about the security service vendor, e.g. Microsoft</td>
<td style="width: 70px;">Optional</td>
</tr>
<tr>
<td style="width: 143px;">provider_information</td>
<td style="width: 527px;">Details about the security service vendor, e.g. Windows Defender ATP</td>
<td style="width: 70px;">Optional</td>
</tr>
</tbody>
</table>
<h5>Context Output</h5>
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 292px;"><strong>Path</strong></th>
<th style="width: 29px;"><strong>Type</strong></th>
<th style="width: 419px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 292px;">MsGraph.Alert.ID</td>
<td style="width: 29px;">string</td>
<td style="width: 419px;">Alert ID</td>
</tr>
<tr>
<td style="width: 292px;">MsGraph.Alert.Status</td>
<td style="width: 29px;">string</td>
<td style="width: 419px;">Alert status</td>
</tr>
</tbody>
</table>

<h5>Command Example</h5>
<pre>!msg-update-alert alert_id=E21C584F-EA0B-34D9-8DD6-4DABF442A232 provider_information="Cloud Application Security" vendor_information=Microsoft status=inProgress</pre>
<h5>Human Readable Output</h5>
<p><code>Alert E21C584F-EA0B-34D9-8DD6-4DABF442A232 has ben successfully updated.</code></p>
<h3 id="h_6620251952141538470649590">4. Get a list of user objects: msg-get-users</h3>
<hr>
<p>Retrieve a list of user objects.</p>
<h5>Required Permissions</h5>
<p>For more information about required permissions, see the <a href="https://docs.microsoft.com/en-us/graph/permissions-reference" target="_blank" rel="noopener">Microsoft Graph documentation.</a></p>
<ul>
<li>User.Read.All</li>
<li>User.ReadWrite.All</li>
<li>Directory.Read.All</li>
<li>Directory.ReadWrite.All</li>
</ul>
<h5>Base Command</h5>
<p><code>msg-get-users</code></p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 332px;"><strong>Path</strong></th>
<th style="width: 26px;"><strong>Type</strong></th>
<th style="width: 382px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 332px;">MsGraph.User.ID</td>
<td style="width: 26px;">string</td>
<td style="width: 382px;">User ID</td>
</tr>
<tr>
<td style="width: 332px;">MsGraph.User.Name</td>
<td style="width: 26px;">string</td>
<td style="width: 382px;">User name</td>
</tr>
<tr>
<td style="width: 332px;">MsGraph.User.Email</td>
<td style="width: 26px;">string</td>
<td style="width: 382px;">User email address</td>
</tr>
<tr>
<td style="width: 332px;">MsGraph.User.Title</td>
<td style="width: 26px;">string</td>
<td style="width: 382px;">User job title</td>
</tr>
</tbody>
</table>
<h5>Command Example</h5>
<pre>!msg-get-users</pre>
<h5>Context Example</h5>
<pre>{
    "MsGraph": {
     "User": {
        "Email": "steve@demisto.com",
        "ID": "17174111-8edf-4613-97d4-74c605c5c181",
        "Name": "Steve Jobs",
        "Title": "Manager"
      }
    }
}
</pre>
<p> </p>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/31018228/46080215-fdfe5880-c1a1-11e8-9df4-6e963c4aab11.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/31018228/46080215-fdfe5880-c1a1-11e8-9df4-6e963c4aab11.png" alt="screen shot 2018-09-26 at 15 36 31"></a></p>
<p> </p>
<h3 id="h_4642340712641538470655690">5. Get information for a user object</h3>
<hr>
<p>Retrieve the properties and relationships of user object.</p>
<h5>Base Command</h5>
<p><code>msg-get-user</code></p>
<h5>Input</h5>
<table style="width: 747px;">
<thead>
<tr>
<th style="width: 181px;"><strong>Argument Name</strong></th>
<th style="width: 518px;"><strong>Description</strong></th>
<th style="width: 41px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 181px;">user_id</td>
<td style="width: 518px;">User ID of user to retreive</td>
<td style="width: 41px;">Required</td>
</tr>
</tbody>
</table>
<h5>Context Output</h5>
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 312px;"><strong>Path</strong></th>
<th style="width: 33px;"><strong>Type</strong></th>
<th style="width: 395px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 312px;">MsGraph.User.ID</td>
<td style="width: 33px;">string</td>
<td style="width: 395px;">User ID</td>
</tr>
<tr>
<td style="width: 312px;">MsGraph.User.Name</td>
<td style="width: 33px;">string</td>
<td style="width: 395px;">User name</td>
</tr>
<tr>
<td style="width: 312px;">MsGraph.User.Email</td>
<td style="width: 33px;">string</td>
<td style="width: 395px;">User email address</td>
</tr>
<tr>
<td style="width: 312px;">MsGraph.User.Title</td>
<td style="width: 33px;">string</td>
<td style="width: 395px;">User job title</td>
</tr>
</tbody>
</table>
<h5>Command Example</h5>
<pre>!msg-get-user user_id=17174111-8edf-4613-97d4-74c605c5c181</pre>
<h5>Context Example</h5>
<pre>{
    "MsGraph": {
     "User": {
        "Email": "steve@demisto.com",
        "ID": "17174111-8edf-4613-97d4-74c605c5c181",
        "Name": "Steve Jobs",
        "Title": "Manager"
      }
    }
}
</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/31018228/46080581-fa1f0600-c1a2-11e8-894b-38055e85c840.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/31018228/46080581-fa1f0600-c1a2-11e8-894b-38055e85c840.png" alt="screen shot 2018-09-26 at 15 43 39"></a></p>
<p> </p>
<h2>Troubleshooting</h2>
<p>If not all expected alerts were returned, it is possible that partial content was returned from Microsoft Graph. If so, the response headers will be printed to Cortex XSOAR logs, and you can find more details under the **Warning** header. For more information, see the <a href="https://docs.microsoft.com/en-us/graph/api/resources/security-error-codes?view=graph-rest-1.0" target="_blank" rel="noopener">Microsoft Graph documentation</a>.</p>

<h2>Known Limitations</h2>
<ol>
<li>Microsoft does not support updating alerts with Office 365 Security and Compliance set as provider.</li>
<li>Updating status for alerts from the providers Azure Active Directory Identity Protection, Microsoft Cloud App Security, Microsoft Defender for Identity and Azure Information Protection gets updated across Microsoft Graph Security API integrated applications but not reflected in the provider’s management experience. For more details, see the <a href="https://docs.microsoft.com/en-us/graph/api/resources/security-api-overview?view=graph-rest-1.0#alerts" target="_blank" rel="noopener">Microsoft documentation</a>.</li>
</ol>
